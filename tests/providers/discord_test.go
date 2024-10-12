package providers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rlebel12/gosesh"
	mock_gosesh "github.com/rlebel12/gosesh/mocks"
	mock_providers "github.com/rlebel12/gosesh/mocks/providers"
	"github.com/rlebel12/gosesh/providers"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"golang.org/x/oauth2"
)

type DiscordSuite struct {
	suite.Suite
}

type mockGoseshOAuth2Credentials struct {
	clientID     string
	clientSecret string
}

func (m mockGoseshOAuth2Credentials) ClientID() string {
	return m.clientID
}

func (m mockGoseshOAuth2Credentials) ClientSecret() string {
	return m.clientSecret
}

func (s *DiscordSuite) TestNewDiscord() {
	for name, test := range map[string]struct {
		scopes         providers.DiscordScopes
		expectedScopes []string
	}{
		"noScopes": {
			scopes:         providers.DiscordScopes{},
			expectedScopes: []string{"identify"},
		},
		"emailScope": {
			scopes:         providers.DiscordScopes{Email: true},
			expectedScopes: []string{"identify", "email"},
		},
	} {
		s.Run(name, func() {
			sesh := newGosesher(s.T())
			discord := providers.NewDiscord(sesh, test.scopes, mockGoseshOAuth2Credentials{"clientID", "clientSecret"}, "/callback")

			s.Equal(&oauth2.Config{
				ClientID:     "clientID",
				ClientSecret: "clientSecret",
				RedirectURL:  "http://localhost/callback",
				Scopes:       test.expectedScopes,
				Endpoint: oauth2.Endpoint{
					AuthURL:   "https://discord.com/oauth2/authorize",
					TokenURL:  "https://discord.com/api/oauth2/token",
					AuthStyle: oauth2.AuthStyleInParams,
				},
			}, discord.Config)
		})
	}
}

func (s *DiscordSuite) TestOAuth2Begin() {
	sesh := newGosesher(s.T())
	discord := providers.NewDiscord(sesh, providers.DiscordScopes{}, mockGoseshOAuth2Credentials{}, "")
	var called bool
	sesh.EXPECT().OAuth2Begin(discord.Config).Return(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	discord.OAuth2Begin().ServeHTTP(nil, httptest.NewRequest("GET", "/", nil))
	s.True(called)
}

func (s *DiscordSuite) TestOAuth2Callback() {
	sesh := newGosesher(s.T())
	discord := providers.NewDiscord(sesh, providers.DiscordScopes{}, mockGoseshOAuth2Credentials{}, "")
	sesh.
		EXPECT().
		OAuth2Callback(discord.NewUser(), discord.Config, mock.AnythingOfType("gosesh.HandlerDone")).
		RunAndReturn(func(ou gosesh.OAuth2User, c *oauth2.Config, ch gosesh.HandlerDone) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				ch(w, r, nil)
			}
		})
	rr := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	var called bool
	discord.OAuth2Callback(func(w http.ResponseWriter, r *http.Request, err error) {
		s.NoError(err)
		called = true
	}).ServeHTTP(rr, r)
	s.True(called)
}

func (s *DiscordSuite) TestUserRequest() {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	sesh := newGosesher(s.T())
	sesh.EXPECT().Scheme().Return("http")
	sesh.EXPECT().Host().Return(server.URL)
	creds := mock_gosesh.NewOAuth2Credentials(s.T())
	creds.EXPECT().ClientID().Return("clientID")
	creds.EXPECT().ClientSecret().Return("clientSecret")
	discord := providers.NewDiscord(sesh, providers.DiscordScopes{}, creds, "", providers.WithDiscodHost(server.URL))

	expectedUser := discord.NewUser().(*providers.DiscordUser)
	expectedUser.ID = "123"
	expectedUser.Username = "username"
	expectedUser.Email = "gosesh@example.com"
	expectedUser.Verified = true
	mux.HandleFunc("GET /api/v9/users/@me", func(w http.ResponseWriter, r *http.Request) {
		err := json.NewEncoder(w).Encode(expectedUser)
		s.Require().NoError(err)
	})

	actualUser := discord.NewUser().(*providers.DiscordUser)
	resp, err := actualUser.Request(context.Background(), "accessToken")

	s.Require().NoError(err)
	content, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	err = actualUser.Unmarshal(content)
	s.Require().NoError(err)
	s.Equal(expectedUser, actualUser)

	s.T().Run("TestFailedCreatingRequest", func(t *testing.T) {
		discord := providers.NewDiscord(sesh, providers.DiscordScopes{}, creds, "", providers.WithDiscodHost("\n"))
		user := discord.NewUser().(*providers.DiscordUser)
		_, err := user.Request(context.Background(), "accessToken")
		s.Error(err)
	})
}

func (s *DiscordSuite) TestDiscordUserString() {
	const userID = "123"
	const userEmail = "123@example.com"
	for name, test := range map[string]struct {
		opts     []providers.DiscordOpt
		expected string
	}{
		"default": {
			opts:     nil,
			expected: userID,
		},
		"discord ID": {
			opts:     []providers.DiscordOpt{providers.WithDiscordKeyMode(providers.DiscordKeyModeID)},
			expected: userID,
		},
		"email": {
			opts:     []providers.DiscordOpt{providers.WithDiscordKeyMode(providers.DiscordKeyModeEmail)},
			expected: userEmail,
		},
	} {
		s.Run(name, func() {
			sesh := newGosesher(s.T())
			discord := providers.NewDiscord(sesh, providers.DiscordScopes{}, mockGoseshOAuth2Credentials{}, "", test.opts...)
			user := discord.NewUser().(*providers.DiscordUser)
			user.ID = userID
			user.Email = userEmail
			s.Equal(test.expected, user.String())
		})
	}
}

func TestDiscordSuite(t *testing.T) {
	suite.Run(t, new(DiscordSuite))
}

func newGosesher(t *testing.T) *mock_providers.Gosesher {
	sesh := mock_providers.NewGosesher(t)
	sesh.EXPECT().Scheme().Return("http")
	sesh.EXPECT().Host().Return("localhost")
	return sesh
}
