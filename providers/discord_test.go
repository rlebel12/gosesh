package providers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rlebel12/gosesh"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"golang.org/x/oauth2"
)

type DiscordSuite struct {
	suite.Suite
}

func (s *DiscordSuite) TestNewDiscord() {
	for name, test := range map[string]struct {
		scopes         DiscordScopes
		expectedScopes []string
	}{
		"noScopes": {
			scopes:         DiscordScopes{},
			expectedScopes: []string{"identify"},
		},
		"emailScope": {
			scopes:         DiscordScopes{Email: true},
			expectedScopes: []string{"identify", "email"},
		},
	} {
		s.Run(name, func() {
			sesh := newGosesher(s.T())
			discord := NewDiscord(sesh, test.scopes, gosesh.OAuth2Credentials{
				ClientID:     "clientID",
				ClientSecret: "clientSecret",
			}, "/callback")

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
			}, discord.config)
		})
	}
}

func (s *DiscordSuite) TestOAuth2Begin() {
	sesh := newGosesher(s.T())
	discord := NewDiscord(sesh, DiscordScopes{}, gosesh.OAuth2Credentials{}, "")
	var called bool
	sesh.EXPECT().OAuth2Begin(discord.config).Return(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	discord.OAuth2Begin().ServeHTTP(nil, httptest.NewRequest("GET", "/", nil))
	s.True(called)
}

func (s *DiscordSuite) TestOAuth2Callback() {
	sesh := newGosesher(s.T())
	discord := NewDiscord(sesh, DiscordScopes{}, gosesh.OAuth2Credentials{}, "")
	user := &DiscordUser{discord: discord}
	sesh.
		EXPECT().
		OAuth2Callback(user, discord.config, mock.AnythingOfType("gosesh.CallbackHandler")).
		RunAndReturn(func(ou gosesh.OAuth2User, c *oauth2.Config, ch gosesh.CallbackHandler) http.HandlerFunc {
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
	expectedUser := DiscordUser{
		ID:       "123",
		Username: "username",
		Email:    "gosesh@example.com",
		Verified: true,
		testHost: &server.URL,
	}
	mux.HandleFunc("GET /api/v9/users/@me", func(w http.ResponseWriter, r *http.Request) {
		err := json.NewEncoder(w).Encode(expectedUser)
		s.Require().NoError(err)
	})

	user := DiscordUser{testHost: &server.URL}

	resp, err := user.Request(context.Background(), "accessToken")
	s.Require().NoError(err)
	content, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	err = user.Unmarshal(content)
	s.Require().NoError(err)
	s.Equal(expectedUser, user)

	s.T().Run("TestFailedCreatingRequest", func(t *testing.T) {
		badURL := "\n"
		user := DiscordUser{testHost: &badURL}
		_, err := user.Request(context.Background(), "accessToken")
		s.Error(err)
	})
}

func (s *DiscordSuite) TestDiscordUserString() {
	const userID = "123"
	const userEmail = "123@example.com"
	for name, test := range map[string]struct {
		opts     []discordOpt
		expected string
	}{
		"default": {
			opts:     nil,
			expected: userID,
		},
		"discord ID": {
			opts:     []discordOpt{WithDiscordKeyMode(DiscordKeyModeID)},
			expected: userID,
		},
		"email": {
			opts:     []discordOpt{WithDiscordKeyMode(DiscordKeyModeEmail)},
			expected: userEmail,
		},
	} {
		s.Run(name, func() {
			sesh := newGosesher(s.T())
			discord := NewDiscord(sesh, DiscordScopes{}, gosesh.OAuth2Credentials{}, "", test.opts...)
			user := &DiscordUser{
				ID:      userID,
				Email:   userEmail,
				discord: discord,
			}
			s.Equal(test.expected, user.String())
		})
	}
}

func TestDiscordSuite(t *testing.T) {
	suite.Run(t, new(DiscordSuite))
}
