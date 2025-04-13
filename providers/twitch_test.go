package providers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestNewTwitch(t *testing.T) {
	for name, test := range map[string]struct {
		scopes         TwitchScopes
		expectedScopes []string
	}{
		"defaultScopes": {
			scopes:         TwitchScopes{},
			expectedScopes: []string{},
		},
		"emailScope": {
			scopes:         TwitchScopes{Email: true},
			expectedScopes: []string{"user:read:email"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			setup := setup(t)
			twitch := NewTwitch(setup.sesh, test.scopes, "clientID", "clientSecret", "/callback")
			prepareProvider(twitch)
			assert.Equal(t, "clientID", twitch.Config.ClientID)
			assert.Equal(t, "clientSecret", twitch.Config.ClientSecret)
			assert.Equal(t, "http://localhost/callback", twitch.Config.RedirectURL)
			assert.Equal(t, test.expectedScopes, twitch.Config.Scopes)
			assert.Equal(t, "https://id.twitch.tv/oauth2/authorize", twitch.Config.Endpoint.AuthURL)
			assert.Equal(t, "https://id.twitch.tv/oauth2/token", twitch.Config.Endpoint.TokenURL)
			assert.Equal(t, oauth2.AuthStyleInParams, twitch.Config.Endpoint.AuthStyle)
		})
	}
}

func TestTwitchOAuth2Begin(t *testing.T) {
	setup := setup(t)
	twitch := NewTwitch(setup.sesh, TwitchScopes{}, "clientID", "clientSecret", "")
	prepareProvider(twitch)
	twitch.OAuth2Begin().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	assert.True(t, setup.gotBeginCall.cfg != nil)
	assert.Equal(t, "clientID", setup.gotBeginCall.cfg.ClientID)
}

func TestTwitchOAuth2Callback(t *testing.T) {
	setup := setup(t)
	twitch := NewTwitch(setup.sesh, TwitchScopes{}, "clientID", "clientSecret", "")
	prepareProvider(twitch)
	rr := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	var gotCalled bool
	var gotErr error
	twitch.OAuth2Callback(func(w http.ResponseWriter, r *http.Request, err error) {
		gotErr = err
		gotCalled = true
	}).ServeHTTP(rr, r)

	assert.NoError(t, gotErr)
	assert.True(t, gotCalled)
}

func TestTwitchUserRequest(t *testing.T) {
	var gotReq *http.Request
	setup := setup(t)
	twitch := NewTwitch(setup.sesh, TwitchScopes{}, "clientID", "clientSecret", "")
	prepareProvider(twitch)
	twitch.doRequest = func(req *http.Request) (io.ReadCloser, error) {
		gotReq = req
		return nil, nil
	}
	_, err := twitch.requestUser(t.Context(), "accessToken")
	require.NoError(t, err)
	assert.Equal(t, "https://api.twitch.tv/helix/users", gotReq.URL.String())
	assert.Equal(t, "Bearer accessToken", gotReq.Header.Get("Authorization"))
}

func TestTwitchUserString(t *testing.T) {
	const userID = "123456789"
	const userEmail = "twitch@example.com"

	for name, test := range map[string]struct {
		opts     []Opt[Twitch]
		expected string
	}{
		"no data": {
			opts:     nil,
			expected: "",
		},
		"default": {
			opts:     nil,
			expected: userID,
		},
		"twitch ID": {
			opts:     []Opt[Twitch]{WithTwitchKeyMode(TwitchKeyModeID)},
			expected: userID,
		},
		"email": {
			opts:     []Opt[Twitch]{WithTwitchKeyMode(TwitchKeyModeEmail)},
			expected: userEmail,
		},
	} {
		t.Run(name, func(t *testing.T) {
			setup := setup(t)
			twitch := NewTwitch(setup.sesh, TwitchScopes{}, "clientID", "clientSecret", "", test.opts...)
			user := twitch.NewUser()

			if name == "no data" {
				assert.Equal(t, test.expected, user.String())
				return
			}

			user.Data = []struct {
				ID    string `json:"id"`
				Login string `json:"login"`
				Email string `json:"email"`
			}{
				{
					ID:    userID,
					Login: "twitchuser",
					Email: userEmail,
				},
			}

			assert.Equal(t, test.expected, user.String())
		})
	}
}
