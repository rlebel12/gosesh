package providers

import (
	"encoding/json"
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

			assert.Equal(t, "clientID", twitch.cfg.ClientID)
			assert.Equal(t, "clientSecret", twitch.cfg.ClientSecret)
			assert.Equal(t, "http://localhost/callback", twitch.cfg.RedirectURL)
			assert.Equal(t, test.expectedScopes, twitch.cfg.Scopes)
			assert.Equal(t, "https://id.twitch.tv/oauth2/authorize", twitch.cfg.Endpoint.AuthURL)
			assert.Equal(t, "https://id.twitch.tv/oauth2/token", twitch.cfg.Endpoint.TokenURL)
			assert.Equal(t, oauth2.AuthStyleInParams, twitch.cfg.Endpoint.AuthStyle)
		})
	}
}

func TestTwitchOAuth2Begin(t *testing.T) {
	setup := setup(t)
	twitch := NewTwitch(setup.sesh, TwitchScopes{}, "clientID", "clientSecret", "")
	twitch.OAuth2Begin().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	assert.True(t, setup.gotBeginCall.cfg != nil)
	assert.Equal(t, "clientID", setup.gotBeginCall.cfg.ClientID)
}

func TestTwitchOAuth2Callback(t *testing.T) {
	setup := setup(t)
	twitch := NewTwitch(setup.sesh, TwitchScopes{}, "clientID", "clientSecret", "")
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
	for name, tc := range map[string]struct {
		giveTwitchHost func(realURL string) string
		wantErr        bool
	}{
		"success": {
			giveTwitchHost: func(realURL string) string { return realURL },
		},
		"error": {
			giveTwitchHost: func(realURL string) string { return "\n" },
			wantErr:        true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			mux := http.NewServeMux()
			server := httptest.NewServer(mux)
			t.Cleanup(server.Close)

			setup := setup(t)
			twitch := NewTwitch(setup.sesh, TwitchScopes{}, "clientID", "clientSecret", "", WithTwitchHost(tc.giveTwitchHost(server.URL)))

			expectedResponse := &TwitchUser{
				Data: []struct {
					ID    string `json:"id"`
					Login string `json:"login"`
					Email string `json:"email"`
				}{
					{
						ID:    "123456789",
						Login: "twitchuser",
						Email: "twitch@example.com",
					},
				},
			}

			mux.HandleFunc("/helix/users", func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "Bearer accessToken", r.Header.Get("Authorization"))
				assert.Equal(t, "clientID", r.Header.Get("Client-Id"))

				err := json.NewEncoder(w).Encode(expectedResponse)
				assert.NoError(t, err)
			})

			actualUser := twitch.NewUser().(*TwitchUser)
			resp, err := actualUser.Request(t.Context(), "accessToken")

			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			content, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			err = actualUser.Unmarshal(content)
			require.NoError(t, err)

			assert.Len(t, actualUser.Data, 1)
			assert.Equal(t, "123456789", actualUser.Data[0].ID)
			assert.Equal(t, "twitchuser", actualUser.Data[0].Login)
			assert.Equal(t, "twitch@example.com", actualUser.Data[0].Email)
		})
	}
}

func TestTwitchUserString(t *testing.T) {
	const userID = "123456789"
	const userEmail = "twitch@example.com"

	for name, test := range map[string]struct {
		opts     []TwitchOpt
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
			opts:     []TwitchOpt{WithTwitchKeyMode(TwitchKeyModeID)},
			expected: userID,
		},
		"email": {
			opts:     []TwitchOpt{WithTwitchKeyMode(TwitchKeyModeEmail)},
			expected: userEmail,
		},
	} {
		t.Run(name, func(t *testing.T) {
			setup := setup(t)
			twitch := NewTwitch(setup.sesh, TwitchScopes{}, "clientID", "clientSecret", "", test.opts...)
			user := twitch.NewUser().(*TwitchUser)

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
