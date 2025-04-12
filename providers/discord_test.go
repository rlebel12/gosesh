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

func TestNewDiscord(t *testing.T) {
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
		t.Run(name, func(t *testing.T) {
			setup := setup(t)
			discord := NewDiscord(setup.sesh, test.scopes, "clientID", "clientSecret", "/callback")

			assert.Equal(t, &oauth2.Config{
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

func TestDiscordOAuth2Begin(t *testing.T) {
	setup := setup(t)
	discord := NewDiscord(setup.sesh, DiscordScopes{}, "clientID", "clientSecret", "")
	discord.OAuth2Begin().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	require.NotNil(t, setup.gotBeginCall.cfg)
	assert.Equal(t, "clientID", setup.gotBeginCall.cfg.ClientID)
}

func TestDiscordOAuth2Callback(t *testing.T) {
	setup := setup(t)
	discord := NewDiscord(setup.sesh, DiscordScopes{}, "clientID", "clientSecret", "")
	rr := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	var gotCalled bool
	var gotErr error
	discord.OAuth2Callback(func(w http.ResponseWriter, r *http.Request, err error) {
		gotErr = err
		gotCalled = true
	}).ServeHTTP(rr, r)

	assert.NoError(t, gotErr)
	assert.True(t, gotCalled)
}

func TestDiscordUserRequest(t *testing.T) {
	for name, tc := range map[string]struct {
		giveDiscordHost func(realURL string) string
		wantErr         bool
	}{
		"success": {
			giveDiscordHost: func(realURL string) string { return realURL },
		},
		"error": {
			giveDiscordHost: func(realURL string) string { return "\n" },
			wantErr:         true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			mux := http.NewServeMux()
			server := httptest.NewServer(mux)
			t.Cleanup(server.Close)

			setup := setup(t)
			discord := NewDiscord(setup.sesh, DiscordScopes{}, "clientID", "clientSecret", "", WithDiscodHost(tc.giveDiscordHost(server.URL)))

			expectedUser := discord.NewUser().(*DiscordUser)
			mux.HandleFunc("/api/v9/users/@me", func(w http.ResponseWriter, r *http.Request) {
				expectedUser.ID = "123"
				expectedUser.Username = "username"
				expectedUser.Email = "gosesh@example.com"
				expectedUser.Verified = true
				err := json.NewEncoder(w).Encode(expectedUser)
				assert.NoError(t, err)
			})

			actualUser := discord.NewUser().(*DiscordUser)
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
			assert.Equal(t, expectedUser, actualUser)
		})
	}
}

func TestDiscordUserString(t *testing.T) {
	const userID = "123"
	const userEmail = "123@example.com"
	for name, test := range map[string]struct {
		opts     []DiscordOpt
		expected string
	}{
		"default": {
			opts:     nil,
			expected: userID,
		},
		"discord ID": {
			opts:     []DiscordOpt{WithDiscordKeyMode(DiscordKeyModeID)},
			expected: userID,
		},
		"email": {
			opts:     []DiscordOpt{WithDiscordKeyMode(DiscordKeyModeEmail)},
			expected: userEmail,
		},
	} {
		t.Run(name, func(t *testing.T) {
			setup := setup(t)
			discord := NewDiscord(setup.sesh, DiscordScopes{}, "clientID", "clientSecret", "", test.opts...)
			user := discord.NewUser().(*DiscordUser)
			user.ID = userID
			user.Email = userEmail
			assert.Equal(t, test.expected, user.String())
		})
	}
}
