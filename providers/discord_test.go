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
	prepareProvider(discord)
	discord.OAuth2Begin().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	require.NotNil(t, setup.gotBeginCall.cfg)
	assert.Equal(t, "clientID", setup.gotBeginCall.cfg.ClientID)
}

func TestDiscordOAuth2Callback(t *testing.T) {
	setup := setup(t)
	discord := NewDiscord(setup.sesh, DiscordScopes{}, "clientID", "clientSecret", "")
	prepareProvider(discord)
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

func TestDiscordRequestUser(t *testing.T) {
	var gotReq *http.Request
	discord := &Discord{
		Provider: Provider{
			doRequest: func(req *http.Request) (io.ReadCloser, error) {
				gotReq = req
				return nil, nil
			},
		},
	}
	_, err := discord.requestUser(t.Context(), "accessToken")
	require.NoError(t, err)
	assert.Equal(t, "https://discord.com/api/v9/users/@me", gotReq.URL.String())
	assert.Equal(t, "Bearer accessToken", gotReq.Header.Get("Authorization"))
}

func TestDiscordUserString(t *testing.T) {
	const userID = "123"
	const userEmail = "123@example.com"
	for name, test := range map[string]struct {
		opts     []Opt[Discord]
		expected string
	}{
		"default": {
			opts:     nil,
			expected: userID,
		},
		"discord ID": {
			opts:     []Opt[Discord]{WithDiscordKeyMode(DiscordKeyModeID)},
			expected: userID,
		},
		"email": {
			opts:     []Opt[Discord]{WithDiscordKeyMode(DiscordKeyModeEmail)},
			expected: userEmail,
		},
	} {
		t.Run(name, func(t *testing.T) {
			setup := setup(t)
			discord := NewDiscord(setup.sesh, DiscordScopes{}, "clientID", "clientSecret", "", test.opts...)
			user := discord.NewUser()
			user.ID = userID
			user.Email = userEmail
			assert.Equal(t, test.expected, user.String())
		})
	}
}
