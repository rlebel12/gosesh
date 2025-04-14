package providers

import (
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscordScopes(t *testing.T) {
	for name, test := range map[string]struct {
		opts           []Opt[Discord]
		expectedScopes []string
	}{
		"noScopes": {
			expectedScopes: []string{"identify"},
		},
		"emailScope": {
			opts:           []Opt[Discord]{WithDiscordEmailScope()},
			expectedScopes: []string{"identify", "email"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			setup := setup(t)
			discord := NewDiscord(setup.sesh, "clientID", "clientSecret", "/callback", test.opts...)
			assert.Equal(t, test.expectedScopes, discord.Config.Scopes)
		})
	}
}

func TestDiscordRequestUser(t *testing.T) {
	var gotMethod, gotURL string
	var gotHeader http.Header
	discord := &Discord{
		Provider: Provider{
			doRequest: func(method, url string, header http.Header) (io.ReadCloser, error) {
				gotMethod = method
				gotURL = url
				gotHeader = header
				return nil, nil
			},
		},
	}
	_, err := discord.requestUser(t.Context(), "accessToken")
	require.NoError(t, err)
	assert.Equal(t, "GET", gotMethod)
	assert.Equal(t, "https://discord.com/api/v9/users/@me", gotURL)
	assert.Equal(t, "Bearer accessToken", gotHeader.Get("Authorization"))
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
			discord := NewDiscord(setup.sesh, "clientID", "clientSecret", "", test.opts...)
			user := discord.NewUser()
			user.ID = userID
			user.Email = userEmail
			assert.Equal(t, test.expected, user.String())
		})
	}
}
