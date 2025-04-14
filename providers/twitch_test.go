package providers

import (
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTwitchScopes(t *testing.T) {
	for name, test := range map[string]struct {
		opts           []Opt[Twitch]
		expectedScopes []string
	}{
		"defaultScopes": {
			expectedScopes: []string{},
		},
		"emailScope": {
			opts:           []Opt[Twitch]{WithEmailScope()},
			expectedScopes: []string{"user:read:email"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			setup := setup(t)
			twitch := NewTwitch(setup.sesh, "clientID", "clientSecret", "/callback", test.opts...)
			assert.Equal(t, test.expectedScopes, twitch.Config.Scopes)
		})
	}
}

func TestTwitchUserRequest(t *testing.T) {
	var gotMethod, gotURL string
	var gotHeader http.Header
	setup := setup(t)
	twitch := NewTwitch(setup.sesh, "clientID", "clientSecret", "/callback")
	prepareProvider(twitch)
	twitch.doRequest = func(method, url string, header http.Header) (io.ReadCloser, error) {
		gotMethod = method
		gotURL = url
		gotHeader = header
		return nil, nil
	}
	_, err := twitch.requestUser(t.Context(), "accessToken")
	require.NoError(t, err)
	assert.Equal(t, "GET", gotMethod)
	assert.Equal(t, "https://api.twitch.tv/helix/users", gotURL)
	assert.Equal(t, "Bearer accessToken", gotHeader.Get("Authorization"))
	assert.Equal(t, "clientID", gotHeader.Get("Client-Id"))
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
			twitch := NewTwitch(setup.sesh, "clientID", "clientSecret", "/callback", test.opts...)
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
