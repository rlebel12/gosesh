package providers

import (
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoogleUserRequest(t *testing.T) {
	var gotMethod, gotURL string
	google := &Google{
		Provider: Provider{
			doRequest: func(method, url string, header http.Header) (io.ReadCloser, error) {
				gotMethod = method
				gotURL = url
				return nil, nil
			},
		},
	}
	_, err := google.requestUser(t.Context(), "accessToken")
	require.NoError(t, err)
	assert.Equal(t, "GET", gotMethod)
	assert.Equal(t, "https://www.googleapis.com/oauth2/v2/userinfo?access_token=accessToken", gotURL)
}

func TestGoogleUserString(t *testing.T) {
	setup := setup(t)
	google := NewGoogle(setup.sesh, "clientID", "clientSecret", "/callback")
	user := google.NewUser()
	user.ID = "123"
	user.Email = "google@example.com"
	assert.Equal(t, "google@example.com", user.String())
}
