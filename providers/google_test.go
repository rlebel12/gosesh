package providers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGoogle(t *testing.T) {
	setup := setup(t)
	google := NewGoogle(setup.sesh, "clientID", "clientSecret", "/callback")
	prepareProvider(google)
	assert.Equal(t, "clientID", google.Config.ClientID)
	assert.Equal(t, "clientSecret", google.Config.ClientSecret)
	assert.Equal(t, "http://localhost/callback", google.Config.RedirectURL)
	assert.Equal(t, []string{"https://www.googleapis.com/auth/userinfo.email"}, google.Config.Scopes)
	assert.Equal(t, "https://accounts.google.com/o/oauth2/auth", google.Config.Endpoint.AuthURL)
	assert.Equal(t, "https://oauth2.googleapis.com/token", google.Config.Endpoint.TokenURL)
}

func TestGoogleOAuth2Begin(t *testing.T) {
	setup := setup(t)
	google := NewGoogle(setup.sesh, "clientID", "clientSecret", "")
	prepareProvider(google)
	google.OAuth2Begin().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	assert.True(t, setup.gotBeginCall.cfg != nil)
	assert.Equal(t, "clientID", setup.gotBeginCall.cfg.ClientID)
}

func TestGoogleOAuth2Callback(t *testing.T) {
	setup := setup(t)
	google := NewGoogle(setup.sesh, "clientID", "clientSecret", "")
	prepareProvider(google)
	rr := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	var gotCalled bool
	var gotErr error
	google.OAuth2Callback(func(w http.ResponseWriter, r *http.Request, err error) {
		gotErr = err
		gotCalled = true
	}).ServeHTTP(rr, r)

	assert.NoError(t, gotErr)
	assert.True(t, gotCalled)
}

func TestGoogleUserRequest(t *testing.T) {
	var gotReq *http.Request
	google := &Google{
		Provider: Provider{
			doRequest: func(req *http.Request) (io.ReadCloser, error) {
				gotReq = req
				return nil, nil
			},
		},
	}
	_, err := google.requestUser(t.Context(), "accessToken")
	require.NoError(t, err)
	assert.Equal(t, "https://www.googleapis.com/oauth2/v2/userinfo?access_token=accessToken", gotReq.URL.String())
}

func TestGoogleUserString(t *testing.T) {
	const userEmail = "google@example.com"
	google := &GoogleUser{
		ID:            "123",
		Email:         userEmail,
		VerifiedEmail: true,
		Picture:       "https://example.com/picture.jpg",
	}
	assert.Equal(t, userEmail, google.String())
}
