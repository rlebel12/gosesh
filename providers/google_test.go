package providers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rlebel12/gosesh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestNewGoogle(t *testing.T) {
	setup := setup(t)
	google := NewGoogle(setup.Sesh, setup.Creds, "/callback")

	assert.Equal(t, "clientID", google.cfg.ClientID)
	assert.Equal(t, "clientSecret", google.cfg.ClientSecret)
	assert.Equal(t, "http://localhost/callback", google.cfg.RedirectURL)
	assert.Equal(t, []string{"https://www.googleapis.com/auth/userinfo.email"}, google.cfg.Scopes)
	assert.Equal(t, "https://accounts.google.com/o/oauth2/auth", google.cfg.Endpoint.AuthURL)
	assert.Equal(t, "https://oauth2.googleapis.com/token", google.cfg.Endpoint.TokenURL)
}

func TestGoogleOAuth2Begin(t *testing.T) {
	setup := setup(t)
	google := NewGoogle(setup.Sesh, setup.Creds, "")
	var gotCalled bool
	var gotCfg *oauth2.Config
	setup.Sesh.OAuth2BeginFunc = func(cfg *oauth2.Config) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			gotCfg = cfg
			gotCalled = true
		}
	}
	google.OAuth2Begin().ServeHTTP(nil, httptest.NewRequest("GET", "/", nil))
	assert.True(t, gotCalled)
	assert.Equal(t, "clientID", gotCfg.ClientID)
}

func TestGoogleOAuth2Callback(t *testing.T) {
	setup := setup(t)
	google := NewGoogle(setup.Sesh, setup.Creds, "")
	setup.Sesh.OAuth2CallbackFunc = func(user gosesh.OAuth2User, cfg *oauth2.Config, handler gosesh.HandlerDone) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			handler(w, r, nil)
		}
	}
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
	assert.Len(t, setup.Sesh.calls.OAuth2Callback, 1)
	assert.IsType(t, &GoogleUser{}, setup.Sesh.calls.OAuth2Callback[0].User)
	assert.Equal(t, "clientID", setup.Sesh.calls.OAuth2Callback[0].Cfg.ClientID)
}

func TestGoogleUserRequest(t *testing.T) {
	for name, tc := range map[string]struct {
		giveGoogleHost func(realURL string) string
		wantErr        bool
	}{
		"success": {
			giveGoogleHost: func(realURL string) string { return realURL },
		},
		"error": {
			giveGoogleHost: func(realURL string) string { return "\n" },
			wantErr:        true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			mux := http.NewServeMux()
			server := httptest.NewServer(mux)
			t.Cleanup(server.Close)

			setup := setup(t)
			setup.Sesh.HostFunc = func() string { return server.URL }
			google := NewGoogle(setup.Sesh, setup.Creds, "", WithGoogleHost(tc.giveGoogleHost(server.URL)))

			expectedUser := google.NewUser().(*GoogleUser)
			mux.HandleFunc("/oauth2/v2/userinfo", func(w http.ResponseWriter, r *http.Request) {
				expectedUser.ID = "123"
				expectedUser.Email = "google@example.com"
				expectedUser.VerifiedEmail = true
				expectedUser.Picture = "https://example.com/picture.jpg"
				err := json.NewEncoder(w).Encode(expectedUser)
				assert.NoError(t, err)
			})

			actualUser := google.NewUser().(*GoogleUser)
			resp, err := actualUser.Request(context.Background(), "accessToken")

			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			content, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			err = actualUser.Unmarshal(content)
			require.NoError(t, err)
			assert.Equal(t, expectedUser.ID, actualUser.ID)
			assert.Equal(t, expectedUser.Email, actualUser.Email)
			assert.Equal(t, expectedUser.VerifiedEmail, actualUser.VerifiedEmail)
			assert.Equal(t, expectedUser.Picture, actualUser.Picture)
		})
	}
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
