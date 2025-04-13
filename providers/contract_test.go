package providers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rlebel12/gosesh"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

type GosesherContract struct {
	NewGosesher func(
		giveScheme, giveHost string,
		giveOAuth2BeginFunc func(cfg *oauth2.Config) http.HandlerFunc,
	) Gosesher
	NewOAuth2User func(giveID string) gosesh.Identifier
}

func (c GosesherContract) Test(t *testing.T) {
	t.Run("returns correct scheme", func(t *testing.T) {
		gosesher := c.NewGosesher("https", "example.com", nil)
		assert.Equal(t, "https", gosesher.Scheme())
	})

	t.Run("returns correct host", func(t *testing.T) {
		gosesher := c.NewGosesher("https", "example.com", nil)
		assert.Equal(t, "example.com", gosesher.Host())
	})

	t.Run("OAuth2Begin handler can be called", func(t *testing.T) {
		var gotCalled bool
		gosesher := c.NewGosesher("https", "example.com", func(cfg *oauth2.Config) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				gotCalled = true
				w.WriteHeader(http.StatusOK)
			}
		})
		handler := gosesher.OAuth2Begin(&oauth2.Config{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			RedirectURL:  "https://example.com/callback",
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()
		handler(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.True(t, gotCalled)
	})

	t.Run("OAuth2Callback handler can be called", func(t *testing.T) {
		var gotCalled bool
		var gotErr error
		gosesher := c.NewGosesher("https", "example.com", nil)
		handler := gosesher.OAuth2Callback(
			c.NewOAuth2User("user-id"),
			&oauth2.Config{
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				RedirectURL:  "https://example.com/callback",
			},
			func(w http.ResponseWriter, r *http.Request, err error) {
				gotErr = err
				gotCalled = true
				w.WriteHeader(http.StatusOK)
			},
		)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()
		handler(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.True(t, gotCalled)
		assert.NoError(t, gotErr)
	})
}
