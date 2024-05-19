package tests

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rlebel12/gosesh"
	"github.com/rlebel12/gosesh/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestAuthenticateAndRefreshCase int

const (
	CaseNoSession TestAuthenticateAndRefreshCase = iota
	CaseSessionActive
	CaseSessionIdleFailedUpdate
	CaseSessionIdleSuccess
)

func TestAuthenticateAndRefresh(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	now := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)

	for name, test := range map[string]TestAuthenticateAndRefreshCase{
		"no current session":         CaseNoSession,
		"session active":             CaseSessionActive,
		"session idle failed update": CaseSessionIdleFailedUpdate,
		"session idle success":       CaseSessionIdleSuccess,
	} {
		t.Run(name, func(t *testing.T) {
			store := mocks.NewStorer(t)
			parser := mocks.NewIDParser(t)
			identifier := mocks.NewIdentifier(t)
			r, err := http.NewRequest(http.MethodGet, "/", nil)
			require.NoError(err)
			sesh := gosesh.New(parser, store,
				gosesh.WithNow(func() time.Time { return now }),
				gosesh.WithSessionCookieName("customName"),
				gosesh.WithSessionActiveDuration(17*time.Minute),
				gosesh.WithSessionIdleDuration(85*time.Minute),
			)
			rr := httptest.NewRecorder()

			func() {
				if test == CaseNoSession {
					return
				}

				if test == CaseSessionActive {
					session := &gosesh.Session{
						IdleAt: now.Add(5 * time.Minute),
					}
					r = r.WithContext(context.WithValue(r.Context(), gosesh.SessionContextKey, session))
					return
				}
				session := &gosesh.Session{
					ID:     identifier,
					UserID: identifier,
					IdleAt: now.Add(-5 * time.Minute),
				}
				identifier.EXPECT().String().Return("identifier")
				r = r.WithContext(context.WithValue(r.Context(), gosesh.SessionContextKey, session))

				if test == CaseSessionIdleFailedUpdate {
					store.EXPECT().UpdateSession(r.Context(), identifier, gosesh.UpdateSessionValues{
						IdleAt:   now.Add(17 * time.Minute),
						ExpireAt: now.Add(85 * time.Minute),
					}).Return(nil, errors.New("failed update"))
					return
				}

				if test == CaseSessionIdleSuccess {
					store.EXPECT().UpdateSession(r.Context(), identifier, gosesh.UpdateSessionValues{
						IdleAt:   now.Add(17 * time.Minute),
						ExpireAt: now.Add(85 * time.Minute),
					}).Return(&gosesh.Session{
						ID:       identifier,
						UserID:   identifier,
						IdleAt:   now.Add(17 * time.Minute),
						ExpireAt: now.Add(85 * time.Minute),
					}, nil)
				}
			}()

			handlerCalled := false
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
			})
			sesh.AuthenticateAndRefresh(handler).ServeHTTP(rr, r)
			assert.True(handlerCalled)
			if test < CaseSessionIdleSuccess {
				return
			}
			result := rr.Result()
			cookie := result.Cookies()[0]
			assert.Equal("customName", cookie.Name)
			assert.Equal("aWRlbnRpZmllcg==", cookie.Value)
			assert.Equal(now.Add(85*time.Minute), cookie.Expires)
			assert.Equal("localhost", cookie.Domain)
			assert.Equal("/", cookie.Path)
			assert.Equal(http.SameSiteLaxMode, cookie.SameSite)
			assert.False(cookie.Secure)
		})
	}
}

func TestRequireAuthentication(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	now := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("authenticated", func(t *testing.T) {
		store := mocks.NewStorer(t)
		parser := mocks.NewIDParser(t)
		identifier := mocks.NewIdentifier(t)
		r, err := http.NewRequest(http.MethodGet, "/", nil)
		require.NoError(err)
		sesh := gosesh.New(parser, store, gosesh.WithNow(func() time.Time { return now }))
		rr := httptest.NewRecorder()

		session := &gosesh.Session{
			ID:     identifier,
			UserID: identifier,
			IdleAt: now.Add(-5 * time.Minute),
		}
		r = r.WithContext(context.WithValue(r.Context(), gosesh.SessionContextKey, session))

		handlerCalled := false
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
		})
		sesh.RequireAuthentication(handler).ServeHTTP(rr, r)
		assert.True(handlerCalled)
	})

	t.Run("unauthenticated", func(t *testing.T) {
		r, err := http.NewRequest(http.MethodGet, "/", nil)
		require.NoError(err)
		store := mocks.NewStorer(t)
		parser := mocks.NewIDParser(t)
		sesh := gosesh.New(parser, store, gosesh.WithNow(func() time.Time { return now }))
		rr := httptest.NewRecorder()

		handlerCalled := false
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
		})
		sesh.RequireAuthentication(handler).ServeHTTP(rr, r)
		assert.False(handlerCalled)
	})
}
