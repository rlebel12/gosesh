package gosesh

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rlebel12/gosesh/internal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestAuthenticateAndRefreshCase int

const (
	CaseNoSession TestAuthenticateAndRefreshCase = iota
	CaseSessionActive
	CaseSessionExpired
	CaseSessionIdleFaileCreateReplacement
	CaseSessionIdleFailedDeleteOld
	CaseSessionIdleSuccess
)

func TestAuthenticateAndRefresh(t *testing.T) {
	testCases := map[string]struct {
		setup                   func(t *testing.T, store Storer, r *http.Request, now time.Time) *http.Request
		giveErrorStore          *erroringStore
		giveParseError          error
		wantLogs                []string
		wantSecureCookieHeaders bool
		wantCookie              bool
	}{
		"no current session": {
			setup: func(t *testing.T, store Storer, r *http.Request, now time.Time) *http.Request {
				return r
			},
			wantSecureCookieHeaders: true,
			wantCookie:              false,
		},
		"session active": {
			setup: func(t *testing.T, store Storer, r *http.Request, now time.Time) *http.Request {
				userID := internal.NewFakeIdentifier("identifier")
				session, err := store.CreateSession(t.Context(), userID, now.Add(5*time.Minute), now.Add(85*time.Minute))
				require.NoError(t, err)
				r.AddCookie(&http.Cookie{
					Name:     "customName",
					Value:    base64.URLEncoding.EncodeToString([]byte(session.ID().String())),
					Expires:  now.Add(85 * time.Minute),
					Path:     "/",
					Domain:   "localhost",
					SameSite: http.SameSiteLaxMode,
				})
				return r
			},
			wantSecureCookieHeaders: true,
		},
		"session expired": {
			setup: func(t *testing.T, store Storer, r *http.Request, now time.Time) *http.Request {
				userID := internal.NewFakeIdentifier("identifier")
				session, err := store.CreateSession(t.Context(), userID, now.Add(-5*time.Minute), now.Add(-1*time.Minute))
				require.NoError(t, err)
				r.AddCookie(&http.Cookie{
					Name:     "customName",
					Value:    base64.URLEncoding.EncodeToString([]byte(session.ID().String())),
					Expires:  now.Add(10 * time.Minute),
					Path:     "/",
					Domain:   "localhost",
					SameSite: http.SameSiteLaxMode,
				})
				return r
			},
			wantLogs:                []string{"msg=\"session expired\""},
			wantSecureCookieHeaders: true,
		},
		"session idle failed create replacement": {
			setup: func(t *testing.T, store Storer, r *http.Request, now time.Time) *http.Request {
				userID := internal.NewFakeIdentifier("identifier")
				session, err := store.CreateSession(t.Context(), userID, now.Add(-5*time.Minute), now.Add(85*time.Minute))
				require.NoError(t, err)
				r = r.WithContext(context.WithValue(r.Context(), sessionKey, session))
				return r
			},
			wantLogs:       []string{"msg=\"replace session\" error=\"create session: mock failure\""},
			giveErrorStore: &erroringStore{createSessionError: true},
		},
		"session idle failed delete old": {
			setup: func(t *testing.T, store Storer, r *http.Request, now time.Time) *http.Request {
				userID := internal.NewFakeIdentifier("identifier")
				session, err := store.CreateSession(t.Context(), userID, now.Add(-5*time.Minute), now.Add(85*time.Minute))
				require.NoError(t, err)
				r = r.WithContext(context.WithValue(r.Context(), sessionKey, session))
				return r
			},
			wantLogs:       []string{"msg=\"replace session\" error=\"delete session: mock failure\""},
			giveErrorStore: &erroringStore{deleteSessionError: true},
		},
		"session idle success": {
			setup: func(t *testing.T, store Storer, r *http.Request, now time.Time) *http.Request {
				userID := internal.NewFakeIdentifier("identifier")
				session, err := store.CreateSession(t.Context(), userID, now.Add(-5*time.Minute), now.Add(85*time.Minute))
				require.NoError(t, err)
				r = r.WithContext(context.WithValue(r.Context(), sessionKey, session))
				return r
			},
			wantCookie: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			require := require.New(t)
			assert := assert.New(t)
			now := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)

			store := NewMemoryStore()
			var testStore Storer = store
			if tc.giveErrorStore != nil {
				tc.giveErrorStore.Storer = store
				testStore = tc.giveErrorStore
			}

			withLogger, logger := withTestLogger()
			sesh := New(
				testStore,
				WithNow(func() time.Time { return now }),
				WithSessionCookieName("customName"),
				WithSessionActiveDuration(17*time.Minute),
				WithSessionIdleDuration(85*time.Minute),
				withLogger,
			)

			r, err := http.NewRequest(http.MethodGet, "/", nil)
			require.NoError(err)
			r = tc.setup(t, store, r, now)

			handlerCalled := false
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
			})

			rr := httptest.NewRecorder()
			sesh.AuthenticateAndRefresh(handler).ServeHTTP(rr, r)
			result := rr.Result()

			assert.True(handlerCalled)
			if tc.wantSecureCookieHeaders {
				assert.Equal(`private, no-cache="Set-Cookie"`, result.Header.Get("Cache-Control"))
				assert.Equal("Cookie", result.Header.Get("Vary"))
			} else {
				assert.Empty(result.Header.Get("Cache-Control"))
				assert.Empty(result.Header.Get("Vary"))
			}

			if tc.wantCookie {
				cookies := result.Cookies()
				require.NotEmpty(cookies)
				cookie := cookies[0]
				assert.Equal("customName", cookie.Name)
				assert.Equal("Mg==", cookie.Value)
				assert.Equal(now.Add(85*time.Minute), cookie.Expires)
				assert.Equal("localhost", cookie.Domain)
				assert.Equal("/", cookie.Path)
				assert.Equal(http.SameSiteLaxMode, cookie.SameSite)
				assert.False(cookie.Secure)
			}

			logger.assertExpectedLogs(t, tc.wantLogs)
		})
	}
}

func TestRequireAuthentication(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	now := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("authenticated", func(t *testing.T) {
		store := NewMemoryStore()
		r, err := http.NewRequest(http.MethodGet, "/", nil)
		require.NoError(err)
		sesh := New(store, WithNow(func() time.Time { return now }))
		rr := httptest.NewRecorder()

		session := NewFakeSession(
			internal.NewFakeIdentifier("session-id"),
			internal.NewFakeIdentifier("user-id"),
			now,
			now.Add(time.Hour),
		)
		r = r.WithContext(context.WithValue(r.Context(), sessionKey, session))

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
		store := NewMemoryStore()
		sesh := New(store, WithNow(func() time.Time { return now }))
		rr := httptest.NewRecorder()

		handlerCalled := false
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
		})
		sesh.RequireAuthentication(handler).ServeHTTP(rr, r)
		assert.False(handlerCalled)
	})
}

func TestRedirectUnauthenticated(t *testing.T) {
	for name, test := range map[string]struct {
		giveHeader          http.Header
		giveSession         func(t *testing.T, r *http.Request) *http.Request
		giveRedirectableOpt []func(r *http.Request) bool
		wantLocation        string
		wantStatus          int
		cookieAsserts       []func(t *testing.T, cookie *http.Cookie)
	}{
		"authenticated": {
			giveSession: func(t *testing.T, r *http.Request) *http.Request {
				session := NewFakeSession(
					internal.NewFakeIdentifier("session-id"),
					internal.NewFakeIdentifier("user-id"),
					time.Now(),
					time.Now().Add(time.Hour),
				)
				return r.WithContext(context.WithValue(r.Context(), sessionKey, session))
			},
			wantStatus: http.StatusOK,
		},
		"redirect default": {
			giveHeader: http.Header{"Accept": []string{"text/html"}},
			cookieAsserts: []func(t *testing.T, cookie *http.Cookie){
				func(t *testing.T, cookie *http.Cookie) {
					assert := assert.New(t)
					assert.Equal("redirect", cookie.Name)
					assert.Equal("Lw==", cookie.Value)
					assert.Equal("/", cookie.Path)
					assert.Equal("localhost", cookie.Domain)
					assert.Equal(http.SameSiteLaxMode, cookie.SameSite)
					assert.False(cookie.Secure)
				},
			},
			wantLocation: "/login",
			wantStatus:   http.StatusTemporaryRedirect,
		},
		"no redirect default": {
			wantStatus: http.StatusUnauthorized,
		},
		"redirect custom redirectable": {
			giveHeader: http.Header{"Accept": []string{"text/plain"}},
			giveRedirectableOpt: []func(r *http.Request) bool{
				func(r *http.Request) bool {
					return r.Header.Get("Accept") == "text/plain"
				},
				func(r *http.Request) bool {
					return false
				},
			},
			cookieAsserts: []func(t *testing.T, cookie *http.Cookie){
				func(t *testing.T, cookie *http.Cookie) {
					assert := assert.New(t)
					assert.Equal("redirect", cookie.Name)
					assert.Equal("Lw==", cookie.Value)
					assert.Equal("/", cookie.Path)
					assert.Equal("localhost", cookie.Domain)
					assert.Equal(http.SameSiteLaxMode, cookie.SameSite)
					assert.False(cookie.Secure)
				},
			},
			wantLocation: "/login",
			wantStatus:   http.StatusTemporaryRedirect,
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			store := NewMemoryStore()

			r, err := http.NewRequest(http.MethodGet, "/", nil)
			if test.giveSession != nil {
				r = test.giveSession(t, r)
			}
			if test.giveHeader != nil {
				r.Header = test.giveHeader
			}
			require.NoError(err)

			sesh := New(store, WithNow(func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }))
			rr := httptest.NewRecorder()

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			loginURL, err := r.URL.Parse("/login")
			require.NoError(err)

			sesh.RedirectUnauthenticated(*loginURL, test.giveRedirectableOpt...)(handler).ServeHTTP(rr, r)

			assert.Equal(test.wantStatus, rr.Result().StatusCode)
			assert.Equal(test.wantLocation, rr.Result().Header.Get("Location"))
			gotCookies := rr.Result().Cookies()
			assert.Len(gotCookies, len(test.cookieAsserts))
			for i, gotCookie := range gotCookies {
				test.cookieAsserts[i](t, gotCookie)
			}
		})
	}
}
