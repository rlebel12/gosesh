package gosesh

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticateAndRefresh(t *testing.T) {
	testCases := map[string]struct {
		setup                   func(t *testing.T, store Storer, r *http.Request, now time.Time) *http.Request
		giveErrorStore          *erroringStore
		wantLogs                []string
		wantSecureCookieHeaders bool
		wantCookie              bool
		wantExtendCalled        bool
	}{
		"no current session": {
			setup: func(t *testing.T, store Storer, r *http.Request, now time.Time) *http.Request {
				return r
			},
			wantSecureCookieHeaders: true,
			wantCookie:              false,
			wantExtendCalled:        false,
		},
		"no_refresh_outside_threshold": {
			setup: func(t *testing.T, store Storer, r *http.Request, now time.Time) *http.Request {
				userID := StringIdentifier("identifier")
				// Session with 15 minutes until idle (> 10min threshold)
				session, err := store.CreateSession(t.Context(), userID, now.Add(15*time.Minute), now.Add(85*time.Minute))
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
			wantCookie:              false,
			wantExtendCalled:        false,
		},
		"refresh_within_threshold": {
			setup: func(t *testing.T, store Storer, r *http.Request, now time.Time) *http.Request {
				userID := StringIdentifier("identifier")
				// Session with 5 minutes until idle (< 10min threshold)
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
			wantCookie:              true,
			wantExtendCalled:        true,
		},
		"refresh_caps_at_absolute": {
			setup: func(t *testing.T, store Storer, r *http.Request, now time.Time) *http.Request {
				userID := StringIdentifier("identifier")
				// Session with 5 minutes until idle, but absolute in 30min
				// sessionIdleTimeout is 17min, so new idle would be now+17min = 17min
				// But absolute is in 30min, so should not cap
				session, err := store.CreateSession(t.Context(), userID, now.Add(5*time.Minute), now.Add(30*time.Minute))
				require.NoError(t, err)
				r.AddCookie(&http.Cookie{
					Name:     "customName",
					Value:    base64.URLEncoding.EncodeToString([]byte(session.ID().String())),
					Expires:  now.Add(30 * time.Minute),
					Path:     "/",
					Domain:   "localhost",
					SameSite: http.SameSiteLaxMode,
				})
				return r
			},
			wantSecureCookieHeaders: true,
			wantCookie:              true,
			wantExtendCalled:        true,
		},
		"refresh_error_continues": {
			setup: func(t *testing.T, store Storer, r *http.Request, now time.Time) *http.Request {
				userID := StringIdentifier("identifier")
				// Session with 5 minutes until idle (within threshold)
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
			giveErrorStore:          &erroringStore{extendSessionError: true},
			wantLogs:                []string{"msg=\"extend session\" error=\"mock failure\""},
			wantSecureCookieHeaders: true,
			wantCookie:              false,
			wantExtendCalled:        false,
		},
		"session expired": {
			setup: func(t *testing.T, store Storer, r *http.Request, now time.Time) *http.Request {
				userID := StringIdentifier("identifier")
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
			wantLogs:                []string{"msg=\"session idle expired\""},
			wantSecureCookieHeaders: true,
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
				WithSessionIdleTimeout(17*time.Minute),
				WithSessionMaxLifetime(85*time.Minute),
				WithSessionRefreshThreshold(10*time.Minute),
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
				// Cookie value should be session ID "1" base64 encoded
				assert.NotEmpty(cookie.Value)
				// Cookie expires at absolute deadline
				assert.Equal("localhost", cookie.Domain)
				assert.Equal("/", cookie.Path)
				assert.Equal(http.SameSiteLaxMode, cookie.SameSite)
				assert.False(cookie.Secure)
			}

			logger.assertExpectedLogs(t, tc.wantLogs)
		})
	}
}

func TestAuthenticateDualDeadline(t *testing.T) {
	testCases := map[string]struct {
		idleDeadline     time.Duration
		absoluteDeadline time.Duration
		wantSession      bool
		wantLogs         []string
	}{
		"both_valid": {
			idleDeadline:     5 * time.Minute,
			absoluteDeadline: 30 * time.Minute,
			wantSession:      true,
			wantLogs:         []string{},
		},
		"idle_expired": {
			idleDeadline:     -5 * time.Minute,
			absoluteDeadline: 30 * time.Minute,
			wantSession:      false,
			wantLogs:         []string{"msg=\"session idle expired\""},
		},
		"absolute_expired": {
			idleDeadline:     5 * time.Minute,
			absoluteDeadline: -5 * time.Minute,
			wantSession:      false,
			wantLogs:         []string{"msg=\"session absolute expired\""},
		},
		"both_expired": {
			idleDeadline:     -10 * time.Minute,
			absoluteDeadline: -5 * time.Minute,
			wantSession:      false,
			wantLogs:         []string{"msg=\"session idle expired\""},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			require := require.New(t)
			assert := assert.New(t)
			now := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)

			store := NewMemoryStore()
			withLogger, logger := withTestLogger()
			sesh := New(
				store,
				WithNow(func() time.Time { return now }),
				WithSessionCookieName("customName"),
				withLogger,
			)

			userID := StringIdentifier("user-id")
			session, err := store.CreateSession(
				context.Background(),
				userID,
				now.Add(tc.idleDeadline),
				now.Add(tc.absoluteDeadline),
			)
			require.NoError(err)

			r, err := http.NewRequest(http.MethodGet, "/", nil)
			require.NoError(err)
			r.AddCookie(&http.Cookie{
				Name:  "customName",
				Value: base64.URLEncoding.EncodeToString([]byte(session.ID().String())),
			})

			handlerCalled := false
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
				gotSession, ok := CurrentSession(r)
				if tc.wantSession {
					assert.True(ok)
					assert.NotNil(gotSession)
				} else {
					assert.False(ok)
					assert.Nil(gotSession)
				}
			})

			rr := httptest.NewRecorder()
			sesh.Authenticate(handler).ServeHTTP(rr, r)

			assert.True(handlerCalled)
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
			StringIdentifier("session-id"),
			StringIdentifier("user-id"),
			now,
			now.Add(time.Hour),
			now,
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
				now := time.Now()
				session := NewFakeSession(
					StringIdentifier("session-id"),
					StringIdentifier("user-id"),
					now,
					now.Add(time.Hour),
					now,
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

func TestAuthenticateWithActivityTracking(t *testing.T) {
	t.Run("records activity when tracker enabled", func(t *testing.T) {
		store := NewMemoryStore()
		now := time.Now().UTC()

		// Use a fixed "now" that advances during the test
		currentTime := now

		gs := New(store,
			WithSessionCookieName("customName"),
			WithOrigin(&url.URL{Scheme: "http", Host: "localhost"}),
			WithNow(func() time.Time { return currentTime }),
			WithActivityTracking(ActivityTrackingConfig{FlushInterval: 1 * time.Hour}), // Won't auto-flush during test
		)
		gs.StartBackgroundTasks(t.Context())

		// Create session at time T0
		userID := StringIdentifier("identifier")
		session, _ := store.CreateSession(t.Context(), userID,
			now.Add(15*time.Minute), now.Add(85*time.Minute))

		originalActivity := session.LastActivityAt()

		// Advance time for the middleware request
		currentTime = now.Add(5 * time.Second)

		// Make request
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{
			Name:  "customName",
			Value: base64.URLEncoding.EncodeToString([]byte(session.ID().String())),
		})

		w := httptest.NewRecorder()
		handler := gs.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		handler.ServeHTTP(w, req)

		// Manually flush to check pending activities
		gs.activityTracker.flush(t.Context())

		// Verify activity was recorded
		updated, _ := store.GetSession(t.Context(), session.ID().String())
		assert.True(t, updated.LastActivityAt().After(originalActivity),
			"Expected LastActivityAt %v to be after %v", updated.LastActivityAt(), originalActivity)
	})

	t.Run("does not panic when tracker disabled", func(t *testing.T) {
		store := NewMemoryStore()
		now := time.Now().UTC()

		gs := New(store,
			WithSessionCookieName("customName"),
			WithOrigin(&url.URL{Scheme: "http", Host: "localhost"}),
			WithNow(func() time.Time { return now }),
			// No activity tracking
		)

		userID := StringIdentifier("identifier")
		session, _ := store.CreateSession(context.Background(), userID,
			now.Add(15*time.Minute), now.Add(85*time.Minute))

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{
			Name:  "customName",
			Value: base64.URLEncoding.EncodeToString([]byte(session.ID().String())),
		})

		w := httptest.NewRecorder()
		handler := gs.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		assert.NotPanics(t, func() {
			handler.ServeHTTP(w, req)
		})
	})
}
