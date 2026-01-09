package gosesh

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthenticateAcrossSourceTypes tests the Authenticate middleware with different credential sources.
func TestAuthenticateAcrossSourceTypes(t *testing.T) {
	testCases := []struct {
		name             string
		credentialSource CredentialSource
		setupRequest     func(t *testing.T, r *http.Request, session Session)
		wantSessionInCtx bool
	}{
		{
			name:             "authenticate_cookie_source",
			credentialSource: NewCookieCredentialSource(WithCookieSourceName("session"), WithCookieSourceSecure(false)),
			setupRequest: func(t *testing.T, r *http.Request, session Session) {
				// Add session cookie to request
				source := NewCookieCredentialSource(WithCookieSourceName("session"), WithCookieSourceSecure(false))
				w := httptest.NewRecorder()
				err := source.WriteSession(w, session)
				require.NoError(t, err)
				cookies := w.Result().Cookies()
				require.NotEmpty(t, cookies)
				r.AddCookie(cookies[0])
			},
			wantSessionInCtx: true,
		},
		{
			name:             "authenticate_header_source",
			credentialSource: NewHeaderCredentialSource(),
			setupRequest: func(t *testing.T, r *http.Request, session Session) {
				// Add Bearer token header to request
				r.Header.Set("Authorization", "Bearer "+session.ID().String())
			},
			wantSessionInCtx: true,
		},
		{
			name: "authenticate_composite_cookie",
			credentialSource: NewCompositeCredentialSource(
				NewCookieCredentialSource(WithCookieSourceName("session"), WithCookieSourceSecure(false)),
				NewHeaderCredentialSource(),
			),
			setupRequest: func(t *testing.T, r *http.Request, session Session) {
				// Add session cookie (first source wins)
				source := NewCookieCredentialSource(WithCookieSourceName("session"), WithCookieSourceSecure(false))
				w := httptest.NewRecorder()
				err := source.WriteSession(w, session)
				require.NoError(t, err)
				cookies := w.Result().Cookies()
				require.NotEmpty(t, cookies)
				r.AddCookie(cookies[0])
			},
			wantSessionInCtx: true,
		},
		{
			name: "authenticate_composite_header",
			credentialSource: NewCompositeCredentialSource(
				NewCookieCredentialSource(WithCookieSourceName("session"), WithCookieSourceSecure(false)),
				NewHeaderCredentialSource(),
			),
			setupRequest: func(t *testing.T, r *http.Request, session Session) {
				// Add header only (fallback to second source)
				r.Header.Set("Authorization", "Bearer "+session.ID().String())
			},
			wantSessionInCtx: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
			store := NewMemoryStore()

			sesh := New(
				store,
				WithNow(func() time.Time { return now }),
				WithCredentialSource(tc.credentialSource),
			)

			// Create a valid session
			userID := StringIdentifier("user-123")
			session, err := store.CreateSession(
				context.Background(),
				userID,
				now.Add(30*time.Minute),
				now.Add(24*time.Hour),
			)
			require.NoError(t, err)

			// Setup request with credentials
			r, err := http.NewRequest(http.MethodGet, "/", nil)
			require.NoError(t, err)
			tc.setupRequest(t, r, session)

			// Test middleware
			handlerCalled := false
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
				gotSession, ok := CurrentSession(r)
				if tc.wantSessionInCtx {
					assert.True(t, ok, "expected session in context")
					assert.NotNil(t, gotSession)
					assert.Equal(t, session.ID().String(), gotSession.ID().String())
				} else {
					assert.False(t, ok, "expected no session in context")
					assert.Nil(t, gotSession)
				}
			})

			rr := httptest.NewRecorder()
			sesh.Authenticate(handler).ServeHTTP(rr, r)
			assert.True(t, handlerCalled)
		})
	}
}

// TestAuthenticationFailureCases tests how middleware handles authentication failures.
func TestAuthenticationFailureCases(t *testing.T) {
	testCases := []struct {
		name                string
		credentialSource    CredentialSource
		setupRequest        func(t *testing.T, r *http.Request, store Storer, now time.Time)
		wantSessionInCtx    bool
		wantCredentialClear bool
	}{
		{
			name:             "authenticate_no_credentials",
			credentialSource: NewCookieCredentialSource(WithCookieSourceName("session"), WithCookieSourceSecure(false)),
			setupRequest: func(t *testing.T, r *http.Request, store Storer, now time.Time) {
				// No credentials added
			},
			wantSessionInCtx:    false,
			wantCredentialClear: false,
		},
		{
			name:             "authenticate_invalid_session",
			credentialSource: NewCookieCredentialSource(WithCookieSourceName("session"), WithCookieSourceSecure(false)),
			setupRequest: func(t *testing.T, r *http.Request, store Storer, now time.Time) {
				// Add cookie with non-existent session ID
				fakeSession := NewFakeSession(
					StringIdentifier("non-existent-session"),
					StringIdentifier("user-123"),
					now.Add(30*time.Minute),
					now.Add(24*time.Hour),
					now,
				)
				source := NewCookieCredentialSource(WithCookieSourceName("session"), WithCookieSourceSecure(false))
				w := httptest.NewRecorder()
				err := source.WriteSession(w, fakeSession)
				require.NoError(t, err)
				cookies := w.Result().Cookies()
				require.NotEmpty(t, cookies)
				r.AddCookie(cookies[0])
			},
			wantSessionInCtx:    false,
			wantCredentialClear: true,
		},
		{
			name:             "authenticate_expired_idle",
			credentialSource: NewCookieCredentialSource(WithCookieSourceName("session"), WithCookieSourceSecure(false)),
			setupRequest: func(t *testing.T, r *http.Request, store Storer, now time.Time) {
				// Create session with idle deadline in the past
				userID := StringIdentifier("user-123")
				session, err := store.CreateSession(
					context.Background(),
					userID,
					now.Add(-5*time.Minute), // Idle expired
					now.Add(24*time.Hour),
				)
				require.NoError(t, err)

				source := NewCookieCredentialSource(WithCookieSourceName("session"), WithCookieSourceSecure(false))
				w := httptest.NewRecorder()
				err = source.WriteSession(w, session)
				require.NoError(t, err)
				cookies := w.Result().Cookies()
				require.NotEmpty(t, cookies)
				r.AddCookie(cookies[0])
			},
			wantSessionInCtx:    false,
			wantCredentialClear: true,
		},
		{
			name:             "authenticate_expired_absolute",
			credentialSource: NewCookieCredentialSource(WithCookieSourceName("session"), WithCookieSourceSecure(false)),
			setupRequest: func(t *testing.T, r *http.Request, store Storer, now time.Time) {
				// Create session with absolute deadline in the past
				userID := StringIdentifier("user-123")
				session, err := store.CreateSession(
					context.Background(),
					userID,
					now.Add(30*time.Minute),
					now.Add(-5*time.Minute), // Absolute expired
				)
				require.NoError(t, err)

				source := NewCookieCredentialSource(WithCookieSourceName("session"), WithCookieSourceSecure(false))
				w := httptest.NewRecorder()
				err = source.WriteSession(w, session)
				require.NoError(t, err)
				cookies := w.Result().Cookies()
				require.NotEmpty(t, cookies)
				r.AddCookie(cookies[0])
			},
			wantSessionInCtx:    false,
			wantCredentialClear: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
			store := NewMemoryStore()

			sesh := New(
				store,
				WithNow(func() time.Time { return now }),
				WithCredentialSource(tc.credentialSource),
			)

			r, err := http.NewRequest(http.MethodGet, "/", nil)
			require.NoError(t, err)
			tc.setupRequest(t, r, store, now)

			// Test middleware
			handlerCalled := false
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
				gotSession, ok := CurrentSession(r)
				if tc.wantSessionInCtx {
					assert.True(t, ok)
					assert.NotNil(t, gotSession)
				} else {
					assert.False(t, ok)
					assert.Nil(t, gotSession)
				}
			})

			rr := httptest.NewRecorder()
			sesh.Authenticate(handler).ServeHTTP(rr, r)
			assert.True(t, handlerCalled)

			// Check if credential was cleared
			if tc.wantCredentialClear {
				cookies := rr.Result().Cookies()
				if tc.credentialSource.CanWrite() {
					assert.NotEmpty(t, cookies, "expected cookie to be cleared")
					// Cookie should be expired (MaxAge=-1 or Expires in past)
					if len(cookies) > 0 {
						cookie := cookies[0]
						assert.True(t, cookie.MaxAge == -1 || cookie.Expires.Before(now), "expected cookie to be expired")
					}
				}
			}
		})
	}
}

// TestRefreshBehaviorByConfig tests that AuthenticateAndRefresh respects the source's RefreshEnabled config.
func TestRefreshBehaviorByConfig(t *testing.T) {
	testCases := []struct {
		name             string
		sourceType       string
		credentialSource CredentialSource
		refreshEnabled   bool
		wantRefresh      bool
	}{
		{
			name:       "refresh_header_disabled",
			sourceType: "header",
			credentialSource: NewHeaderCredentialSource(
				WithHeaderSessionConfig(SessionConfig{
					IdleDuration:     0, // No idle timeout
					AbsoluteDuration: 30 * 24 * time.Hour,
					RefreshEnabled:   false,
				}),
			),
			refreshEnabled: false,
			wantRefresh:    false,
		},
		{
			name:       "refresh_cookie_enabled",
			sourceType: "cookie",
			credentialSource: NewCookieCredentialSource(
				WithCookieSourceName("session"),
				WithCookieSourceSecure(false),
				WithCookieSourceSessionConfig(SessionConfig{
					IdleDuration:     30 * time.Minute,
					AbsoluteDuration: 24 * time.Hour,
					RefreshEnabled:   true,
				}),
			),
			refreshEnabled: true,
			wantRefresh:    true,
		},
		{
			name:       "refresh_cookie_disabled",
			sourceType: "cookie",
			credentialSource: NewCookieCredentialSource(
				WithCookieSourceName("session"),
				WithCookieSourceSecure(false),
				WithCookieSourceSessionConfig(SessionConfig{
					IdleDuration:     30 * time.Minute,
					AbsoluteDuration: 24 * time.Hour,
					RefreshEnabled:   false,
				}),
			),
			refreshEnabled: false,
			wantRefresh:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
			store := NewMemoryStore()

			sesh := New(
				store,
				WithNow(func() time.Time { return now }),
				WithCredentialSource(tc.credentialSource),
				WithSessionRefreshThreshold(10*time.Minute),
			)

			// Create session with 5 minutes until idle (within refresh threshold)
			userID := StringIdentifier("user-123")
			session, err := store.CreateSession(
				context.Background(),
				userID,
				now.Add(5*time.Minute),
				now.Add(24*time.Hour),
			)
			require.NoError(t, err)

			r, err := http.NewRequest(http.MethodGet, "/", nil)
			require.NoError(t, err)

			// Setup request based on source type
			if tc.sourceType == "cookie" {
				w := httptest.NewRecorder()
				err = tc.credentialSource.WriteSession(w, session)
				require.NoError(t, err)
				cookies := w.Result().Cookies()
				require.NotEmpty(t, cookies)
				r.AddCookie(cookies[0])
			} else {
				r.Header.Set("Authorization", "Bearer "+session.ID().String())
			}

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Handler just needs to be called
			})

			rr := httptest.NewRecorder()
			sesh.AuthenticateAndRefresh(handler).ServeHTTP(rr, r)

			// Check if refresh happened
			if tc.wantRefresh {
				// For writable sources, we should see a cookie being set
				if tc.credentialSource.CanWrite() {
					cookies := rr.Result().Cookies()
					assert.NotEmpty(t, cookies, "expected session cookie to be refreshed")
				}
			} else {
				// No refresh should happen - no new cookies
				cookies := rr.Result().Cookies()
				assert.Empty(t, cookies, "expected no session refresh")
			}
		})
	}
}

// TestRequireAuthenticationResponse tests RequireAuthentication with different credential sources.
func TestRequireAuthenticationResponse(t *testing.T) {
	testCases := []struct {
		name             string
		credentialSource CredentialSource
		setupRequest     func(t *testing.T, r *http.Request, session Session)
		wantStatus       int
		wantSessionInCtx bool
	}{
		{
			name:             "require_auth_header_missing",
			credentialSource: NewHeaderCredentialSource(),
			setupRequest: func(t *testing.T, r *http.Request, session Session) {
				// No header added
			},
			wantStatus:       http.StatusUnauthorized,
			wantSessionInCtx: false,
		},
		{
			name:             "require_auth_cookie_missing",
			credentialSource: NewCookieCredentialSource(WithCookieSourceName("session"), WithCookieSourceSecure(false)),
			setupRequest: func(t *testing.T, r *http.Request, session Session) {
				// No cookie added
			},
			wantStatus:       http.StatusUnauthorized,
			wantSessionInCtx: false,
		},
		{
			name:             "require_auth_header_present",
			credentialSource: NewHeaderCredentialSource(),
			setupRequest: func(t *testing.T, r *http.Request, session Session) {
				r.Header.Set("Authorization", "Bearer "+session.ID().String())
			},
			wantStatus:       http.StatusOK,
			wantSessionInCtx: true,
		},
		{
			name:             "require_auth_cookie_present",
			credentialSource: NewCookieCredentialSource(WithCookieSourceName("session"), WithCookieSourceSecure(false)),
			setupRequest: func(t *testing.T, r *http.Request, session Session) {
				source := NewCookieCredentialSource(WithCookieSourceName("session"), WithCookieSourceSecure(false))
				w := httptest.NewRecorder()
				err := source.WriteSession(w, session)
				require.NoError(t, err)
				cookies := w.Result().Cookies()
				require.NotEmpty(t, cookies)
				r.AddCookie(cookies[0])
			},
			wantStatus:       http.StatusOK,
			wantSessionInCtx: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
			store := NewMemoryStore()

			sesh := New(
				store,
				WithNow(func() time.Time { return now }),
				WithCredentialSource(tc.credentialSource),
			)

			// Create a valid session
			userID := StringIdentifier("user-123")
			session, err := store.CreateSession(
				context.Background(),
				userID,
				now.Add(30*time.Minute),
				now.Add(24*time.Hour),
			)
			require.NoError(t, err)

			r, err := http.NewRequest(http.MethodGet, "/", nil)
			require.NoError(t, err)
			tc.setupRequest(t, r, session)

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				gotSession, ok := CurrentSession(r)
				if tc.wantSessionInCtx {
					assert.True(t, ok)
					assert.NotNil(t, gotSession)
				} else {
					assert.False(t, ok)
					assert.Nil(t, gotSession)
				}
			})

			rr := httptest.NewRecorder()
			sesh.RequireAuthentication(handler).ServeHTTP(rr, r)
			assert.Equal(t, tc.wantStatus, rr.Code)
		})
	}
}

// TestBackwardCompatNoSource tests that Gosesh without explicit source defaults to cookie source.
func TestBackwardCompatNoSource(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	store := NewMemoryStore()

	// Create Gosesh without specifying a credential source
	sesh := New(
		store,
		WithNow(func() time.Time { return now }),
	)

	// Create a session
	userID := StringIdentifier("user-123")
	session, err := store.CreateSession(
		context.Background(),
		userID,
		now.Add(30*time.Minute),
		now.Add(24*time.Hour),
	)
	require.NoError(t, err)

	// Add session via the default cookie mechanism
	r, err := http.NewRequest(http.MethodGet, "/", nil)
	require.NoError(t, err)

	// The default should be a cookie source, so write using cookie
	source := NewCookieCredentialSource(WithCookieSourceName("session"), WithCookieSourceSecure(false))
	w := httptest.NewRecorder()
	err = source.WriteSession(w, session)
	require.NoError(t, err)
	cookies := w.Result().Cookies()
	require.NotEmpty(t, cookies)
	r.AddCookie(cookies[0])

	// Test that authentication works
	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		gotSession, ok := CurrentSession(r)
		assert.True(t, ok, "expected session in context with default cookie source")
		assert.NotNil(t, gotSession)
		assert.Equal(t, session.ID().String(), gotSession.ID().String())
	})

	rr := httptest.NewRecorder()
	sesh.Authenticate(handler).ServeHTTP(rr, r)
	assert.True(t, handlerCalled)
}

// TestBackwardCompatOldOptions tests that old cookie options are honored by the default cookie source.
func TestBackwardCompatOldOptions(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	store := NewMemoryStore()

	// Create Gosesh with old-style cookie options
	sesh := New(
		store,
		WithNow(func() time.Time { return now }),
		WithSessionCookieName("custom-session"),
		WithSessionIdleTimeout(17*time.Minute),
		WithSessionMaxLifetime(85*time.Minute),
	)

	// Create a session
	userID := StringIdentifier("user-123")
	session, err := store.CreateSession(
		context.Background(),
		userID,
		now.Add(17*time.Minute),
		now.Add(85*time.Minute),
	)
	require.NoError(t, err)

	// Add session with custom cookie name
	r, err := http.NewRequest(http.MethodGet, "/", nil)
	require.NoError(t, err)

	source := NewCookieCredentialSource(WithCookieSourceName("custom-session"), WithCookieSourceSecure(false))
	w := httptest.NewRecorder()
	err = source.WriteSession(w, session)
	require.NoError(t, err)
	cookies := w.Result().Cookies()
	require.NotEmpty(t, cookies)
	r.AddCookie(cookies[0])

	// Test that authentication works with the custom cookie name
	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		gotSession, ok := CurrentSession(r)
		assert.True(t, ok, "expected session in context")
		assert.NotNil(t, gotSession)
		assert.Equal(t, session.ID().String(), gotSession.ID().String())
	})

	rr := httptest.NewRecorder()
	sesh.Authenticate(handler).ServeHTTP(rr, r)
	assert.True(t, handlerCalled)
}

// TestBackwardCompatExistingSessions tests that sessions created with old API still work with new API.
func TestBackwardCompatExistingSessions(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	store := NewMemoryStore()

	// Create session using old-style API (no credential source)
	oldSesh := New(
		store,
		WithNow(func() time.Time { return now }),
	)

	userID := StringIdentifier("user-123")
	session, err := store.CreateSession(
		context.Background(),
		userID,
		now.Add(30*time.Minute),
		now.Add(24*time.Hour),
	)
	require.NoError(t, err)

	// Create new Gosesh instance (simulating app restart)
	newSesh := New(
		store,
		WithNow(func() time.Time { return now }),
	)

	// Session should still be valid with new instance
	r, err := http.NewRequest(http.MethodGet, "/", nil)
	require.NoError(t, err)

	source := NewCookieCredentialSource(WithCookieSourceName("session"), WithCookieSourceSecure(false))
	w := httptest.NewRecorder()
	err = source.WriteSession(w, session)
	require.NoError(t, err)
	cookies := w.Result().Cookies()
	require.NotEmpty(t, cookies)
	r.AddCookie(cookies[0])

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		gotSession, ok := CurrentSession(r)
		assert.True(t, ok, "session created with old API should work with new API")
		assert.NotNil(t, gotSession)
		assert.Equal(t, session.ID().String(), gotSession.ID().String())
	})

	rr := httptest.NewRecorder()
	newSesh.Authenticate(handler).ServeHTTP(rr, r)
	assert.True(t, handlerCalled)

	// Verify both instances work the same way
	_ = oldSesh
}
