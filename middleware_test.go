package gosesh

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestAuthenticateAndRefreshCase int

const (
	CaseNoSession TestAuthenticateAndRefreshCase = iota
	CaseSessionActive
	CaseSessionIdleFaileCreateReplacement
	CaseSessionIdleFailedDeleteOld
	CaseSessionIdleSuccess
)

type testLogger struct {
	logs []string
}

func (l *testLogger) Write(p []byte) (n int, err error) {
	l.logs = append(l.logs, string(p))
	return len(p), nil
}

func prepareTestLogger() (func(*Gosesh), *testLogger) {
	logger := &testLogger{}
	handler := slog.NewTextHandler(logger, nil)
	return func(g *Gosesh) {
		g.logger = slog.New(handler)
	}, logger
}

type erroringStore struct {
	*MemoryStore
	createSessionError bool
	deleteSessionError bool
}

func (s *erroringStore) CreateSession(ctx context.Context, req CreateSessionRequest) (Session, error) {
	if s.createSessionError {
		return nil, errors.New("mock failure")
	}
	return s.MemoryStore.CreateSession(ctx, req)
}

func (s *erroringStore) DeleteSession(ctx context.Context, sessionID Identifier) error {
	if s.deleteSessionError {
		return errors.New("mock failure")
	}
	return s.MemoryStore.DeleteSession(ctx, sessionID)
}

func TestAuthenticateAndRefresh(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	now := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)

	for name, test := range map[string]TestAuthenticateAndRefreshCase{
		"no current session":                     CaseNoSession,
		"session active":                         CaseSessionActive,
		"session idle failed create replacement": CaseSessionIdleFaileCreateReplacement,
		"session idle failed delete old":         CaseSessionIdleFailedDeleteOld,
		"session idle success":                   CaseSessionIdleSuccess,
	} {
		t.Run(name, func(t *testing.T) {
			store := NewMemoryStore()
			errorStore := &erroringStore{MemoryStore: store}
			parser := func(b []byte) (Identifier, error) {
				return NewFakeIdentifier("identifier"), nil
			}
			identifier := NewFakeIdentifier("identifier")
			r, err := http.NewRequest(http.MethodGet, "/", nil)
			require.NoError(err)

			var expectedLogs []string
			var wantSecureCookieHeaders bool
			withLogger, logger := prepareTestLogger()
			sesh := New(parser, errorStore,
				WithNow(func() time.Time { return now }),
				WithSessionCookieName("customName"),
				WithSessionActiveDuration(17*time.Minute),
				WithSessionIdleDuration(85*time.Minute),
				withLogger,
			)

			func() {
				if test == CaseNoSession {
					wantSecureCookieHeaders = true
					return
				}

				if test == CaseSessionActive {
					session, err := store.CreateSession(t.Context(), CreateSessionRequest{
						UserID:   identifier,
						IdleAt:   now.Add(5 * time.Minute),
						ExpireAt: now.Add(85 * time.Minute),
					})
					require.NoError(err)
					r = r.WithContext(context.WithValue(r.Context(), SessionContextKey, session))
					return
				}

				session, err := store.CreateSession(t.Context(), CreateSessionRequest{
					UserID:   identifier,
					IdleAt:   now.Add(-5 * time.Minute),
					ExpireAt: now.Add(85 * time.Minute),
				})
				require.NoError(err)
				r = r.WithContext(context.WithValue(r.Context(), SessionContextKey, session))

				if test == CaseSessionIdleFaileCreateReplacement {
					errorStore.createSessionError = true
					expectedLogs = append(expectedLogs, "msg=\"replace session\" error=\"create session: mock failure\"")
					return
				}

				if test == CaseSessionIdleFailedDeleteOld {
					errorStore.deleteSessionError = true
					expectedLogs = append(expectedLogs, "msg=\"replace session\" error=\"delete session: mock failure\"")
					return
				}
			}()

			handlerCalled := false
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
			})
			rr := httptest.NewRecorder()

			sesh.AuthenticateAndRefresh(handler).ServeHTTP(rr, r)

			result := rr.Result()

			if wantSecureCookieHeaders {
				assert.Equal(`private, no-cache="Set-Cookie"`, result.Header.Get("Cache-Control"))
				assert.Equal("Cookie", result.Header.Get("Vary"))
			} else {
				assert.Empty(result.Header.Get("Cache-Control"))
				assert.Empty(result.Header.Get("Vary"))
			}

			assert.True(handlerCalled)
			for i, expectedLog := range expectedLogs {
				assert.Contains(logger.logs[i], expectedLog)
			}
			if test < CaseSessionIdleSuccess {
				return
			}

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
		})
	}
}

func TestRequireAuthentication(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	now := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("authenticated", func(t *testing.T) {
		store := NewMemoryStore()
		parser := func(b []byte) (Identifier, error) {
			return NewFakeIdentifier("identifier"), nil
		}
		r, err := http.NewRequest(http.MethodGet, "/", nil)
		require.NoError(err)
		sesh := New(parser, store, WithNow(func() time.Time { return now }))
		rr := httptest.NewRecorder()

		session := NewFakeSession(
			NewFakeIdentifier("session-id"),
			NewFakeIdentifier("user-id"),
			now,
			now.Add(time.Hour),
		)
		r = r.WithContext(context.WithValue(r.Context(), SessionContextKey, session))

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
		parser := func(b []byte) (Identifier, error) {
			return NewFakeIdentifier("identifier"), nil
		}
		sesh := New(parser, store, WithNow(func() time.Time { return now }))
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
					NewFakeIdentifier("session-id"),
					NewFakeIdentifier("user-id"),
					time.Now(),
					time.Now().Add(time.Hour),
				)
				return r.WithContext(context.WithValue(r.Context(), SessionContextKey, session))
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
			parser := func(b []byte) (Identifier, error) {
				return NewFakeIdentifier("identifier"), nil
			}

			r, err := http.NewRequest(http.MethodGet, "/", nil)
			if test.giveSession != nil {
				r = test.giveSession(t, r)
			}
			if test.giveHeader != nil {
				r.Header = test.giveHeader
			}
			require.NoError(err)

			sesh := New(parser, store, WithNow(func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }))
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
