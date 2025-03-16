package tests

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rlebel12/gosesh"
	mock_gosesh "github.com/rlebel12/gosesh/mocks"
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
			store := mock_gosesh.NewStorer(t)
			parser := mock_gosesh.NewIDParser(t)
			identifier := mock_gosesh.NewIdentifier(t)
			r, err := http.NewRequest(http.MethodGet, "/", nil)
			require.NoError(err)

			var expectedLogs []string
			var wantSecureCookieHeaders bool
			withLogger, slogger := prepareSlogger()
			sesh := gosesh.New(parser.Execute, store,
				gosesh.WithNow(func() time.Time { return now }),
				gosesh.WithSessionCookieName("customName"),
				gosesh.WithSessionActiveDuration(17*time.Minute),
				gosesh.WithSessionIdleDuration(85*time.Minute),
				withLogger,
			)

			func() {
				if test == CaseNoSession {
					wantSecureCookieHeaders = true
					return
				}

				if test == CaseSessionActive {
					session := mock_gosesh.NewSession(t)
					session.EXPECT().IdleAt().Return(now.Add(5 * time.Minute))
					r = r.WithContext(context.WithValue(r.Context(), gosesh.SessionContextKey, session))
					return
				}
				session := mock_gosesh.NewSession(t)
				session.EXPECT().IdleAt().Return(now.Add(-5 * time.Minute))
				session.EXPECT().UserID().Return(identifier)
				identifier.EXPECT().String().Return("identifier")
				r = r.WithContext(context.WithValue(r.Context(), gosesh.SessionContextKey, session))

				createSessionFn := store.EXPECT().CreateSession(r.Context(), gosesh.CreateSessionRequest{
					UserID:   identifier,
					IdleAt:   now.Add(17 * time.Minute),
					ExpireAt: now.Add(85 * time.Minute),
				})
				if test == CaseSessionIdleFaileCreateReplacement {
					createSessionFn.Return(nil, errors.New("mock failure"))
					expectedLogs = append(expectedLogs, "msg=\"replace session\" error=\"create session: mock failure\"")
					return
				}
				new_session := mock_gosesh.NewSession(t)
				createSessionFn.Return(new_session, nil)

				session.EXPECT().ID().Return(identifier)
				deleteSessionFn := store.EXPECT().DeleteSession(r.Context(), identifier)
				if test == CaseSessionIdleFailedDeleteOld {
					deleteSessionFn.Return(errors.New("mock failure"))
					expectedLogs = append(expectedLogs, "msg=\"replace session\" error=\"delete session: mock failure\"")
					return
				}
				deleteSessionFn.Return(nil)

				if test == CaseSessionIdleSuccess {
					new_session.EXPECT().ID().Return(identifier)
					new_session.EXPECT().ExpireAt().Return(now.Add(85 * time.Minute))
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
				assert.Contains(slogger.logs[i], expectedLog)
			}
			if test < CaseSessionIdleSuccess {
				return
			}
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
		store := mock_gosesh.NewStorer(t)
		parser := mock_gosesh.NewIDParser(t)
		r, err := http.NewRequest(http.MethodGet, "/", nil)
		require.NoError(err)
		sesh := gosesh.New(parser.Execute, store, gosesh.WithNow(func() time.Time { return now }))
		rr := httptest.NewRecorder()

		session := mock_gosesh.NewSession(t)
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
		store := mock_gosesh.NewStorer(t)
		parser := mock_gosesh.NewIDParser(t)
		sesh := gosesh.New(parser.Execute, store, gosesh.WithNow(func() time.Time { return now }))
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
				return r.WithContext(context.WithValue(r.Context(), gosesh.SessionContextKey, mock_gosesh.NewSession(t)))
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
			store := mock_gosesh.NewStorer(t)
			parser := mock_gosesh.NewIDParser(t)

			r, err := http.NewRequest(http.MethodGet, "/", nil)
			if test.giveSession != nil {
				r = test.giveSession(t, r)
			}
			if test.giveHeader != nil {
				r.Header = test.giveHeader
			}
			require.NoError(err)

			sesh := gosesh.New(parser.Execute, store, gosesh.WithNow(func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }))
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
