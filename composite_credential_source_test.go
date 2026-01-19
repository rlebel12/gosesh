package gosesh

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompositeCredentialSource(t *testing.T) {
	t.Run("name_returns_composite", func(t *testing.T) {
		source := NewCompositeCredentialSource()
		assert.Equal(t, "composite", source.Name(), "Name() should return 'composite'")
	})

	t.Run("session_config_first_source", func(t *testing.T) {
		cookieSource := NewCookieCredentialSource(
			WithCookieSourceSessionConfig(SessionConfig{
				IdleDuration:     10 * time.Minute,
				AbsoluteDuration: 1 * time.Hour,
				RefreshThreshold: nil,
			}),
		)
		headerSource := NewHeaderCredentialSource(
			WithHeaderSessionConfig(SessionConfig{
				IdleDuration:     0,
				AbsoluteDuration: 30 * 24 * time.Hour,
				RefreshThreshold: nil,
			}),
		)

		source := NewCompositeCredentialSource(cookieSource, headerSource)
		config := source.SessionConfig()

		// Should get config from first source (cookie)
		assert.Equal(t, 10*time.Minute, config.IdleDuration)
		assert.Equal(t, 1*time.Hour, config.AbsoluteDuration)
		assert.Nil(t, config.RefreshThreshold)
	})

	t.Run("read_session_id_priority", func(t *testing.T) {
		tests := []struct {
			name           string
			sources        []CredentialSource
			setupRequest   func(*http.Request)
			expectedResult string
		}{
			{
				name:    "read_first_source",
				sources: []CredentialSource{NewCookieCredentialSource(), NewHeaderCredentialSource()},
				setupRequest: func(r *http.Request) {
					// Add cookie only
					r.AddCookie(&http.Cookie{
						Name:  "session",
						Value: base64.URLEncoding.EncodeToString([]byte("cookie-session")),
					})
				},
				expectedResult: "cookie-session",
			},
			{
				name:    "read_second_source",
				sources: []CredentialSource{NewCookieCredentialSource(), NewHeaderCredentialSource()},
				setupRequest: func(r *http.Request) {
					// Add header only
					r.Header.Set("Authorization", "Bearer header-session")
				},
				expectedResult: "header-session",
			},
			{
				name:    "read_both_present",
				sources: []CredentialSource{NewCookieCredentialSource(), NewHeaderCredentialSource()},
				setupRequest: func(r *http.Request) {
					// Add both cookie and header
					r.AddCookie(&http.Cookie{
						Name:  "session",
						Value: base64.URLEncoding.EncodeToString([]byte("cookie-session")),
					})
					r.Header.Set("Authorization", "Bearer header-session")
				},
				expectedResult: "cookie-session", // First takes priority
			},
			{
				name:    "read_neither_present",
				sources: []CredentialSource{NewCookieCredentialSource(), NewHeaderCredentialSource()},
				setupRequest: func(r *http.Request) {
					// Don't add anything
				},
				expectedResult: "",
			},
			{
				name:    "read_reversed_order",
				sources: []CredentialSource{NewHeaderCredentialSource(), NewCookieCredentialSource()},
				setupRequest: func(r *http.Request) {
					// Add both cookie and header
					r.AddCookie(&http.Cookie{
						Name:  "session",
						Value: base64.URLEncoding.EncodeToString([]byte("cookie-session")),
					})
					r.Header.Set("Authorization", "Bearer header-session")
				},
				expectedResult: "header-session", // Header is first, so it wins
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				source := NewCompositeCredentialSource(tt.sources...)
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				tt.setupRequest(req)

				result := source.ReadSessionID(req)
				assert.Equal(t, tt.expectedResult, result)
			})
		}
	})

	t.Run("can_write_based_on_composition", func(t *testing.T) {
		tests := []struct {
			name     string
			sources  []CredentialSource
			expected bool
		}{
			{
				name:     "can_write_any_writable",
				sources:  []CredentialSource{NewCookieCredentialSource(), NewHeaderCredentialSource()},
				expected: true, // Cookie can write
			},
			{
				name:     "can_write_none_writable",
				sources:  []CredentialSource{NewHeaderCredentialSource(), NewHeaderCredentialSource()},
				expected: false, // Neither can write
			},
			{
				name:     "can_write_all_writable",
				sources:  []CredentialSource{NewCookieCredentialSource(), NewCookieCredentialSource()},
				expected: true, // Both can write
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				source := NewCompositeCredentialSource(tt.sources...)
				assert.Equal(t, tt.expected, source.CanWrite())
			})
		}
	})

	t.Run("write_to_writable", func(t *testing.T) {
		cookieSource := NewCookieCredentialSource()
		headerSource := NewHeaderCredentialSource()
		source := NewCompositeCredentialSource(cookieSource, headerSource)

		sessionID := StringIdentifier("test-session-id")
		userID := StringIdentifier("test-user-id")
		now := time.Now()
		session := NewFakeSession(
			sessionID,
			userID,
			now.Add(30*time.Minute),
			now.Add(24*time.Hour),
			now,
		)

		w := httptest.NewRecorder()
		err := source.WriteSession(w, session)
		require.NoError(t, err)

		// Cookie should be written (cookie source can write)
		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1, "Should have exactly one cookie from cookie source")
		assert.Equal(t, "session", cookies[0].Name)

		// Header source doesn't write anything (it's read-only)
		// So we just verify no error occurred
	})

	t.Run("write_multiple_writable", func(t *testing.T) {
		cookieSource1 := NewCookieCredentialSource(WithCookieSourceName("session1"))
		cookieSource2 := NewCookieCredentialSource(WithCookieSourceName("session2"))
		source := NewCompositeCredentialSource(cookieSource1, cookieSource2)

		sessionID := StringIdentifier("test-session-id")
		userID := StringIdentifier("test-user-id")
		now := time.Now()
		session := NewFakeSession(
			sessionID,
			userID,
			now.Add(30*time.Minute),
			now.Add(24*time.Hour),
			now,
		)

		w := httptest.NewRecorder()
		err := source.WriteSession(w, session)
		require.NoError(t, err)

		// Both cookies should be written
		cookies := w.Result().Cookies()
		require.Len(t, cookies, 2, "Should have two cookies from both sources")

		cookieNames := make(map[string]bool)
		for _, cookie := range cookies {
			cookieNames[cookie.Name] = true
		}
		assert.True(t, cookieNames["session1"], "Should have session1 cookie")
		assert.True(t, cookieNames["session2"], "Should have session2 cookie")
	})

	t.Run("clear_to_writable", func(t *testing.T) {
		cookieSource := NewCookieCredentialSource()
		headerSource := NewHeaderCredentialSource()
		source := NewCompositeCredentialSource(cookieSource, headerSource)

		w := httptest.NewRecorder()
		err := source.ClearSession(w)
		require.NoError(t, err)

		// Cookie should be cleared (cookie source can write)
		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1, "Should have exactly one cookie being cleared")
		assert.Equal(t, "session", cookies[0].Name)
		assert.Equal(t, -1, cookies[0].MaxAge, "Cookie should have MaxAge=-1 to clear it")
	})

	t.Run("empty_sources", func(t *testing.T) {
		source := NewCompositeCredentialSource()

		// Name should still work
		assert.Equal(t, "composite", source.Name())

		// CanWrite should return false with no sources
		assert.False(t, source.CanWrite())

		// SessionConfig should return zero value
		config := source.SessionConfig()
		assert.Equal(t, SessionConfig{}, config)

		// ReadSessionID should return empty string
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		result := source.ReadSessionID(req)
		assert.Equal(t, "", result)

		// WriteSession should be no-op
		sessionID := StringIdentifier("test-session-id")
		userID := StringIdentifier("test-user-id")
		now := time.Now()
		session := NewFakeSession(
			sessionID,
			userID,
			now.Add(30*time.Minute),
			now.Add(24*time.Hour),
			now,
		)
		w := httptest.NewRecorder()
		err := source.WriteSession(w, session)
		assert.NoError(t, err)

		// ClearSession should be no-op
		w = httptest.NewRecorder()
		err = source.ClearSession(w)
		assert.NoError(t, err)
	})

	t.Run("single_source", func(t *testing.T) {
		cookieSource := NewCookieCredentialSource()
		source := NewCompositeCredentialSource(cookieSource)

		// Should behave exactly like the cookie source
		assert.Equal(t, "composite", source.Name())
		assert.True(t, source.CanWrite())

		// Config should match cookie source
		config := source.SessionConfig()
		cookieConfig := cookieSource.SessionConfig()
		assert.Equal(t, cookieConfig, config)

		// Read should work
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{
			Name:  "session",
			Value: base64.URLEncoding.EncodeToString([]byte("test-session")),
		})
		result := source.ReadSessionID(req)
		assert.Equal(t, "test-session", result)

		// Write should work
		sessionID := StringIdentifier("test-session-id")
		userID := StringIdentifier("test-user-id")
		now := time.Now()
		session := NewFakeSession(
			sessionID,
			userID,
			now.Add(30*time.Minute),
			now.Add(24*time.Hour),
			now,
		)
		w := httptest.NewRecorder()
		err := source.WriteSession(w, session)
		require.NoError(t, err)

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1)
		assert.Equal(t, "session", cookies[0].Name)
	})
}

func TestCompositeCredentialSourceContract(t *testing.T) {
	contract := CredentialSourceContract{
		Name: "CompositeCredentialSource",
		NewSource: func() CredentialSource {
			// Use cookie source for writable composite
			return NewCompositeCredentialSource(NewCookieCredentialSource())
		},
		RequestFromResponse: func(w *httptest.ResponseRecorder) *http.Request {
			// Convert Set-Cookie headers back into a request with cookies
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			for _, cookie := range w.Result().Cookies() {
				req.AddCookie(cookie)
			}
			return req
		},
	}
	contract.Test(t)
}
