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

func TestCookieCredentialSource(t *testing.T) {
	t.Run("name_returns_cookie", func(t *testing.T) {
		source := NewCookieCredentialSource()
		assert.Equal(t, "cookie", source.Name(), "Name() should return 'cookie'")
	})

	t.Run("can_write_true", func(t *testing.T) {
		source := NewCookieCredentialSource()
		assert.True(t, source.CanWrite(), "CanWrite() should return true for cookies")
	})

	t.Run("session_config_defaults", func(t *testing.T) {
		source := NewCookieCredentialSource()
		config := source.SessionConfig()
		assert.Equal(t, 30*time.Minute, config.IdleDuration, "Default idle duration should be 30 minutes")
		assert.Equal(t, 24*time.Hour, config.AbsoluteDuration, "Default absolute duration should be 24 hours")
		require.NotNil(t, config.RefreshThreshold, "Default should have refresh threshold set")
		assert.Equal(t, 10*time.Minute, *config.RefreshThreshold, "Default refresh threshold should be 10 minutes")
	})

	t.Run("read_session_id", func(t *testing.T) {
		tests := []struct {
			name           string
			cookieValue    string
			expectedResult RawSessionID
			setupCookie    bool
		}{
			{
				name:           "read_missing_cookie",
				setupCookie:    false,
				expectedResult: "",
			},
			{
				name:           "read_valid_cookie",
				cookieValue:    base64.URLEncoding.EncodeToString([]byte("test-session-id")),
				expectedResult: RawSessionID("test-session-id"),
				setupCookie:    true,
			},
			{
				name:           "read_invalid_base64",
				cookieValue:    "not-valid-base64!!!",
				expectedResult: "",
				setupCookie:    true,
			},
			{
				name:           "read_empty_value",
				cookieValue:    "",
				expectedResult: "",
				setupCookie:    true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				source := NewCookieCredentialSource()
				req := httptest.NewRequest(http.MethodGet, "/", nil)

				if tt.setupCookie {
					req.AddCookie(&http.Cookie{
						Name:  "session",
						Value: tt.cookieValue,
					})
				}

				result := source.ReadSessionID(req)
				assert.Equal(t, tt.expectedResult, result)
			})
		}
	})

	t.Run("cookie_attributes", func(t *testing.T) {
		source := NewCookieCredentialSource()
		hashedID := HashedSessionID("test-hashed-id")
	_ = RawSessionID("test-raw-id")
		userID := "test-user-id"
		now := time.Now()
		session := NewFakeSession(
			hashedID,
			userID,
			now.Add(30*time.Minute),
			now.Add(24*time.Hour),
			now,
		)

		w := httptest.NewRecorder()
		err := source.WriteSession(w, RawSessionID("test-raw"), session)
		require.NoError(t, err)

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1, "Should have exactly one cookie")
		cookie := cookies[0]

		// Test all attributes in parameterized fashion
		attributes := []struct {
			name     string
			actual   interface{}
			expected interface{}
		}{
			{"HttpOnly", cookie.HttpOnly, true},
			{"Secure", cookie.Secure, true},
			{"SameSite", cookie.SameSite, http.SameSiteLaxMode},
			{"Path", cookie.Path, "/"},
		}

		for _, attr := range attributes {
			t.Run(attr.name, func(t *testing.T) {
				assert.Equal(t, attr.expected, attr.actual, "%s should match expected value", attr.name)
			})
		}
	})

	t.Run("write_sets_cookie", func(t *testing.T) {
		source := NewCookieCredentialSource()
		hashedID := HashedSessionID("test-hashed-id")
	_ = RawSessionID("test-raw-id")
		userID := "test-user-id"
		now := time.Now()
		session := NewFakeSession(
			hashedID,
			userID,
			now.Add(30*time.Minute),
			now.Add(24*time.Hour),
			now,
		)

		w := httptest.NewRecorder()
		err := source.WriteSession(w, RawSessionID("test-raw"), session)
		require.NoError(t, err)

		assert.NotEmpty(t, w.Header().Get("Set-Cookie"), "Response should have Set-Cookie header")

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1, "Should have exactly one cookie")
		assert.Equal(t, "session", cookies[0].Name, "Cookie name should be 'session'")

		// Verify cookie value is base64 encoded session ID
		decoded, err := base64.URLEncoding.DecodeString(cookies[0].Value)
		require.NoError(t, err, "Cookie value should be valid base64")
		assert.Equal(t, "test-raw", string(decoded), "Decoded cookie value should match raw session ID")
	})

	t.Run("write_cookie_expiry", func(t *testing.T) {
		source := NewCookieCredentialSource()
		hashedID := HashedSessionID("test-hashed-id")
	_ = RawSessionID("test-raw-id")
		userID := "test-user-id"
		now := time.Now()
		absoluteDeadline := now.Add(24 * time.Hour)
		session := NewFakeSession(
			hashedID,
			userID,
			now.Add(30*time.Minute),
			absoluteDeadline,
			now,
		)

		w := httptest.NewRecorder()
		err := source.WriteSession(w, RawSessionID("test-raw"), session)
		require.NoError(t, err)

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1)

		// Cookie expiry should match session's absolute deadline
		// Allow small time tolerance for test execution
		assert.WithinDuration(t, absoluteDeadline, cookies[0].Expires, time.Second,
			"Cookie expires should match session's AbsoluteDeadline")
	})

	t.Run("clear_expires_cookie", func(t *testing.T) {
		source := NewCookieCredentialSource()
		w := httptest.NewRecorder()
		err := source.ClearSession(w)
		require.NoError(t, err)

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1, "Should have exactly one cookie")

		cookie := cookies[0]
		assert.Equal(t, "session", cookie.Name, "Cookie name should be 'session'")
		assert.Equal(t, -1, cookie.MaxAge, "MaxAge should be -1 to expire cookie")
		assert.True(t, cookie.Expires.Before(time.Now()), "Expires should be in the past")
	})

	t.Run("custom_options", func(t *testing.T) {
		tests := []struct {
			name       string
			option     CookieSourceOption
			verifyFunc func(t *testing.T, source *CookieCredentialSource, w *httptest.ResponseRecorder)
		}{
			{
				name:   "WithCookieSourceName",
				option: WithCookieSourceName("custom"),
				verifyFunc: func(t *testing.T, source *CookieCredentialSource, w *httptest.ResponseRecorder) {
					cookies := w.Result().Cookies()
					require.Len(t, cookies, 1)
					assert.Equal(t, "custom", cookies[0].Name, "Cookie name should be 'custom'")
				},
			},
			{
				name:   "WithCookieSourceDomain",
				option: WithCookieSourceDomain(".example.com"),
				verifyFunc: func(t *testing.T, source *CookieCredentialSource, w *httptest.ResponseRecorder) {
					cookies := w.Result().Cookies()
					require.Len(t, cookies, 1)
					// Note: Go's http.SetCookie normalizes domains by removing leading dot (RFC 6265)
					assert.Equal(t, "example.com", cookies[0].Domain, "Cookie domain should be 'example.com' (normalized)")
				},
			},
			{
				name:   "WithCookieSourceSecure",
				option: WithCookieSourceSecure(false),
				verifyFunc: func(t *testing.T, source *CookieCredentialSource, w *httptest.ResponseRecorder) {
					cookies := w.Result().Cookies()
					require.Len(t, cookies, 1)
					assert.False(t, cookies[0].Secure, "Cookie Secure flag should be false")
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				source := NewCookieCredentialSource(tt.option)

				// Write a session to test the option
				hashedID := HashedSessionID("test-hashed-id")
	_ = RawSessionID("test-raw-id")
				userID := "test-user-id"
				now := time.Now()
				session := NewFakeSession(
					hashedID,
					userID,
					now.Add(30*time.Minute),
					now.Add(24*time.Hour),
					now,
				)

				w := httptest.NewRecorder()
				err := source.WriteSession(w, RawSessionID("test-raw"), session)
				require.NoError(t, err)

				tt.verifyFunc(t, source, w)
			})
		}
	})

	t.Run("custom_session_config", func(t *testing.T) {
		customConfig := SessionConfig{
			IdleDuration:     1 * time.Hour,
			AbsoluteDuration: 48 * time.Hour,
			RefreshThreshold: nil,
		}
		source := NewCookieCredentialSource(WithCookieSourceSessionConfig(customConfig))

		config := source.SessionConfig()
		assert.Equal(t, customConfig.IdleDuration, config.IdleDuration)
		assert.Equal(t, customConfig.AbsoluteDuration, config.AbsoluteDuration)
		assert.Equal(t, customConfig.RefreshThreshold, config.RefreshThreshold)
	})

	t.Run("empty_session_id_edge_case", func(t *testing.T) {
		source := NewCookieCredentialSource()
		hashedID := HashedSessionID("")
		userID := "test-user-id"
		now := time.Now()
		session := NewFakeSession(
			hashedID,
			userID,
			now.Add(30*time.Minute),
			now.Add(24*time.Hour),
			now,
		)

		w := httptest.NewRecorder()
		err := source.WriteSession(w, RawSessionID("test-raw"), session)

		// Should still work, just with empty encoded value
		require.NoError(t, err)
	})

	t.Run("cookie_name_with_special_characters", func(t *testing.T) {
		// Cookie names with special characters should work
		source := NewCookieCredentialSource(WithCookieSourceName("my-session_2"))
		hashedID := HashedSessionID("test-id")
		userID := "test-user"
		now := time.Now()
		session := NewFakeSession(hashedID, userID, now.Add(time.Minute), now.Add(time.Hour), now)

		w := httptest.NewRecorder()
		err := source.WriteSession(w, RawSessionID("test-raw"), session)
		require.NoError(t, err)

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1)
		assert.Equal(t, "my-session_2", cookies[0].Name)
	})

	t.Run("domain_with_leading_dot", func(t *testing.T) {
		source := NewCookieCredentialSource(WithCookieSourceDomain(".example.com"))
		hashedID := HashedSessionID("test-id")
		userID := "test-user"
		now := time.Now()
		session := NewFakeSession(hashedID, userID, now.Add(time.Minute), now.Add(time.Hour), now)

		w := httptest.NewRecorder()
		err := source.WriteSession(w, RawSessionID("test-raw"), session)
		require.NoError(t, err)

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1)
		// Note: Go's http.SetCookie normalizes domains by removing leading dot (RFC 6265)
		assert.Equal(t, "example.com", cookies[0].Domain)
	})
}

// TestCookieCredentialSourceContract runs the contract tests for CookieCredentialSource
func TestCookieCredentialSourceContract(t *testing.T) {
	contract := CredentialSourceContract{
		Name: "CookieCredentialSource",
		NewSource: func() CredentialSource {
			return NewCookieCredentialSource()
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

// TestCookieCredentialSource_ReadSessionIDReturnsRawType verifies ReadSessionID returns RawSessionID type
func TestCookieCredentialSource_ReadSessionIDReturnsRawType(t *testing.T) {
	source := NewCookieCredentialSource()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: base64.URLEncoding.EncodeToString([]byte("test-raw-id")),
	})

	result := source.ReadSessionID(req)

	// Type assertion to ensure return type is RawSessionID
	var _ RawSessionID = result
	assert.Equal(t, RawSessionID("test-raw-id"), result)
}

// TestCookieCredentialSource_WriteSessionAcceptsRawSessionID verifies WriteSession accepts RawSessionID parameter
func TestCookieCredentialSource_WriteSessionAcceptsRawSessionID(t *testing.T) {
	source := NewCookieCredentialSource()
	hashedID := HashedSessionID("test-hashed-id")
	userID := "test-user-id"
	now := time.Now()
	session := NewFakeSession(
		hashedID,
		userID,
		now.Add(30*time.Minute),
		now.Add(24*time.Hour),
		now,
	)

	w := httptest.NewRecorder()
	rawID := RawSessionID("test-raw-id")
	err := source.WriteSession(w, rawID, session)
	require.NoError(t, err)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)

	// Verify cookie contains base64-encoded raw ID
	decoded, err := base64.URLEncoding.DecodeString(cookies[0].Value)
	require.NoError(t, err)
	assert.Equal(t, "test-raw-id", string(decoded))
}

// TestCookieCredentialSource_WriteReadRoundTrip verifies write-then-read round-trip with RawSessionID
func TestCookieCredentialSource_WriteReadRoundTrip(t *testing.T) {
	source := NewCookieCredentialSource()
	hashedID := HashedSessionID("test-hashed-id")
	userID := "test-user-id"
	now := time.Now()
	session := NewFakeSession(
		hashedID,
		userID,
		now.Add(30*time.Minute),
		now.Add(24*time.Hour),
		now,
	)

	// Write session with specific raw ID
	rawID := RawSessionID("my-raw-session")
	w := httptest.NewRecorder()
	err := source.WriteSession(w, rawID, session)
	require.NoError(t, err)

	// Read back the cookie
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookies[0])

	readID := source.ReadSessionID(req)
	assert.Equal(t, rawID, readID)
}

// TestCookieCredentialSource_WriteUsesRawIDNotSessionID verifies WriteSession uses rawID parameter, not session.ID()
func TestCookieCredentialSource_WriteUsesRawIDNotSessionID(t *testing.T) {
	source := NewCookieCredentialSource()

	// Create session with a hashed ID (different from raw ID)
	hashedID := HashedSessionID("hashed-value-abc123")
	userID := "test-user-id"
	now := time.Now()
	session := NewFakeSession(
		hashedID,
		userID,
		now.Add(30*time.Minute),
		now.Add(24*time.Hour),
		now,
	)

	// Write with a different raw ID
	rawID := RawSessionID("raw-value-xyz789")
	w := httptest.NewRecorder()
	err := source.WriteSession(w, rawID, session)
	require.NoError(t, err)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)

	// Decode cookie value
	decoded, err := base64.URLEncoding.DecodeString(cookies[0].Value)
	require.NoError(t, err)

	// Cookie should contain rawID, NOT session.ID()
	assert.Equal(t, "raw-value-xyz789", string(decoded), "Cookie must contain rawID parameter, not session.ID()")
	assert.NotEqual(t, "hashed-value-abc123", string(decoded), "Cookie must NOT contain session.ID()")
}

// TestCookieCredentialSource_EmptyRawSessionID tests edge case of empty RawSessionID
func TestCookieCredentialSource_EmptyRawSessionID(t *testing.T) {
	source := NewCookieCredentialSource()
	hashedID := HashedSessionID("test-hashed-id")
	userID := "test-user-id"
	now := time.Now()
	session := NewFakeSession(
		hashedID,
		userID,
		now.Add(30*time.Minute),
		now.Add(24*time.Hour),
		now,
	)

	w := httptest.NewRecorder()
	emptyRawID := RawSessionID("")
	err := source.WriteSession(w, emptyRawID, session)

	// Should not error with empty raw ID
	require.NoError(t, err)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)

	// Decode cookie value
	decoded, err := base64.URLEncoding.DecodeString(cookies[0].Value)
	require.NoError(t, err)
	assert.Equal(t, "", string(decoded))
}
