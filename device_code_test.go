package gosesh

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeviceCodeBegin(t *testing.T) {
	t.Run("DeviceCodeBegin Response Structure", func(t *testing.T) {
		t.Run("begin_returns_codes", func(t *testing.T) {
			store := NewMemoryDeviceCodeStore()
			gs := New(NewMemoryStore())
			handler := gs.DeviceCodeBegin(store)

			req := httptest.NewRequest("POST", "/auth/device/begin", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			require.Equal(t, http.StatusOK, rr.Code)

			var resp DeviceCodeBeginResponse
			err := json.NewDecoder(rr.Body).Decode(&resp)
			require.NoError(t, err)

			assert.NotEmpty(t, resp.DeviceCode, "device_code should be present")
			assert.NotEmpty(t, resp.UserCode, "user_code should be present")
			assert.NotEmpty(t, resp.VerificationURI, "verification_uri should be present")
			assert.Greater(t, resp.ExpiresIn, 0, "expires_in should be positive")
			assert.Greater(t, resp.Interval, 0, "interval should be positive")
		})

		t.Run("begin_user_code_format", func(t *testing.T) {
			store := NewMemoryDeviceCodeStore()
			gs := New(NewMemoryStore())
			handler := gs.DeviceCodeBegin(store)

			req := httptest.NewRequest("POST", "/auth/device/begin", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			require.Equal(t, http.StatusOK, rr.Code)

			var resp DeviceCodeBeginResponse
			err := json.NewDecoder(rr.Body).Decode(&resp)
			require.NoError(t, err)

			// Check format: XXXX-XXXX
			assert.Len(t, resp.UserCode, 9, "user_code should be 9 chars (XXXX-XXXX)")
			assert.Equal(t, "-", string(resp.UserCode[4]), "5th character should be hyphen")

			// Check safe alphabet (no vowels, no 0/1/O/I)
			safeChars := "BCDFGHJKLMNPQRSTVWXYZ23456789"
			for i, ch := range resp.UserCode {
				if i == 4 {
					continue // Skip hyphen
				}
				assert.Contains(t, safeChars, string(ch), "character should be from safe alphabet")
			}
		})

		t.Run("begin_expires_in", func(t *testing.T) {
			store := NewMemoryDeviceCodeStore()
			gs := New(NewMemoryStore())
			handler := gs.DeviceCodeBegin(store)

			req := httptest.NewRequest("POST", "/auth/device/begin", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			require.Equal(t, http.StatusOK, rr.Code)

			var resp DeviceCodeBeginResponse
			err := json.NewDecoder(rr.Body).Decode(&resp)
			require.NoError(t, err)

			// 5-15 minute range (300-900 seconds)
			assert.GreaterOrEqual(t, resp.ExpiresIn, 300, "expires_in should be >= 300 seconds")
			assert.LessOrEqual(t, resp.ExpiresIn, 900, "expires_in should be <= 900 seconds")
		})

		t.Run("begin_interval", func(t *testing.T) {
			store := NewMemoryDeviceCodeStore()
			gs := New(NewMemoryStore())
			handler := gs.DeviceCodeBegin(store)

			req := httptest.NewRequest("POST", "/auth/device/begin", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			require.Equal(t, http.StatusOK, rr.Code)

			var resp DeviceCodeBeginResponse
			err := json.NewDecoder(rr.Body).Decode(&resp)
			require.NoError(t, err)

			assert.Equal(t, 5, resp.Interval, "interval should be 5 seconds")
		})
	})
}

func TestDeviceCodePoll(t *testing.T) {
	t.Run("DeviceCodePoll Status Cases", func(t *testing.T) {
		tests := []struct {
			name           string
			setupStore     func(store DeviceCodeStore) string
			expectedStatus string
			hasSessionID   bool
		}{
			{
				name: "poll_pending",
				setupStore: func(store DeviceCodeStore) string {
					ctx := context.Background()
					deviceCode, _ := store.CreateDeviceCode(ctx, "TEST1234", time.Now().Add(15*time.Minute))
					return deviceCode
				},
				expectedStatus: "pending",
				hasSessionID:   false,
			},
			{
				name: "poll_complete",
				setupStore: func(store DeviceCodeStore) string {
					ctx := context.Background()
					deviceCode, _ := store.CreateDeviceCode(ctx, "TEST5678", time.Now().Add(15*time.Minute))
					sessionID := StringIdentifier("session-123")
					_ = store.CompleteDeviceCode(ctx, deviceCode, sessionID)
					return deviceCode
				},
				expectedStatus: "complete",
				hasSessionID:   true,
			},
			{
				name: "poll_expired",
				setupStore: func(store DeviceCodeStore) string {
					ctx := context.Background()
					deviceCode, _ := store.CreateDeviceCode(ctx, "TESTEXP1", time.Now().Add(-1*time.Minute))
					return deviceCode
				},
				expectedStatus: "expired",
				hasSessionID:   false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				store := NewMemoryDeviceCodeStore()
				deviceCode := tt.setupStore(store)

				gs := New(NewMemoryStore())
				handler := gs.DeviceCodePoll(store)

				body := fmt.Sprintf(`{"device_code": "%s"}`, deviceCode)
				req := httptest.NewRequest("POST", "/auth/device/poll", bytes.NewBufferString(body))
				req.Header.Set("Content-Type", "application/json")
				rr := httptest.NewRecorder()

				handler.ServeHTTP(rr, req)

				require.Equal(t, http.StatusOK, rr.Code)

				var resp DeviceCodePollResponse
				err := json.NewDecoder(rr.Body).Decode(&resp)
				require.NoError(t, err)

				assert.Equal(t, tt.expectedStatus, resp.Status)
				if tt.hasSessionID {
					assert.NotEmpty(t, resp.SessionID)
				} else {
					assert.Empty(t, resp.SessionID)
				}
			})
		}
	})

	t.Run("DeviceCodePoll Error Cases", func(t *testing.T) {
		tests := []struct {
			name           string
			setupRequest   func() *http.Request
			expectedStatus int
		}{
			{
				name: "poll_invalid_code",
				setupRequest: func() *http.Request {
					body := `{"device_code": "unknown-device-code"}`
					req := httptest.NewRequest("POST", "/auth/device/poll", bytes.NewBufferString(body))
					req.Header.Set("Content-Type", "application/json")
					return req
				},
				expectedStatus: http.StatusBadRequest,
			},
			{
				name: "poll_missing_code",
				setupRequest: func() *http.Request {
					body := `{}`
					req := httptest.NewRequest("POST", "/auth/device/poll", bytes.NewBufferString(body))
					req.Header.Set("Content-Type", "application/json")
					return req
				},
				expectedStatus: http.StatusBadRequest,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				store := NewMemoryDeviceCodeStore()
				gs := New(NewMemoryStore())
				handler := gs.DeviceCodePoll(store)

				req := tt.setupRequest()
				rr := httptest.NewRecorder()

				handler.ServeHTTP(rr, req)

				assert.Equal(t, tt.expectedStatus, rr.Code)
			})
		}
	})

	t.Run("poll_rate_limit", func(t *testing.T) {
		store := NewMemoryDeviceCodeStore()
		ctx := context.Background()
		deviceCode, err := store.CreateDeviceCode(ctx, "RATELIM1", time.Now().Add(15*time.Minute))
		require.NoError(t, err)

		// First poll should succeed
		err = store.UpdateLastPoll(ctx, deviceCode, time.Now())
		require.NoError(t, err)

		gs := New(NewMemoryStore())
		handler := gs.DeviceCodePoll(store)

		// Second poll within 5 seconds should be rate limited
		body := fmt.Sprintf(`{"device_code": "%s"}`, deviceCode)
		req := httptest.NewRequest("POST", "/auth/device/poll", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusTooManyRequests, rr.Code)
	})
}

func TestDeviceCodeAuthorize(t *testing.T) {
	t.Run("DeviceCodeAuthorize Flow", func(t *testing.T) {
		t.Run("authorize_page_get", func(t *testing.T) {
			store := NewMemoryDeviceCodeStore()
			gs := New(NewMemoryStore())
			handler := gs.DeviceCodeAuthorize(store)

			req := httptest.NewRequest("GET", "/auth/device", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code)
			assert.Contains(t, rr.Header().Get("Content-Type"), "text/html")

			body := rr.Body.String()
			assert.Contains(t, body, "form", "should contain form")
		})

		t.Run("authorize_submit_valid", func(t *testing.T) {
			store := NewMemoryDeviceCodeStore()
			ctx := context.Background()

			// Create a device code entry
			_, err := store.CreateDeviceCode(ctx, "VALID123", time.Now().Add(15*time.Minute))
			require.NoError(t, err)

			gs := New(NewMemoryStore())
			handler := gs.DeviceCodeAuthorize(store)

			form := url.Values{}
			form.Set("user_code", "VALID123")
			req := httptest.NewRequest("POST", "/auth/device", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			// Should redirect to OAuth provider
			assert.Equal(t, http.StatusFound, rr.Code)
			location := rr.Header().Get("Location")
			assert.NotEmpty(t, location)
		})

		t.Run("authorize_submit_invalid", func(t *testing.T) {
			store := NewMemoryDeviceCodeStore()
			gs := New(NewMemoryStore())
			handler := gs.DeviceCodeAuthorize(store)

			form := url.Values{}
			form.Set("user_code", "INVALID1")
			req := httptest.NewRequest("POST", "/auth/device", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code)
			body := rr.Body.String()
			assert.Contains(t, strings.ToLower(body), "invalid", "should show error message")
		})

		t.Run("authorize_callback", func(t *testing.T) {
			// This test is complex because it requires mocking the OAuth2 token exchange
			// For now, we'll skip it and rely on integration tests
			// The handler is tested indirectly through the other tests
			t.Skip("Callback requires complex OAuth2 mocking, covered by integration tests")
		})
	})
}

func TestGenerateUserCode(t *testing.T) {
	t.Run("generates unique codes", func(t *testing.T) {
		store := NewMemoryDeviceCodeStore()
		ctx := context.Background()

		codes := make(map[string]bool)
		for i := 0; i < 100; i++ {
			code, err := generateUserCode(store, ctx)
			require.NoError(t, err)
			assert.NotContains(t, codes, code, "code should be unique")
			codes[code] = true

			// Verify format
			assert.Len(t, code, 9, "code should be 9 chars")
			assert.Equal(t, "-", string(code[4]), "5th char should be hyphen")
		}
	})

	t.Run("handles collision", func(t *testing.T) {
		store := NewMemoryDeviceCodeStore()
		ctx := context.Background()

		// Create an entry with a user code
		existingCode := "BCDF-GHJK"
		_, err := store.CreateDeviceCode(ctx, existingCode, time.Now().Add(15*time.Minute))
		require.NoError(t, err)

		// Generate a new code - should avoid collision
		newCode, err := generateUserCode(store, ctx)
		require.NoError(t, err)
		assert.NotEqual(t, existingCode, newCode, "should generate different code")
	})

	t.Run("uses safe alphabet", func(t *testing.T) {
		store := NewMemoryDeviceCodeStore()
		ctx := context.Background()

		safeChars := "BCDFGHJKLMNPQRSTVWXYZ23456789"
		for i := 0; i < 50; i++ {
			code, err := generateUserCode(store, ctx)
			require.NoError(t, err)

			for j, ch := range code {
				if j == 4 {
					continue // Skip hyphen
				}
				assert.Contains(t, safeChars, string(ch), "should only use safe alphabet")
			}
		}
	})
}
