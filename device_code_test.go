package gosesh

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
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
					rawSessionID := RawSessionID("session-123")
					_ = store.CompleteDeviceCode(ctx, deviceCode, rawSessionID)
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
			deviceCode, err := store.CreateDeviceCode(ctx, "VALID123", time.Now().Add(15*time.Minute))
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

			// Should set device code cookie
			cookies := rr.Result().Cookies()
			var deviceCodeCookie *http.Cookie
			for _, c := range cookies {
				if c.Name == "devicecode" {
					deviceCodeCookie = c
					break
				}
			}
			require.NotNil(t, deviceCodeCookie, "device code cookie should be set")

			// Verify cookie contains encoded device code
			decodedValue, err := base64.URLEncoding.DecodeString(deviceCodeCookie.Value)
			require.NoError(t, err)
			assert.Equal(t, deviceCode, string(decodedValue))
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

		t.Run("authorize_submit_valid_custom_cookie_name", func(t *testing.T) {
			store := NewMemoryDeviceCodeStore()
			ctx := context.Background()

			// Create a device code entry
			deviceCode, err := store.CreateDeviceCode(ctx, "CUST1234", time.Now().Add(15*time.Minute))
			require.NoError(t, err)

			gs := New(NewMemoryStore(), WithDeviceCodeCookieName("custom_device"))
			handler := gs.DeviceCodeAuthorize(store)

			form := url.Values{}
			form.Set("user_code", "CUST1234")
			req := httptest.NewRequest("POST", "/auth/device", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			// Should set device code cookie with custom name
			cookies := rr.Result().Cookies()
			var deviceCodeCookie *http.Cookie
			for _, c := range cookies {
				if c.Name == "custom_device" {
					deviceCodeCookie = c
					break
				}
			}
			require.NotNil(t, deviceCodeCookie, "custom device code cookie should be set")

			// Verify cookie contains encoded device code
			decodedValue, err := base64.URLEncoding.DecodeString(deviceCodeCookie.Value)
			require.NoError(t, err)
			assert.Equal(t, deviceCode, string(decodedValue))
		})

		t.Run("authorize_callback", func(t *testing.T) {
			// This test is complex because it requires mocking the OAuth2 token exchange
			// For now, we'll skip it and rely on integration tests
			// The handler is tested indirectly through the other tests
			t.Skip("Callback requires complex OAuth2 mocking, covered by integration tests")
		})
	})
}

func TestDeviceCodeCookie(t *testing.T) {
	t.Run("cookie properties", func(t *testing.T) {
		fixedTime := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
		gs := New(NewMemoryStore(), WithNow(func() time.Time { return fixedTime }))

		expireAt := fixedTime.Add(5 * time.Minute)
		cookie := gs.deviceCodeCookie("test-device-code", expireAt)

		assert.Equal(t, "devicecode", cookie.Name)
		assert.Equal(t, base64.URLEncoding.EncodeToString([]byte("test-device-code")), cookie.Value)
		assert.Equal(t, "/", cookie.Path)
		assert.Equal(t, "localhost", cookie.Domain)
		assert.Equal(t, expireAt, cookie.Expires)
		assert.False(t, cookie.Secure, "insecure by default")
		assert.True(t, cookie.HttpOnly)
		assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
	})

	t.Run("secure cookie for https", func(t *testing.T) {
		origin, _ := url.Parse("https://example.com")
		gs := New(NewMemoryStore(), WithOrigin(origin))

		cookie := gs.deviceCodeCookie("test-code", time.Now())

		assert.True(t, cookie.Secure)
		assert.Equal(t, "example.com", cookie.Domain)
	})

	t.Run("custom cookie name", func(t *testing.T) {
		gs := New(NewMemoryStore(), WithDeviceCodeCookieName("my_device_code"))

		cookie := gs.deviceCodeCookie("test-code", time.Now())

		assert.Equal(t, "my_device_code", cookie.Name)
	})

	t.Run("clear cookie has empty value and past expiration", func(t *testing.T) {
		fixedTime := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
		gs := New(NewMemoryStore(), WithNow(func() time.Time { return fixedTime }))

		// To clear a cookie, use empty value and past/current expiration
		clearCookie := gs.deviceCodeCookie("", fixedTime)

		assert.Equal(t, "devicecode", clearCookie.Name)
		assert.Equal(t, base64.URLEncoding.EncodeToString([]byte("")), clearCookie.Value)
		assert.Equal(t, fixedTime, clearCookie.Expires)
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

func TestDeviceCodeAuthorizeCallback(t *testing.T) {
	fixedTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	// Helper: Create OAuth server that returns valid token
	newSuccessOAuthServer := func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/token" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"test-token","token_type":"bearer"}`))
			} else {
				http.Error(w, "not found", http.StatusNotFound)
			}
		}))
	}

	// Helper: Create OAuth server that fails
	newFailingOAuthServer := func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "not found", http.StatusNotFound)
		}))
	}

	// Helper: Create valid device code cookie
	validCookie := func(deviceCode string) *http.Cookie {
		return &http.Cookie{
			Name:  "devicecode",
			Value: base64.URLEncoding.EncodeToString([]byte(deviceCode)),
		}
	}

	// Helper: Success request func
	successRequestFunc := func(_ context.Context, _ string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(`{"id":"user123"}`)), nil
	}

	// Helper: Success unmarshal func
	successUnmarshalFunc := func(_ []byte) (Identifier, error) {
		return StringIdentifier("user123"), nil
	}

	// Helper: Default store setup - creates device code entry, returns device code
	defaultStoreSetup := func(t *testing.T, store *erroringStore, dcStore *erroringDeviceCodeStore) string {
		t.Helper()
		ctx := t.Context()
		deviceCode, err := dcStore.CreateDeviceCode(ctx, "TEST1234", fixedTime.Add(15*time.Minute))
		require.NoError(t, err)
		return deviceCode
	}

	tests := []struct {
		name              string
		giveOAuthServer   func() *httptest.Server
		giveStoreSetup    func(t *testing.T, store *erroringStore, dcStore *erroringDeviceCodeStore) string
		giveRequestFunc   RequestFunc
		giveUnmarshalFunc UnmarshalFunc
		giveCookie        func(deviceCode string) *http.Cookie
		giveOAuthCode     string
		wantStatus        int
		wantBodyContains  string
	}{
		{
			name:              "success",
			giveOAuthServer:   newSuccessOAuthServer,
			giveStoreSetup:    defaultStoreSetup,
			giveRequestFunc:   successRequestFunc,
			giveUnmarshalFunc: successUnmarshalFunc,
			giveCookie:        validCookie,
			giveOAuthCode:     "auth-code",
			wantStatus:        http.StatusOK,
			wantBodyContains:  "Authorization Complete",
		},
		{
			name:              "token_exchange_error",
			giveOAuthServer:   newFailingOAuthServer,
			giveStoreSetup:    defaultStoreSetup,
			giveRequestFunc:   successRequestFunc,
			giveUnmarshalFunc: successUnmarshalFunc,
			giveCookie:        validCookie,
			giveOAuthCode:     "auth-code",
			wantStatus:        http.StatusInternalServerError,
			wantBodyContains:  "exchange token",
		},
		{
			name:            "request_user_error",
			giveOAuthServer: newSuccessOAuthServer,
			giveStoreSetup:  defaultStoreSetup,
			giveRequestFunc: func(_ context.Context, _ string) (io.ReadCloser, error) {
				return nil, errors.New("provider unreachable")
			},
			giveUnmarshalFunc: successUnmarshalFunc,
			giveCookie:        validCookie,
			giveOAuthCode:     "auth-code",
			wantStatus:        http.StatusInternalServerError,
			wantBodyContains:  "get user data",
		},
		{
			name:              "unmarshal_user_error",
			giveOAuthServer:   newSuccessOAuthServer,
			giveStoreSetup:    defaultStoreSetup,
			giveRequestFunc:   successRequestFunc,
			giveUnmarshalFunc: func(_ []byte) (Identifier, error) {
				return nil, errors.New("invalid user data")
			},
			giveCookie:       validCookie,
			giveOAuthCode:    "auth-code",
			wantStatus:       http.StatusInternalServerError,
			wantBodyContains: "get user data",
		},
		{
			name:            "upsert_user_error",
			giveOAuthServer: newSuccessOAuthServer,
			giveStoreSetup: func(t *testing.T, store *erroringStore, dcStore *erroringDeviceCodeStore) string {
				t.Helper()
				store.upsertUserError = true
				return defaultStoreSetup(t, store, dcStore)
			},
			giveRequestFunc:   successRequestFunc,
			giveUnmarshalFunc: successUnmarshalFunc,
			giveCookie:        validCookie,
			giveOAuthCode:     "auth-code",
			wantStatus:        http.StatusInternalServerError,
			wantBodyContains:  "upsert user",
		},
		{
			name:            "create_session_error",
			giveOAuthServer: newSuccessOAuthServer,
			giveStoreSetup: func(t *testing.T, store *erroringStore, dcStore *erroringDeviceCodeStore) string {
				t.Helper()
				store.createSessionError = true
				return defaultStoreSetup(t, store, dcStore)
			},
			giveRequestFunc:   successRequestFunc,
			giveUnmarshalFunc: successUnmarshalFunc,
			giveCookie:        validCookie,
			giveOAuthCode:     "auth-code",
			wantStatus:        http.StatusInternalServerError,
			wantBodyContains:  "create session",
		},
		{
			name:              "missing_device_code_cookie",
			giveOAuthServer:   newSuccessOAuthServer,
			giveStoreSetup:    defaultStoreSetup,
			giveRequestFunc:   successRequestFunc,
			giveUnmarshalFunc: successUnmarshalFunc,
			giveCookie:        nil,
			giveOAuthCode:     "auth-code",
			wantStatus:        http.StatusBadRequest,
			wantBodyContains:  "missing device code",
		},
		{
			name:            "invalid_device_code_cookie",
			giveOAuthServer: newSuccessOAuthServer,
			giveStoreSetup:  defaultStoreSetup,
			giveRequestFunc: successRequestFunc,
			giveUnmarshalFunc: successUnmarshalFunc,
			giveCookie: func(deviceCode string) *http.Cookie {
				return &http.Cookie{
					Name:  "devicecode",
					Value: "not-valid-base64!!!",
				}
			},
			giveOAuthCode:    "auth-code",
			wantStatus:       http.StatusBadRequest,
			wantBodyContains: "invalid device code",
		},
		{
			name:            "complete_device_code_error",
			giveOAuthServer: newSuccessOAuthServer,
			giveStoreSetup: func(t *testing.T, store *erroringStore, dcStore *erroringDeviceCodeStore) string {
				t.Helper()
				dcStore.completeDeviceCodeError = true
				return defaultStoreSetup(t, store, dcStore)
			},
			giveRequestFunc:   successRequestFunc,
			giveUnmarshalFunc: successUnmarshalFunc,
			giveCookie:        validCookie,
			giveOAuthCode:     "auth-code",
			wantStatus:        http.StatusInternalServerError,
			wantBodyContains:  "complete device code",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()

			// Create OAuth server
			oauthServer := tc.giveOAuthServer()
			t.Cleanup(oauthServer.Close)

			// Create stores
			memStore := NewMemoryStore()
			store := &erroringStore{Storer: memStore}
			memDCStore := NewMemoryDeviceCodeStore()
			dcStore := &erroringDeviceCodeStore{DeviceCodeStore: memDCStore}

			// Setup stores and get device code
			deviceCode := tc.giveStoreSetup(t, store, dcStore)

			// Create Gosesh instance
			gs := New(store, WithNow(func() time.Time { return fixedTime }))

			// Build oauth2.Config pointing to test server
			oauthCfg := &oauth2.Config{
				ClientID:     "client_id",
				ClientSecret: "client_secret",
				RedirectURL:  oauthServer.URL + "/callback",
				Endpoint: oauth2.Endpoint{
					TokenURL: oauthServer.URL + "/token",
				},
			}

			// Create handler
			handler := gs.DeviceCodeAuthorizeCallback(dcStore, oauthCfg, tc.giveRequestFunc, tc.giveUnmarshalFunc)

			// Create request
			req := httptest.NewRequest("GET", "/callback?code="+tc.giveOAuthCode, nil)
			req = req.WithContext(ctx)

			// Add cookie if specified
			if tc.giveCookie != nil {
				req.AddCookie(tc.giveCookie(deviceCode))
			}

			// Execute handler
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			// Assert response
			assert.Equal(t, tc.wantStatus, rr.Code, "status code mismatch")
			assert.Contains(t, rr.Body.String(), tc.wantBodyContains, "body should contain expected substring")
		})
	}
}
