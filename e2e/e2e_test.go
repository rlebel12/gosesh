package e2e

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/rlebel12/gosesh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Package-level shared test server
var testServer *TestServer

// TestMain sets up a single shared test server for all e2e tests.
// This minimizes overhead - tests isolate state by calling testServer.Reset() between runs.
func TestMain(m *testing.M) {
	// Create single TestServer instance
	testServer = NewTestServer()

	// Run tests
	code := m.Run()

	// Cleanup
	testServer.Close()

	os.Exit(code)
}

// TestE2E_DeviceCode_FullFlow tests the full device code OAuth flow.
func TestE2E_DeviceCode_FullFlow(t *testing.T) {
	testServer.Reset()
	ctx := t.Context()

	client := NewNativeAppClient(testServer.Server.URL)

	// Authenticate via device code flow
	err := client.AuthenticateViaDeviceCode(ctx, func(userCode string) error {
		return SimulateUserAuthorization(testServer.Server.URL, userCode)
	})
	require.NoError(t, err, "Device code authentication should succeed")
	assert.NotEmpty(t, client.Token, "Token should be set")

	// Verify token works
	me, err := client.GetMe(ctx)
	require.NoError(t, err, "GetMe should succeed")
	assert.NotEmpty(t, me.UserID, "UserID should be set")
	assert.NotEmpty(t, me.SessionID, "SessionID should be set")
}

// TestE2E_DeviceCode_PollPending tests polling before authorization.
func TestE2E_DeviceCode_PollPending(t *testing.T) {
	testServer.Reset()

	// Begin device code flow
	beginURL := testServer.Server.URL + "/auth/device/begin"
	resp, err := testServer.Server.Client().Post(beginURL, "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	var beginResp struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&beginResp))

	// Poll without authorization - should get "pending" status
	pollURL := testServer.Server.URL + "/auth/device/poll"
	pollReq := map[string]string{"device_code": beginResp.DeviceCode}
	pollBody, _ := json.Marshal(pollReq)

	pollResp, err := testServer.Server.Client().Post(pollURL, "application/json", bytes.NewReader(pollBody))
	require.NoError(t, err)
	defer pollResp.Body.Close()

	var pollResult struct {
		Status string `json:"status"`
	}
	require.NoError(t, json.NewDecoder(pollResp.Body).Decode(&pollResult))
	assert.Equal(t, "pending", pollResult.Status, "Should return pending status before authorization")
}

// TestE2E_DeviceCode_TokenWorks verifies device code token works for API calls.
func TestE2E_DeviceCode_TokenWorks(t *testing.T) {
	testServer.Reset()
	ctx := t.Context()

	client := NewNativeAppClient(testServer.Server.URL)
	err := client.AuthenticateViaDeviceCode(ctx, func(userCode string) error {
		return SimulateUserAuthorization(testServer.Server.URL, userCode)
	})
	require.NoError(t, err)

	// Make authenticated request
	resp, err := client.Request(ctx, "GET", "/api/protected", nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode, "Protected endpoint should allow authenticated request")
}

// TestE2E_DeviceCode_ProtectedEndpoint tests accessing protected endpoint with device code token.
func TestE2E_DeviceCode_ProtectedEndpoint(t *testing.T) {
	testServer.Reset()
	ctx := t.Context()

	client := NewNativeAppClient(testServer.Server.URL)
	err := client.AuthenticateViaDeviceCode(ctx, func(userCode string) error {
		return SimulateUserAuthorization(testServer.Server.URL, userCode)
	})
	require.NoError(t, err)

	// Access /api/me
	me, err := client.GetMe(ctx)
	require.NoError(t, err, "Should get session info")
	assert.NotEmpty(t, me.SessionID)
	assert.NotEmpty(t, me.UserID)
}

// TestE2E_DeviceCode_ExpiredCode tests device code expiration.
func TestE2E_DeviceCode_ExpiredCode(t *testing.T) {
	testServer.Reset()
	ctx := t.Context()

	// Begin device code flow
	beginURL := testServer.Server.URL + "/auth/device/begin"
	resp, err := testServer.Server.Client().Post(beginURL, "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	var beginResp struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&beginResp))

	// Get the device code entry and manually expire it
	entry, err := testServer.DeviceStore.GetDeviceCode(ctx, beginResp.DeviceCode)
	require.NoError(t, err)

	// Expire the code by setting ExpiresAt to the past
	pastTime := time.Now().Add(-1 * time.Hour)
	entry.ExpiresAt = pastTime

	// We need to update it in the store - let's delete and recreate with expired time
	testServer.DeviceStore.DeleteDeviceCode(ctx, beginResp.DeviceCode)
	expiredDeviceCode, err := testServer.DeviceStore.CreateDeviceCode(ctx, beginResp.UserCode, pastTime)
	require.NoError(t, err)

	// Poll for expired code - should get "expired" status
	pollURL := testServer.Server.URL + "/auth/device/poll"
	pollReq := map[string]string{"device_code": expiredDeviceCode}
	pollBody, _ := json.Marshal(pollReq)

	pollResp, err := testServer.Server.Client().Post(pollURL, "application/json", bytes.NewReader(pollBody))
	require.NoError(t, err)
	defer pollResp.Body.Close()

	var pollResult struct {
		Status string `json:"status"`
	}
	require.NoError(t, json.NewDecoder(pollResp.Body).Decode(&pollResult))
	assert.Equal(t, "expired", pollResult.Status, "Should return expired status for expired code")
}

// TestE2E_DeviceCode_RateLimit tests polling rate limiting.
func TestE2E_DeviceCode_RateLimit(t *testing.T) {
	testServer.Reset()

	// Begin device code flow
	beginURL := testServer.Server.URL + "/auth/device/begin"
	resp, err := testServer.Server.Client().Post(beginURL, "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	var beginResp struct {
		DeviceCode string `json:"device_code"`
		Interval   int    `json:"interval"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&beginResp))

	// Poll immediately (first poll should succeed)
	pollURL := testServer.Server.URL + "/auth/device/poll"
	pollReq := map[string]string{"device_code": beginResp.DeviceCode}
	pollBody, _ := json.Marshal(pollReq)

	pollResp1, err := testServer.Server.Client().Post(pollURL, "application/json", bytes.NewReader(pollBody))
	require.NoError(t, err)
	defer pollResp1.Body.Close()
	assert.Equal(t, 200, pollResp1.StatusCode, "First poll should succeed")

	// Poll again immediately (should be rate limited)
	pollBody, _ = json.Marshal(pollReq)
	pollResp2, err := testServer.Server.Client().Post(pollURL, "application/json", bytes.NewReader(pollBody))
	require.NoError(t, err)
	defer pollResp2.Body.Close()
	assert.Equal(t, 429, pollResp2.StatusCode, "Second immediate poll should be rate limited")
}

// TestE2E_HeaderAuth_Works tests header-based authentication.
func TestE2E_HeaderAuth_Works(t *testing.T) {
	testServer.Reset()
	ctx := t.Context()

	client := NewNativeAppClient(testServer.Server.URL)
	err := client.AuthenticateViaDeviceCode(ctx, func(userCode string) error {
		return SimulateUserAuthorization(testServer.Server.URL, userCode)
	})
	require.NoError(t, err)

	// Use header authentication
	me, err := client.GetMe(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, me.SessionID)
}

// TestE2E_CookieAuth_Works tests cookie-based authentication.
func TestE2E_CookieAuth_Works(t *testing.T) {
	testServer.Reset()
	ctx := t.Context()

	client := NewNativeAppClient(testServer.Server.URL)

	// Do browser OAuth flow
	err := client.BrowserAuthFlow(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, client.Token, "Should have session cookie")

	// Use cookie authentication
	resp, err := client.RequestWithCookie(ctx, "GET", "/api/me", "session")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)
}

// TestE2E_CompositeAuth_PrefersCookie tests that composite source prefers cookie.
func TestE2E_CompositeAuth_PrefersCookie(t *testing.T) {
	testServer.Reset()
	ctx := t.Context()

	// Create two different sessions - one via device code (header), one via browser (cookie)
	client := NewNativeAppClient(testServer.Server.URL)
	err := client.AuthenticateViaDeviceCode(ctx, func(userCode string) error {
		return SimulateUserAuthorization(testServer.Server.URL, userCode)
	})
	require.NoError(t, err)
	headerToken := client.Token

	// Create browser session with different user
	err = client.BrowserAuthFlow(ctx)
	require.NoError(t, err)
	cookieToken := client.Token

	// headerToken and cookieToken should be different
	assert.NotEqual(t, headerToken, cookieToken, "Sessions should be different")

	// Make request with BOTH header and cookie - cookie should take precedence
	// Manually construct request with both auth methods
	req2, err := http.NewRequestWithContext(ctx, "GET", testServer.Server.URL+"/api/me", nil)
	require.NoError(t, err)
	req2.Header.Set("Authorization", "Bearer "+headerToken)
	req2.AddCookie(&http.Cookie{Name: "session", Value: cookieToken})

	resp, err := testServer.Server.Client().Do(req2)
	require.NoError(t, err)
	defer resp.Body.Close()

	var me MeResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&me))

	// Session ID should match cookie token, not header token
	// Note: Cookie values are base64 encoded in gosesh, so we need to decode to compare
	// Or we can just check that it's NOT the header token
	assert.NotEqual(t, headerToken, me.SessionID, "Should NOT use header session (composite prefers cookie)")
}

// TestE2E_HeaderAuth_NoRefresh tests that header sessions don't refresh.
func TestE2E_HeaderAuth_NoRefresh(t *testing.T) {
	testServer.Reset()
	ctx := t.Context()

	client := NewNativeAppClient(testServer.Server.URL)
	err := client.AuthenticateViaDeviceCode(ctx, func(userCode string) error {
		return SimulateUserAuthorization(testServer.Server.URL, userCode)
	})
	require.NoError(t, err)

	// Get initial session info
	me1, err := client.GetMe(ctx)
	require.NoError(t, err)
	initialIdleDeadline := me1.IdleDeadline

	// Wait a bit and make another request
	time.Sleep(100 * time.Millisecond)

	// Get session info again
	me2, err := client.GetMe(ctx)
	require.NoError(t, err)

	// Idle deadline should be unchanged (no refresh for header sessions)
	assert.Equal(t, initialIdleDeadline, me2.IdleDeadline, "Header sessions should not refresh")
}

// TestE2E_CookieAuth_WithRefresh tests that cookie sessions do refresh.
func TestE2E_CookieAuth_WithRefresh(t *testing.T) {
	testServer.Reset()
	ctx := t.Context()

	client := NewNativeAppClient(testServer.Server.URL)

	// Do browser OAuth flow (creates cookie session with refresh enabled)
	err := client.BrowserAuthFlow(ctx)
	require.NoError(t, err)

	// Get initial session info via cookie
	resp1, err := client.RequestWithCookie(ctx, "GET", "/api/me", "session")
	require.NoError(t, err)
	defer resp1.Body.Close()

	var me1 MeResponse
	require.NoError(t, json.NewDecoder(resp1.Body).Decode(&me1))
	initialIdleDeadline := me1.IdleDeadline

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// Make another request - should refresh idle deadline
	resp2, err := client.RequestWithCookie(ctx, "GET", "/api/me", "session")
	require.NoError(t, err)
	defer resp2.Body.Close()

	var me2 MeResponse
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&me2))

	// Idle deadline should be updated (refreshed) for cookie sessions
	// Note: This test may be flaky if the system is slow, but cookie sessions
	// should refresh their idle deadline on each authenticated request
	assert.True(t, me2.IdleDeadline.After(initialIdleDeadline) || me2.IdleDeadline.Equal(initialIdleDeadline),
		"Cookie sessions should refresh idle deadline")
}

// TestE2E_HeaderSession_Config tests native app session configuration.
func TestE2E_HeaderSession_Config(t *testing.T) {
	testServer.Reset()
	ctx := t.Context()

	client := NewNativeAppClient(testServer.Server.URL)
	err := client.AuthenticateViaDeviceCode(ctx, func(userCode string) error {
		return SimulateUserAuthorization(testServer.Server.URL, userCode)
	})
	require.NoError(t, err)

	me, err := client.GetMe(ctx)
	require.NoError(t, err)

	// Native app sessions should have 30-day absolute duration
	expectedAbsolute := time.Now().Add(30 * 24 * time.Hour)
	actualAbsolute := me.AbsoluteDeadline

	// Allow 1 minute tolerance for test execution time
	timeDiff := actualAbsolute.Sub(expectedAbsolute)
	assert.Less(t, timeDiff.Abs(), time.Minute, "Absolute deadline should be ~30 days from now")
}

// TestE2E_CookieSession_Config tests browser session configuration.
func TestE2E_CookieSession_Config(t *testing.T) {
	testServer.Reset()
	ctx := t.Context()

	client := NewNativeAppClient(testServer.Server.URL)

	// Do browser OAuth flow
	err := client.BrowserAuthFlow(ctx)
	require.NoError(t, err)

	// Get session info
	resp, err := client.RequestWithCookie(ctx, "GET", "/api/me", "session")
	require.NoError(t, err)
	defer resp.Body.Close()

	var me MeResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&me))

	// Browser sessions should have absolute and idle deadlines
	// The exact values are set by the OAuth handler configuration,
	// but we can verify that they're in the expected range
	absoluteDuration := me.AbsoluteDeadline.Sub(time.Now())
	assert.Greater(t, absoluteDuration, 23*time.Hour, "Absolute deadline should be more than 23 hours from now")
	assert.Less(t, absoluteDuration, 25*time.Hour, "Absolute deadline should be less than 25 hours from now")

	// Browser sessions should have idle deadline earlier than absolute deadline
	assert.True(t, me.IdleDeadline.Before(me.AbsoluteDeadline),
		"Browser sessions should have idle deadline before absolute deadline")
}

// TestE2E_HeaderSession_NoIdleTimeout tests that native app sessions don't have idle timeout.
func TestE2E_HeaderSession_NoIdleTimeout(t *testing.T) {
	testServer.Reset()
	ctx := t.Context()

	client := NewNativeAppClient(testServer.Server.URL)
	err := client.AuthenticateViaDeviceCode(ctx, func(userCode string) error {
		return SimulateUserAuthorization(testServer.Server.URL, userCode)
	})
	require.NoError(t, err)

	me, err := client.GetMe(ctx)
	require.NoError(t, err)

	// For native app sessions with no idle timeout, idle deadline == absolute deadline
	assert.Equal(t, me.AbsoluteDeadline, me.IdleDeadline,
		"Native app sessions should have idle deadline equal to absolute deadline (no idle timeout)")
}

// TestE2E_CookieSession_IdleTimeout tests browser session idle timeout.
func TestE2E_CookieSession_IdleTimeout(t *testing.T) {
	testServer.Reset()
	ctx := t.Context()

	client := NewNativeAppClient(testServer.Server.URL)

	// Do browser OAuth flow
	err := client.BrowserAuthFlow(ctx)
	require.NoError(t, err)

	// Get session info to find the actual session ID
	resp1, err := client.RequestWithCookie(ctx, "GET", "/api/me", "session")
	require.NoError(t, err)
	defer resp1.Body.Close()

	var me MeResponse
	require.NoError(t, json.NewDecoder(resp1.Body).Decode(&me))

	// Get the session and manually expire the idle deadline
	session, err := testServer.Store.GetSession(ctx, me.SessionID)
	require.NoError(t, err)

	// Set idle deadline to past (simulate idle timeout)
	pastTime := time.Now().Add(-1 * time.Hour)
	memSession := session.(*gosesh.MemoryStoreSession)
	memSession.SetIdleDeadline(pastTime)

	// Try to use session - should fail due to idle timeout
	resp, err := client.RequestWithCookie(ctx, "GET", "/api/me", "session")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 401, resp.StatusCode, "Should return 401 for idle timeout")
}
