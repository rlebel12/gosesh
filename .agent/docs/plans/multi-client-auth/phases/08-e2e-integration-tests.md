# Phase 08: End-to-End Integration Tests

**Depends on:** Phase 06, Phase 07
**Status:** Complete

---

## RED: Write Tests

**Objective:** Create end-to-end integration tests that test full authentication flows with real HTTP server and minimal CLI client

**Files:**

- `e2e_test.go`
- `e2e/cli_client.go` (minimal CLI client for testing)
- `e2e/test_server.go` (test server setup)

**Test Cases - Localhost Callback Flow:**

### Unique: E2E Localhost OAuth Flow

Each test requires distinct setup with FakeOAuthProvider.

| Case Name | Scenario | Expected | Notes |
|-----------|----------|----------|-------|
| `e2e_localhost_full_flow` | CLI initiates, browser completes OAuth | CLI receives valid session token | Full happy path |
| `e2e_localhost_token_works` | Use received token for API call | Authenticated request succeeds | Token validation |
| `e2e_localhost_protected_endpoint` | Access /api/me with token | 200 OK with session data | Full auth chain |
| `e2e_localhost_expired_session` | Wait for expiry, then request | 401 Unauthorized | Expiry works e2e |
| `e2e_localhost_invalid_token` | Use garbage token | 401 Unauthorized | Invalid token handling |

**Test Cases - Device Code Flow:**

### Unique: E2E Device Code Flow

Each test requires distinct state management.

| Case Name | Scenario | Expected | Notes |
|-----------|----------|----------|-------|
| `e2e_device_full_flow` | CLI gets code, user authorizes | CLI receives token via poll | Full happy path |
| `e2e_device_poll_pending` | CLI polls before authorization | `{"status": "pending"}` | Pending state |
| `e2e_device_token_works` | Use received token for API call | Authenticated request succeeds | Token validation |
| `e2e_device_protected_endpoint` | Access /api/me with token | 200 OK with session data | Full auth chain |
| `e2e_device_expired_code` | Wait for expiry, then poll | `{"status": "expired"}` | Expiry works e2e |
| `e2e_device_rate_limit` | Poll faster than interval | 429 Too Many Requests | Rate limiting works |

**Test Cases - Header vs Cookie Auth:**

### Parameterized: Credential Source E2E Verification

| Case Name | Credential Source | Request Type | Expected | Notes |
|-----------|-------------------|--------------|----------|-------|
| `e2e_header_auth_works` | Header | Bearer token | Authenticated | Header source works |
| `e2e_cookie_auth_works` | Cookie | Session cookie | Authenticated | Cookie source works |
| `e2e_composite_prefers_cookie` | Composite | Both present | Uses cookie session | Priority works |

### Parameterized: Refresh Behavior E2E

| Case Name | Source Type | RefreshEnabled | Expected After Request | Notes |
|-----------|-------------|----------------|------------------------|-------|
| `e2e_header_no_refresh` | Header | `false` | IdleDeadline unchanged | No refresh |
| `e2e_cookie_with_refresh` | Cookie | `true` | IdleDeadline extended | Refresh works |

**Test Cases - Session Behavior:**

### Parameterized: Session Duration by Flow

| Case Name | Auth Flow | Expected AbsoluteDuration | Expected IdleDuration | Notes |
|-----------|-----------|---------------------------|----------------------|-------|
| `e2e_header_session_config` | CLI (localhost or device) | 30 days | None (0) | CLI config |
| `e2e_cookie_session_config` | Browser OAuth | 24 hours | 30 minutes | Browser config |

### Unique: Idle Timeout Behavior E2E

| Case Name | Scenario | Expected | Notes |
|-----------|----------|----------|-------|
| `e2e_header_no_idle_timeout` | CLI session, wait past "normal" idle period | Session still valid | No idle for CLI |
| `e2e_cookie_idle_timeout` | Cookie session, wait past idle period | Session expired, 401 | Idle works for browser |

**Assertions:**

- Full OAuth2 flow completes without manual intervention (using fake OAuth provider)
- Session tokens are valid and work for authenticated requests
- Session timeouts are correctly applied based on credential source
- Both localhost callback and device code flows work end-to-end

**Edge Cases:**

- Network interruption during OAuth flow
- Concurrent authentication requests
- Session created by one source, accessed via another (if using composite)

### Gate: RED

- [x] Test files created with all enumerated test cases
- [x] All tests FAIL (implementation does not exist yet)
- [x] Test coverage includes happy path and all edge cases

---

## GREEN: Implement

**Objective:** Implement test infrastructure and end-to-end tests

**Files:**

- `e2e_test.go`
- `e2e/cli_client.go`
- `e2e/test_server.go`
- `e2e/fake_oauth_provider.go`

**Implementation Guidance:**

**Note:** Use a single shared test server started via `TestMain` to minimize overhead. Tests isolate state by clearing sessions between runs, not by creating new servers.

```go
// e2e/test_server.go

// TestServer wraps a real HTTP server with gosesh for e2e testing
type TestServer struct {
    Server       *httptest.Server
    Gosesh       *gosesh.Gosesh
    Store        *gosesh.MemoryStore      // Concrete type for Reset()
    DeviceStore  *MemoryDeviceCodeStore   // Concrete type for Reset()
    OAuthServer  *FakeOAuthProvider
}

func NewTestServer(opts ...TestServerOption) *TestServer {
    // Implementation approach:
    // 1. Create MemoryStore for sessions
    // 2. Create MemoryDeviceCodeStore for device codes
    // 3. Create FakeOAuthProvider
    // 4. Configure Gosesh with:
    //    - CompositeCredentialSource (cookie + header)
    //    - Test OAuth config pointing to fake provider
    // 5. Set up routes:
    //    - /auth/login (browser OAuth begin)
    //    - /auth/callback (browser OAuth callback)
    //    - /auth/cli/begin (CLI OAuth begin)
    //    - /auth/cli/callback (CLI OAuth callback)
    //    - /auth/device/begin (device code begin)
    //    - /auth/device/poll (device code poll)
    //    - /auth/device (device authorization page)
    //    - /auth/device/callback (device OAuth callback)
    //    - /api/me (protected endpoint returning session info)
    // 6. Start httptest.Server
    // 7. Return TestServer
}

func (ts *TestServer) Reset() {
    // Implementation approach:
    // 1. Clear all sessions from Store
    // 2. Clear all device codes from DeviceStore
    // 3. Reset FakeOAuthProvider state if needed
    //
    // Called between tests to isolate state without restarting server
}

func (ts *TestServer) Close() {
    ts.Server.Close()
    ts.OAuthServer.Close()
}
```

```go
// e2e/cli_client.go

// CLIClient simulates a CLI application authenticating with the server
type CLIClient struct {
    BaseURL     string
    Token       string // stored session token
    HTTPClient  *http.Client
}

func NewCLIClient(baseURL string) *CLIClient { ... }

// AuthenticateViaLocalhost performs localhost callback flow
func (c *CLIClient) AuthenticateViaLocalhost(ctx context.Context) error {
    // Implementation approach:
    // 1. Start local HTTP server on random port
    // 2. Build callback URL: http://localhost:<port>/callback
    // 3. GET /auth/cli/begin?callback=<url>
    // 4. Follow redirect to OAuth provider (FakeOAuthProvider auto-approves)
    // 5. Wait for callback on local server
    // 6. Extract token from query param
    // 7. Store token in c.Token
    // 8. Close local server
}

// AuthenticateViaDeviceCode performs device code flow
func (c *CLIClient) AuthenticateViaDeviceCode(ctx context.Context, authorizeFunc func(userCode string) error) error {
    // Implementation approach:
    // 1. POST /auth/device/begin
    // 2. Parse response for device_code, user_code
    // 3. Call authorizeFunc(userCode) - simulates user authorizing in browser
    // 4. Poll /auth/device/poll with device_code
    // 5. When status="complete", extract session_id
    // 6. Store token in c.Token
}

// Request makes an authenticated request using Bearer token
func (c *CLIClient) Request(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
    // Implementation approach:
    // 1. Create request
    // 2. Set Authorization: Bearer <c.Token>
    // 3. Execute request
    // 4. Return response
}

// GetMe calls /api/me to verify authentication
func (c *CLIClient) GetMe(ctx context.Context) (*MeResponse, error) {
    // Implementation approach:
    // 1. Call Request(ctx, "GET", "/api/me", nil)
    // 2. Parse JSON response
    // 3. Return session info
}
```

```go
// e2e/fake_oauth_provider.go

// FakeOAuthProvider simulates an OAuth2 provider for testing
type FakeOAuthProvider struct {
    Server       *httptest.Server
    Config       *oauth2.Config
    AutoApprove  bool // automatically approve authorization
}

func NewFakeOAuthProvider() *FakeOAuthProvider {
    // Implementation approach:
    // 1. Create httptest.Server with routes:
    //    - GET /authorize (authorization endpoint)
    //    - POST /token (token exchange endpoint)
    //    - GET /userinfo (user info endpoint)
    // 2. If AutoApprove, /authorize immediately redirects with code
    // 3. /token returns access token for valid code
    // 4. /userinfo returns fake user data
    // 5. Return provider with oauth2.Config pointing to server
}

func (p *FakeOAuthProvider) OAuthConfig() *oauth2.Config {
    return p.Config
}

func (p *FakeOAuthProvider) Close() {
    p.Server.Close()
}
```

```go
// e2e_test.go

// Package-level shared test server
var testServer *e2e.TestServer

func TestMain(m *testing.M) {
    // Implementation approach:
    // 1. Create single TestServer instance
    // 2. Store in package-level var
    // 3. Run tests
    // 4. Close server and exit
    testServer = e2e.NewTestServer()
    code := m.Run()
    testServer.Close()
    os.Exit(code)
}

func TestE2E_LocalhostCallback_FullFlow(t *testing.T) {
    // Implementation approach:
    // 1. Reset server state (clear sessions, device codes)
    // 2. Create CLIClient pointing to shared server
    // 3. Call cli.AuthenticateViaLocalhost(ctx)
    // 4. Assert cli.Token is non-empty
    // 5. Call cli.GetMe(ctx)
    // 6. Assert response contains valid session info
    testServer.Reset()
    cli := e2e.NewCLIClient(testServer.Server.URL)
    // ... test logic
}

func TestE2E_DeviceCode_FullFlow(t *testing.T) {
    // Implementation approach:
    // 1. Reset server state
    // 2. Create CLIClient pointing to shared server
    // 3. Call cli.AuthenticateViaDeviceCode(ctx, func(userCode string) error {
    //        // Simulate user authorizing via browser
    //        return simulateUserAuthorization(testServer.Server.URL, userCode)
    //    })
    // 4. Assert cli.Token is non-empty
    // 5. Call cli.GetMe(ctx)
    // 6. Assert response contains valid session info
    testServer.Reset()
    cli := e2e.NewCLIClient(testServer.Server.URL)
    // ... test logic
}

func TestE2E_HeaderAuth_ProtectedEndpoint(t *testing.T) {
    // Implementation approach:
    // 1. Reset server state
    // 2. Create CLIClient and authenticate
    // 3. Make request to protected endpoint
    // 4. Assert 200 OK
    // 5. Assert response contains session data
    testServer.Reset()
    // ... test logic
}

func TestE2E_SessionExpiry(t *testing.T) {
    // Implementation approach:
    // 1. Reset server state
    // 2. Authenticate CLI
    // 3. Directly manipulate session in Store to set expired deadline
    //    (avoids waiting - Store is accessible via testServer.Store)
    // 4. Make request with token
    // 5. Assert 401 Unauthorized
    testServer.Reset()
    // ... test logic
}

// Helper function
func simulateUserAuthorization(serverURL, userCode string) error {
    // POST to /auth/device with user_code
    // Follow OAuth redirects (FakeOAuthProvider auto-approves)
    // Return nil on success
}
```

### Gate: GREEN

- [x] All tests from RED phase now PASS
- [x] Test command: `go test -v -run TestE2E`
- [x] All e2e tests pass with real HTTP traffic
- [x] Implementation follows pseudocode logic flow

---

## REFACTOR: Quality

**Focus:** Code quality, not new functionality.

- Ensure test cleanup is thorough (no leaked goroutines or servers)
- Add test timeouts to prevent hanging
- Consider table-driven tests for similar test cases
- Document how to run e2e tests separately
- **Do not use `t.Parallel()`** - tests share server state and rely on `Reset()` between runs

### Gate: REFACTOR

- [x] Commit succeeds (pre-commit handles formatting/linting)
- [x] All tests complete in reasonable time (< 20 seconds)
- [x] No resource leaks (verify with `go test -race`)

---

## Phase Complete

When all gates pass:

1. Update this file's status to **Complete**
2. Update index.md status table
3. Implementation complete - proceed with cleanup

---

**Previous:** [Phase 06](06-localhost-callback.md) and [Phase 07](07-device-code-flow.md)
**Next:** Final phase - implementation complete
