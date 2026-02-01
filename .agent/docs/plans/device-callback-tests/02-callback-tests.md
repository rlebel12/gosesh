# Phase 02: DeviceCodeAuthorizeCallback Tests

**Depends on:** Phase 01
**Phase Type:** Standard
**Status:** Pending

---

## RED: Write Tests

**Objective:** Create comprehensive table-driven tests for DeviceCodeAuthorizeCallback handler

**Files:**

- `device_code_test.go`

**Test Cases:**

Table-driven tests covering all code paths in `DeviceCodeAuthorizeCallback`:

| Case Name | Setup | Expected Status | Expected Body Contains | Notes |
|-----------|-------|-----------------|------------------------|-------|
| `success` | Create device code, set valid cookie, mock OAuth success, mock user success | 200 | "Authorization Complete" | Happy path |
| `token_exchange_error` | Create device code, set valid cookie, OAuth server returns 404 | 500 | "exchange token" | oauthCfg.Exchange fails |
| `request_user_error` | Create device code, set valid cookie, OAuth success, RequestFunc returns error | 500 | "get user data" | unmarshalUserData fails on request |
| `unmarshal_user_error` | Create device code, set valid cookie, OAuth success, UnmarshalFunc returns error | 500 | "get user data" | unmarshalUserData fails on unmarshal |
| `upsert_user_error` | Create device code, set valid cookie, OAuth success, erroringStore.upsertUserError = true | 500 | "upsert user" | Store.UpsertUser fails |
| `create_session_error` | Create device code, set valid cookie, OAuth success, erroringStore.createSessionError = true | 500 | "create session" | Store.CreateSession fails |
| `missing_device_code_cookie` | Create device code, no cookie set | 400 | "missing device code" | r.Cookie returns error |
| `invalid_device_code_cookie` | Create device code, cookie value is not valid base64 | 400 | "invalid device code" | base64.URLEncoding.DecodeString fails |
| `complete_device_code_error` | Create device code, set valid cookie, OAuth success, erroringDeviceCodeStore.completeDeviceCodeError = true | 500 | "complete device code" | store.CompleteDeviceCode fails |

**Test Structure:**

```go
func TestDeviceCodeAuthorizeCallback(t *testing.T) {
    // Table structure following give*/want* naming convention (matches handlers_test.go):
    // - name: test case identifier
    // - giveOAuthServer: returns *httptest.Server configured for this test
    // - giveStoreSetup: configures error flags on stores, creates device code entry
    // - giveRequestFunc: RequestFunc for user data fetch
    // - giveUnmarshalFunc: UnmarshalFunc for user data parsing
    // - giveCookie: returns cookie to set (nil = no cookie)
    // - giveOAuthCode: OAuth authorization code query parameter
    // - wantStatus: expected HTTP status code
    // - wantBodyContains: substring expected in response body

    tests := []struct {
        name             string
        giveOAuthServer  func() *httptest.Server
        giveStoreSetup   func(t *testing.T, store *erroringStore, dcStore *erroringDeviceCodeStore) string // returns deviceCode
        giveRequestFunc  RequestFunc
        giveUnmarshalFunc UnmarshalFunc
        giveCookie       func(deviceCode string) *http.Cookie // nil = no cookie
        giveOAuthCode    string
        wantStatus       int
        wantBodyContains string
    }{
        // ... test cases
    }
}
```

**Assertions:**

- HTTP status code matches expected
- Response body contains expected substring
- For success case: response is HTML with success message

**Edge Cases:**

- Cookie with valid base64 but device code not in store (handled by CompleteDeviceCode error returning ErrDeviceCodeNotFound)

### Gate: RED

- [ ] Test file created with all 9 enumerated test cases
- [ ] All tests FAIL (tests reference handler behavior)
- [ ] Test coverage includes happy path and all 8 error paths

---

## GREEN: Implement

**Objective:** Write tests that validate DeviceCodeAuthorizeCallback behavior

**Files:**

- `device_code_test.go`

**Implementation Guidance:**

```go
func TestDeviceCodeAuthorizeCallback(t *testing.T) {
    fixedTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

    // Helper: Create OAuth server that returns valid token
    newSuccessOAuthServer := func() *httptest.Server {
        // Implementation approach:
        // 1. Create httptest.Server handling /token endpoint
        // 2. Return JSON: {"access_token":"test-token","token_type":"bearer"}
        // 3. All other paths return 404
    }

    // Helper: Create OAuth server that fails
    newFailingOAuthServer := func() *httptest.Server {
        // Implementation approach:
        // 1. Create httptest.Server that returns 404 for /token
    }

    // Helper: Create valid device code cookie
    validCookie := func(deviceCode string) *http.Cookie {
        // Implementation approach:
        // 1. Base64 URL encode the device code
        // 2. Return cookie with name "devicecode"
    }

    // Helper: Success request func
    successRequestFunc := func(ctx context.Context, token string) (io.ReadCloser, error) {
        // Return valid user data as io.ReadCloser
    }

    // Helper: Success unmarshal func
    successUnmarshalFunc := func(data []byte) (Identifier, error) {
        // Return StringIdentifier("user123")
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
            name: "success",
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
            name: "token_exchange_error",
            giveOAuthServer:   newFailingOAuthServer,
            giveStoreSetup:    defaultStoreSetup,
            giveRequestFunc:   successRequestFunc,
            giveUnmarshalFunc: successUnmarshalFunc,
            giveCookie:        validCookie,
            giveOAuthCode:     "auth-code",
            wantStatus:        http.StatusInternalServerError,
            wantBodyContains:  "exchange token",
        },
        // ... remaining cases following the pattern
    }

    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            ctx := t.Context()  // Use t.Context(), not context.Background()

            // Implementation approach:
            // 1. Create OAuth server using tc.giveOAuthServer()
            // 2. Register cleanup: t.Cleanup(oauthServer.Close)
            // 3. Create stores: memStore, erroringStore wrapper, dcStore, erroringDCStore wrapper
            // 4. Call tc.giveStoreSetup to configure stores and get deviceCode
            // 5. Create Gosesh with erroringStore and WithNow(fixedTime)
            // 6. Build oauth2.Config pointing to test server's /token endpoint
            // 7. Create handler: gs.DeviceCodeAuthorizeCallback(dcStore, oauthCfg, requestFunc, unmarshalFunc)
            // 8. Create request with URL: /callback?code={tc.giveOAuthCode}
            // 9. If tc.giveCookie != nil, add cookie to request
            // 10. Execute handler with httptest.NewRecorder()
            // 11. Assert: response.Code == tc.wantStatus
            // 12. Assert: response.Body.String() contains tc.wantBodyContains
        })
    }
}
```

**Key Implementation Details:**

1. **OAuth Server Mocking**: Use `httptest.Server` to mock token endpoint
   - Success: Return `{"access_token":"test-token","token_type":"bearer"}`
   - Failure: Return 404 or error response

2. **Device Code Store Setup**: Create device code entry before each test
   - Call `store.CreateDeviceCode(ctx, userCode, expiry)` to get device code
   - Pass device code to cookie setup function

3. **Cookie Encoding**: Device code must be base64 URL encoded
   - `base64.URLEncoding.EncodeToString([]byte(deviceCode))`

4. **Request Setup**: Must include `?code=auth-code` query param
   - The handler calls `r.FormValue("code")` for OAuth exchange

### Gate: GREEN

- [ ] All 9 tests pass
- [ ] Test command: `go test -v -run TestDeviceCodeAuthorizeCallback ./...` (9 tests)
- [ ] Implementation follows pseudocode logic flow

---

## REFACTOR: Quality

**Focus:** Code quality improvements, not new functionality.

**Review Areas:**

- **Helper Extraction**: Extract common setup into reusable helpers
- **Consistency**: Follow patterns from `TestExchangeExternalToken` and `Oauth2CallbackHandlerSuite`
- **Cleanup**: Ensure OAuth servers are properly closed with `t.Cleanup()`
- **Context**: Use `t.Context()` instead of `context.Background()`

### Gate: REFACTOR

- [ ] Reviewed for code duplication and extracted common patterns
- [ ] Variable and function names are clear and descriptive
- [ ] OAuth servers properly cleaned up with t.Cleanup()
- [ ] Uses t.Context() for context values
- [ ] Helper functions call t.Helper() at the start

---

## Phase Complete

When all gates pass:

1. Update this file's status to **Complete**
2. Update index.md status table
3. Run `make coverage` to verify coverage improvement

---

**Previous:** [Phase 01](01-test-infrastructure.md)
**Next:** Final phase
