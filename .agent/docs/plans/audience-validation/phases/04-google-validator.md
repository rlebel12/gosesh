# Phase 04: Google TokenInfo Validator

**Depends on:** Phase 01 (interface definition)
**Status:** Pending

---

## RED: Write Tests

**Objective:** Test `GoogleTokenInfoValidator` implementation that calls Google's tokeninfo endpoint.

**Files:**

- `providers/google_test.go` (extend)

**Test Cases:**

**Parameterized Tests** (table format):

| Case Name | HTTP Response | Expected Audience | Expected Error | Notes |
|-----------|---------------|-------------------|----------------|-------|
| `valid_token_returns_audience` | `200 {"audience": "client-id.apps.googleusercontent.com", ...}` | `"client-id.apps.googleusercontent.com"` | `nil` | Happy path |
| `invalid_token_400` | `400 {"error": "invalid_token"}` | `""` | error contains "validate token" | Invalid/expired token |
| `malformed_json` | `200 not-json` | `""` | error contains "unmarshal" | Corrupt response |
| `missing_audience_field` | `200 {"email": "user@example.com"}` | `""` | `nil` (empty string returned) | API response missing field - returns zero value |
| `empty_audience` | `200 {"audience": ""}` | `""` | `nil` | Edge case - empty but present |
| `http_error` | connection error | `""` | error wraps underlying | Network failure |

**Discrete Tests:**

- **Test context cancellation**: Validator respects context.Done() during HTTP call
- **Test context timeout**: Validator respects context deadline
- **Test request URL construction**: Correct tokeninfo URL with access_token query param
- **Test nil client uses default**: `NewGoogleTokenInfoValidator(nil)` uses `http.DefaultClient`

**Assertions:**

- Correct HTTP request to `https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=<token>`
- Returns audience from JSON response
- HTTP errors result in wrapped errors
- Context cancellation propagates correctly

**Edge Cases:**

- Token with special characters (URL encoding)
- Very long access tokens
- Response with extra fields (should be ignored)
- Response with 5xx status codes

**Test Data:**

```go
// Mock HTTP responses
validResponse := `{
    "audience": "123456789.apps.googleusercontent.com",
    "user_id": "1234567890",
    "scope": "email profile",
    "expires_in": 3600
}`

invalidTokenResponse := `{
    "error": "invalid_token",
    "error_description": "Token has been expired or revoked."
}`

// Test helper for mock HTTP client
type mockRoundTripper struct {
    response   *http.Response
    err        error
    gotRequest *http.Request
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
    m.gotRequest = req
    return m.response, m.err
}

func newMockClient(statusCode int, body string) *http.Client {
    return &http.Client{
        Transport: &mockRoundTripper{
            response: &http.Response{
                StatusCode: statusCode,
                Body:       io.NopCloser(strings.NewReader(body)),
            },
        },
    }
}
```

### Gate: RED

- [ ] Test file created with all enumerated test cases
- [ ] All tests FAIL (implementation does not exist yet)
- [ ] Test coverage includes happy path and all edge cases

---

## GREEN: Implement

**Objective:** Implement `GoogleTokenInfoValidator` that calls Google's tokeninfo endpoint.

**Files:**

- `providers/google_audience.go` (new file in providers package)

**Implementation Guidance:**

```go
// providers/google_audience.go

const googleTokenInfoURL = "https://www.googleapis.com/oauth2/v1/tokeninfo"

// GoogleTokenInfoValidator validates Google OAuth tokens using the tokeninfo endpoint.
//
// Implementation approach:
// 1. Store *http.Client for HTTP requests
// 2. If nil client provided to constructor, use http.DefaultClient
type GoogleTokenInfoValidator struct {
    client *http.Client
}

// NewGoogleTokenInfoValidator creates a validator for Google access tokens.
//
// Implementation approach:
// 1. Accept optional *http.Client
// 2. Default to http.DefaultClient if nil
// 3. Return pointer to struct
func NewGoogleTokenInfoValidator(client *http.Client) *GoogleTokenInfoValidator {
    if client == nil {
        client = http.DefaultClient
    }
    return &GoogleTokenInfoValidator{client: client}
}

// tokenInfoResponse represents the JSON response from Google's tokeninfo endpoint.
// Only fields we need are defined; extra fields are ignored by json.Unmarshal.
type tokenInfoResponse struct {
    Audience string `json:"audience"`
    Error    string `json:"error,omitempty"`
}

// ValidateAudience calls Google's tokeninfo endpoint to get the token's audience.
//
// Implementation approach:
// 1. Build URL with access_token query parameter using url.URL
// 2. Create request with context using http.NewRequestWithContext
// 3. Execute request using stored client
// 4. Check status code - non-2xx is an error
// 5. Parse JSON response
// 6. If error field present, return error
// 7. Return audience field
//
// Error handling:
// - Network/HTTP errors: wrap with context
// - Non-2xx status: return error with status
// - JSON parse errors: wrap with "unmarshal response" context
// - API error response: return error with API error message
func (v *GoogleTokenInfoValidator) ValidateAudience(ctx context.Context, accessToken string) (string, error) {
    // Build URL using url.URL for proper query parameter handling
    u, err := url.Parse(googleTokenInfoURL)
    if err != nil {
        return "", fmt.Errorf("parse url: %w", err)
    }
    q := u.Query()
    q.Set("access_token", accessToken)
    u.RawQuery = q.Encode()

    // Create request with context for cancellation/timeout
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
    if err != nil {
        return "", fmt.Errorf("create request: %w", err)
    }

    // Execute request
    resp, err := v.client.Do(req)
    if err != nil {
        return "", fmt.Errorf("send request: %w", err)
    }
    defer resp.Body.Close()

    // Read body
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", fmt.Errorf("read response: %w", err)
    }

    // Check status code
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        return "", fmt.Errorf("validate token: %s", resp.Status)
    }

    // Parse JSON
    var tokenInfo tokenInfoResponse
    if err := json.Unmarshal(body, &tokenInfo); err != nil {
        return "", fmt.Errorf("unmarshal response: %w", err)
    }

    // Check for API-level error
    if tokenInfo.Error != "" {
        return "", fmt.Errorf("validate token: %s", tokenInfo.Error)
    }

    return tokenInfo.Audience, nil
}
```

**Key Implementation Notes:**

1. **Use `http.NewRequestWithContext`** - critical for respecting context cancellation/deadlines
2. **URL encode the token** - tokens may contain special characters
3. **Read body before checking status** - needed to get error details from API
4. **Don't define unused fields** - only Audience and Error needed from response

### Gate: GREEN

- [ ] All tests from RED phase now PASS
- [ ] Test command: `go test -v -run TestGoogleTokenInfo ./providers/...`
- [ ] Implementation follows pseudocode logic flow

---

## REFACTOR: Quality

**Focus:** Code quality improvements, not new functionality.

**Review Areas:**

- **Error messages**: Ensure error context is clear for debugging (status codes included in error messages)
- **Response body limits**: Consider limiting body read size with `io.LimitReader` to prevent memory issues with malformed responses
- **Context error handling**: Verify context cancellation errors propagate correctly from `client.Do()`

### Gate: REFACTOR

- [ ] Reviewed for code duplication and extracted common patterns
- [ ] Variable and function names are clear and descriptive
- [ ] Complex logic simplified where possible
- [ ] Error messages are helpful and actionable

---

## Phase Complete

When all gates pass:

1. Update this file's status to **Complete**
2. Update index.md status table
3. Proceed to cleanup

---

**Previous:** [Phase 03: Handler Integration](03-handler-integration.md)
**Next:** Final phase - plan complete
