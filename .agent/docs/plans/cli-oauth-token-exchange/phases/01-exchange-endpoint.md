# Phase 01: ExchangeExternalToken Endpoint

**Depends on:** None
**Status:** Complete

---

## RED: Write Tests

**Objective:** Write tests for new ExchangeExternalToken handler

**Files:**

- `handlers_test.go` (add new test function)

**Test Cases:**

| Case Name | Input | Expected | Notes |
|-----------|-------|----------|-------|
| `valid_token_creates_session` | Valid access token, working RequestFunc | 200, JSON with session ID | Happy path |
| `invalid_json_body` | Malformed JSON | 400 Bad Request | Parse error |
| `missing_access_token` | Empty/missing token field | 400 Bad Request | Validation |
| `request_func_error` | RequestFunc returns error | 500, error in done handler | Provider unreachable |
| `unmarshal_error` | UnmarshalFunc returns error | 500, error in done handler | Invalid user data |
| `upsert_user_error` | Store.UpsertUser fails | 500, error in done handler | DB error |
| `create_session_error` | Store.CreateSession fails | 500, error in done handler | DB error |

**Discrete Tests:**

- **Test session uses CLI config**: Verify 30-day absolute, no idle timeout
- **Test response body format**: JSON contains `session_id` and `expires_at` fields

**Test Structure (table-driven):**

```go
func TestExchangeExternalToken(t *testing.T) {
    tests := map[string]struct {
        giveRequestBody   string
        giveRequestFunc   gosesh.RequestFunc
        giveUnmarshalFunc gosesh.UnmarshalFunc
        giveStoreSetup    func(*testing.T, *gosesh.MemoryStore)
        wantStatusCode    int
        wantErrContains   string
    }{
        "valid_token_creates_session": {
            giveRequestBody: `{"access_token":"valid-token"}`,
            wantStatusCode:  http.StatusOK,
        },
        // ... remaining cases from table above
    }

    for name, tc := range tests {
        t.Run(name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

**Test Helper Requirements:**
- Mark setup/helper functions with `t.Helper()`
- Use `t.Context()` for context in tests

**Assertions:**

- Response Content-Type is application/json
- Session ID in response matches created session
- Session has correct CLI timeout configuration (30-day absolute, no idle)
- Errors are wrapped with sentinel types

### Gate: RED

- [ ] Test file created with all enumerated test cases
- [ ] All tests FAIL (implementation does not exist yet)
- [ ] Test coverage includes happy path and all edge cases

---

## GREEN: Implement

**Objective:** Implement ExchangeExternalToken handler

**Files:**

- `handlers.go` (add new handler method)

**Request/Response Types:**

```go
// ExchangeTokenRequest is the expected JSON body
type ExchangeTokenRequest struct {
    AccessToken string `json:"access_token"`
}

// ExchangeTokenResponse is the JSON response
type ExchangeTokenResponse struct {
    SessionID string    `json:"session_id"`
    ExpiresAt time.Time `json:"expires_at"`
}
```

**Implementation Guidance:**

```go
func (gs *Gosesh) ExchangeExternalToken(
    request RequestFunc,
    unmarshal UnmarshalFunc,
    done HandlerDoneFunc,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        ctx := r.Context()

        // 1. Parse JSON body into ExchangeTokenRequest
        // 2. Validate access_token is non-empty
        // 3. Call request(ctx, accessToken) to fetch user data from provider
        // 4. Call unmarshal(userData) to get user Identifier
        // 5. UpsertUser(ctx, providerID)
        // 6. CreateSession(ctx, ...) with DefaultCLISessionConfig() timeouts
        // 7. Marshal ExchangeTokenResponse to JSON
        // 8. Write response with 200 OK
    }
}
```

**Error Handling:**

```go
// JSON parse error -> 400
fmt.Errorf("parse request body: %w", err)

// Empty token -> 400
errors.New("validate token: empty access_token")

// request error -> wrap and call done handler
fmt.Errorf("%w: fetch user data: %w", ErrFailedExchangingToken, err)

// unmarshal error -> wrap and call done handler
fmt.Errorf("%w: %w", ErrFailedUnmarshallingData, err)

// UpsertUser error -> wrap and call done handler
fmt.Errorf("%w: %w", ErrFailedUpsertingUser, err)

// CreateSession error -> wrap and call done handler
fmt.Errorf("%w: %w", ErrFailedCreatingSession, err)
```

**Session Configuration:**

Use `DefaultCLISessionConfig()` for CLI session timeouts (30-day absolute, no idle):

```go
cliConfig := DefaultCLISessionConfig()
session, err := gs.store.CreateSession(
    ctx,
    userID,
    now.Add(cliConfig.IdleDuration),      // 0 (no idle timeout)
    now.Add(cliConfig.AbsoluteDuration),  // 30 days
)
```

**Follow existing patterns from:**
- `OAuth2Callback()` in handlers.go:63-118 for user upsert/session creation flow
- Error wrapping with sentinel types

### Gate: GREEN

- [ ] All tests from RED phase now PASS
- [ ] Test command: `go test -v -run TestExchangeExternalToken`
- [ ] Implementation follows pseudocode logic flow

---

## REFACTOR: Quality

**Focus:** Code quality improvements

**Review Areas:**

- **Duplication**: Compare with OAuth2Callback - extract shared logic if beneficial
- **Naming**: Ensure request/response types are clear
- **Error Messages**: JSON error responses should be actionable
- **Documentation**: Add godoc comments to exported types and handler

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
3. Proceed to Phase 02

---

**Previous:** First phase
**Next:** [Phase 02](02-remove-cli-handlers.md)
