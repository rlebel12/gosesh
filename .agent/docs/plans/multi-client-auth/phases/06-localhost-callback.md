# Phase 06: Localhost Callback Flow

**Depends on:** Phase 05
**Status:** Complete

---

## RED: Write Tests

**Objective:** Test OAuth2 localhost callback flow for CLI clients with browser access

**Files:**

- `localhost_callback_test.go`

**Test Cases:**

### Parameterized: OAuth2BeginCLI Callback URL Validation

| Case Name | Callback URL | Expected | Notes |
|-----------|--------------|----------|-------|
| `begin_valid_callback_url` | `http://localhost:8080/cb` | Redirects to OAuth provider | Valid localhost |
| `begin_callback_with_port` | `http://localhost:54321/cb` | Redirects to OAuth provider | Random port allowed |
| `begin_callback_127_0_0_1` | `http://127.0.0.1:8080/cb` | Redirects to OAuth provider | 127.0.0.1 allowed |
| `begin_invalid_callback_host` | `http://evil.com/cb` | 400 Bad Request | Non-localhost rejected |
| `begin_callback_https_localhost` | `https://localhost:8080/cb` | 400 Bad Request | HTTPS localhost rejected |
| `begin_missing_callback` | (none) | 400 Bad Request | Callback required |
| `begin_callback_malformed` | `not-a-url` | 400 Bad Request | Invalid URL rejected |
| `begin_callback_with_query` | `http://localhost:8080/cb?existing=param` | Redirects to OAuth provider | Query params preserved |

### Unique: OAuth2BeginCLI State Handling

| Case Name | Input | Expected | Notes |
|-----------|-------|----------|-------|
| `begin_sets_state_cookie` | Valid callback | State cookie set with HttpOnly, Secure | CSRF protection |
| `begin_stores_callback_in_state` | Valid callback | Callback URL encoded in state data | Passed through OAuth |

### Parameterized: OAuth2CallbackCLI Response Scenarios

| Case Name | OAuth Response | State Match | Expected | Notes |
|-----------|----------------|-------------|----------|-------|
| `callback_valid_flow` | Valid code | Yes | Redirects to localhost with `?token=<id>` | Happy path |
| `callback_invalid_state` | Valid code | No | 400 Bad Request | CSRF protection |
| `callback_oauth_error` | `?error=access_denied` | Yes | Redirects with `?error=access_denied` | Error forwarded |
| `callback_oauth_error_desc` | `?error=access_denied&error_description=User%20denied` | Yes | Redirects with error params | Description included |

### Unique: OAuth2CallbackCLI Session Creation

| Case Name | Input | Expected | Notes |
|-----------|-------|----------|-------|
| `callback_creates_session` | Valid OAuth flow | Session created in store | Session persists |
| `callback_session_config` | Valid OAuth flow | Session has 30-day absolute, no idle | Uses CLI SessionConfig |
| `callback_token_param_name` | Valid OAuth flow | Token in `?token=<id>` query param | Not in fragment |

**Assertions:**

- Only localhost/127.0.0.1 callbacks accepted
- State parameter validates CSRF
- Token passed via query parameter (not cookie)
- Session created with HeaderCredentialSource's SessionConfig

**Edge Cases:**

- Callback URL with query parameters already present
- Callback URL with fragment (should be stripped/ignored)
- IPv6 localhost (::1) - decide if supported
- Port 0 in callback URL

### Gate: RED

- [ ] Test file created with all enumerated test cases
- [ ] All tests FAIL (implementation does not exist yet)
- [ ] Test coverage includes happy path and all edge cases

---

## GREEN: Implement

**Objective:** Implement OAuth2 handlers for CLI localhost callback flow

**Files:**

- `handlers_cli.go`

**Implementation Guidance:**

```go
// LocalhostCallbackConfig configures the localhost callback flow
type LocalhostCallbackConfig struct {
    // Implementation approach:
    // 1. TokenParam: query parameter name for session token (default: "token")
    // 2. ErrorParam: query parameter name for error (default: "error")
    // 3. SessionConfig: override session config (default: header source config)
}

// isLocalhostURL validates that a URL is localhost
func isLocalhostURL(u *url.URL) bool {
    // Implementation approach:
    // 1. Check scheme is "http" (not https - localhost doesn't need TLS)
    // 2. Check host is "localhost" or "127.0.0.1"
    // 3. Return true if valid localhost
    //
    // Note: Reject https://localhost - unusual and may indicate misconfiguration
    // Note: Consider supporting [::1] IPv6 localhost
}

// OAuth2BeginCLI initiates OAuth2 flow with localhost callback
func (gs *Gosesh) OAuth2BeginCLI(oauthCfg *oauth2.Config) http.HandlerFunc {
    // Implementation approach:
    // 1. Extract callback URL from query: r.URL.Query().Get("callback")
    // 2. If missing -> return 400 "callback parameter required"
    // 3. Parse callback URL
    // 4. Validate isLocalhostURL(callbackURL)
    // 5. If invalid -> return 400 "callback must be localhost"
    // 6. Generate state (existing pattern from OAuth2Begin)
    // 7. Store callback URL in state cookie value (JSON encode state+callback)
    //    OR use separate cookie for callback
    // 8. Set state cookie
    // 9. Redirect to OAuth provider
}

// CLIStateData holds state + callback for CLI flow
type CLIStateData struct {
    State    string `json:"state"`
    Callback string `json:"callback"`
}

// OAuth2CallbackCLI handles OAuth2 callback and redirects to localhost
func (gs *Gosesh) OAuth2CallbackCLI(
    oauthCfg *oauth2.Config,
    request RequestFunc,
    unmarshal UnmarshalFunc,
) http.HandlerFunc {
    // Implementation approach:
    // 1. Read state cookie, parse CLIStateData
    // 2. Validate state matches response (CSRF check)
    // 3. If error in OAuth response:
    //    a. Parse callback URL
    //    b. Add error to query params
    //    c. Redirect to callback with error
    //    d. Return
    // 4. Exchange code for token (existing pattern)
    // 5. Fetch user data via request()
    // 6. Unmarshal user via unmarshal()
    // 7. Upsert user in store
    // 8. Create session with header source's SessionConfig:
    //    - Get config from gs.getHeaderSourceConfig() or default CLI config
    //    - IdleDuration: 0 (no idle timeout)
    //    - AbsoluteDuration: 30 days
    // 9. Build redirect URL:
    //    a. Parse callback URL
    //    b. Add token=<session_id> to query
    // 10. Expire state cookie
    // 11. Redirect to callback URL with token
}

// Helper to get session config for CLI sessions
func (gs *Gosesh) getCLISessionConfig() SessionConfig {
    // Implementation approach:
    // 1. If credential source is CompositeCredentialSource:
    //    - Find HeaderCredentialSource in the chain
    //    - Return its SessionConfig
    // 2. If credential source is HeaderCredentialSource:
    //    - Return its SessionConfig
    // 3. Otherwise return DefaultCLISessionConfig()
}
```

### Gate: GREEN

- [ ] All tests from RED phase now PASS
- [ ] Test command: `go test -v -run TestLocalhostCallback`
- [ ] Implementation follows pseudocode logic flow

---

## REFACTOR: Quality

**Focus:** Code quality, not new functionality.

- Ensure URL validation is thorough (no open redirects)
- Document security considerations (why http-only, why localhost-only)
- Consider extracting shared OAuth2 logic between handlers.go and handlers_cli.go

### Gate: REFACTOR

- [ ] Commit succeeds (pre-commit handles formatting/linting)

---

## Phase Complete

When all gates pass:

1. Update this file's status to **Complete**
2. Update index.md status table
3. Phase 08 can proceed once both Phase 06 and Phase 07 complete

---

**Previous:** [Phase 05](05-middleware-integration.md)
**Next:** [Phase 08](08-e2e-integration-tests.md) (after Phase 07 also completes)
