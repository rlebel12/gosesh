# Phase 02: Cookie Credential Source

**Depends on:** Phase 01
**Status:** Complete

---

## RED: Write Tests

**Objective:** Test CookieCredentialSource implementation that wraps existing cookie logic

**Files:**

- `cookie_credential_source_test.go`

**Test Cases:**

### Unique: Basic Properties

| Case Name | Input | Expected | Notes |
|-----------|-------|----------|-------|
| `name_returns_cookie` | New source | `Name()` returns `"cookie"` | Identifies source type |
| `can_write_true` | Any source | `CanWrite()` returns `true` | Cookies are writable |
| `session_config_defaults` | Default source | Config has 30min idle, 24h absolute | Browser defaults |

### Parameterized: ReadSessionID Cases

| Case Name | Cookie Value | Expected | Notes |
|-----------|--------------|----------|-------|
| `read_missing_cookie` | (no cookie) | `""` | No cookie = empty |
| `read_valid_cookie` | Base64-encoded session ID | Decoded session ID | Standard cookie read |
| `read_invalid_base64` | `"not-valid-base64!!!"` | `""` | Graceful handling |
| `read_empty_value` | `""` | `""` | Empty cookie value |

### Parameterized: Cookie Attribute Verification

Single `WriteSession` call, verify all attributes in one parameterized assertion.

| Attribute | Expected Value | Notes |
|-----------|----------------|-------|
| `HttpOnly` | `true` | Security requirement |
| `Secure` | Matches source config | HTTPS mode |
| `SameSite` | `Lax` | CSRF protection |
| `Path` | `"/"` | Site-wide scope |

### Unique: Write/Clear Behavior

| Case Name | Input | Expected | Notes |
|-----------|-------|----------|-------|
| `write_sets_cookie` | Write session | Response has `Set-Cookie` header | Cookie created |
| `write_cookie_expiry` | Write session | Cookie expires at session's AbsoluteDeadline | Expiry from session |
| `clear_expires_cookie` | Clear session | Cookie set to expired (MaxAge=-1) | Removal via expiry |

### Parameterized: Custom Options

| Option | Input | Expected Effect | Notes |
|--------|-------|-----------------|-------|
| `WithCookieName("custom")` | Custom name | Cookie uses that name | Configurable name |
| `WithCookieDomain(".example.com")` | Domain option | Cookie has domain set | Multi-domain support |
| `WithCookieSecure(false)` | Secure=false | Cookie lacks Secure flag | Development mode |

**Assertions:**

- Cookie value is base64-encoded session ID
- Cookie attributes match security requirements
- Session config matches browser defaults unless overridden
- Custom options are respected

**Edge Cases:**

- Empty session ID (should not write cookie)
- Cookie name with special characters
- Domain with leading dot

### Gate: RED

- [ ] Test file created with all enumerated test cases
- [ ] All tests FAIL (implementation does not exist yet)
- [ ] Test coverage includes happy path and all edge cases

---

## GREEN: Implement

**Objective:** Implement CookieCredentialSource refactoring existing cookie.go logic

**Files:**

- `cookie_credential_source.go`

**Implementation Guidance:**

```go
// CookieCredentialSource reads/writes session IDs via HTTP cookies.
type CookieCredentialSource struct {
    // Implementation approach:
    // 1. Store configuration: cookieName, domain, secure, sessionConfig
    // 2. Reuse existing cookie creation logic from cookies.go
    // 3. Base64 encode/decode session IDs (existing pattern)
}

// CookieSourceOption configures CookieCredentialSource
type CookieSourceOption func(*CookieCredentialSource)

func NewCookieCredentialSource(opts ...CookieSourceOption) *CookieCredentialSource {
    // Implementation approach:
    // 1. Create with defaults:
    //    - cookieName: "session"
    //    - domain: "" (current domain)
    //    - secure: true
    //    - sessionConfig: DefaultBrowserSessionConfig()
    // 2. Apply options
    // 3. Return configured source
}

// Option functions
func WithCookieName(name string) CookieSourceOption { ... }
func WithCookieDomain(domain string) CookieSourceOption { ... }
func WithCookieSecure(secure bool) CookieSourceOption { ... }
func WithCookieSessionConfig(cfg SessionConfig) CookieSourceOption { ... }

func (c *CookieCredentialSource) Name() string {
    // Return "cookie"
}

func (c *CookieCredentialSource) ReadSessionID(r *http.Request) string {
    // Implementation approach:
    // 1. Get cookie by name from request
    // 2. If not found -> return ""
    // 3. Base64 decode the value
    // 4. If decode fails -> return ""
    // 5. Return decoded session ID
}

func (c *CookieCredentialSource) WriteSession(w http.ResponseWriter, session Session) error {
    // Implementation approach:
    // 1. Base64 encode session.ID().String()
    // 2. Create cookie with:
    //    - Name: c.cookieName
    //    - Value: encoded ID
    //    - Path: "/"
    //    - Domain: c.domain
    //    - Expires: session.AbsoluteDeadline()
    //    - HttpOnly: true
    //    - Secure: c.secure
    //    - SameSite: Lax
    // 3. Set cookie on response
    // 4. Set security headers (Cache-Control, Vary)
}

func (c *CookieCredentialSource) ClearSession(w http.ResponseWriter) error {
    // Implementation approach:
    // 1. Create cookie with same name
    // 2. Set Expires to Unix epoch (time.Unix(0, 0))
    // 3. Set MaxAge to -1
    // 4. Set cookie on response
}

func (c *CookieCredentialSource) CanWrite() bool {
    // Return true - cookies can be written
}

func (c *CookieCredentialSource) SessionConfig() SessionConfig {
    // Return c.sessionConfig
}
```

### Gate: GREEN

- [ ] All tests from RED phase now PASS
- [ ] Test command: `go test -v -run TestCookieCredentialSource`
- [ ] Implementation follows pseudocode logic flow
- [ ] Contract tests also pass for CookieCredentialSource

---

## REFACTOR: Quality

**Focus:** Code quality, not new functionality.

- Extract shared cookie creation logic if duplicated with existing cookies.go
- Ensure option functions follow existing WithXxx pattern
- Document security considerations

### Gate: REFACTOR

- [ ] Commit succeeds (pre-commit handles formatting/linting)

---

## Phase Complete

When all gates pass:

1. Update this file's status to **Complete**
2. Update index.md status table
3. Phase 04 can proceed once both Phase 02 and Phase 03 complete

---

**Previous:** [Phase 01](01-credential-source-interface.md)
**Next:** [Phase 04](04-composite-credential-source.md) (after Phase 03 also completes)
