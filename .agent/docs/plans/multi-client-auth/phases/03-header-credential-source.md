# Phase 03: Header Credential Source

**Depends on:** Phase 01
**Status:** Complete

---

## RED: Write Tests

**Objective:** Test HeaderCredentialSource implementation for Bearer token authentication

**Files:**

- `header_credential_source_test.go`

**Test Cases:**

### Unique: Basic Properties

| Case Name | Input | Expected | Notes |
|-----------|-------|----------|-------|
| `name_returns_header` | New source | `Name()` returns `"header"` | Identifies source type |
| `can_write_false` | Any source | `CanWrite()` returns `false` | Headers not writable |
| `session_config_defaults` | Default source | No idle timeout, 30 day absolute | CLI defaults |

### Parameterized: ReadSessionID Cases

| Case Name | Authorization Header | Expected | Notes |
|-----------|---------------------|----------|-------|
| `read_missing_header` | (no header) | `""` | No header = empty |
| `read_valid_bearer` | `Bearer abc123` | `"abc123"` | Standard Bearer token |
| `read_bearer_base64` | `Bearer dXNlcjEyMw==` | `"user123"` | Base64 decoded |
| `read_wrong_scheme` | `Basic xxx` | `""` | Only Bearer supported |
| `read_malformed_no_token` | `Bearer ` | `""` | Missing token after scheme |
| `read_malformed_no_space` | `Bearerabc123` | `""` | Missing space separator |
| `read_case_insensitive` | `bearer abc123` | `"abc123"` | Scheme is case-insensitive |
| `read_BEARER_caps` | `BEARER abc123` | `"abc123"` | Scheme is case-insensitive |

### Unique: Write/Clear No-Op Behavior

| Case Name | Input | Expected | Notes |
|-----------|-------|----------|-------|
| `write_noop` | Write session | Response headers unchanged | Headers can't write |
| `clear_noop` | Clear session | Response headers unchanged | Headers can't clear |

### Parameterized: Custom Options

| Option | Input | Expected Effect | Notes |
|--------|-------|-----------------|-------|
| `WithHeaderName("X-Session-ID")` | `X-Session-ID: abc` | Returns `"abc"` | Configurable header |
| `WithHeaderScheme("Token")` | `Authorization: Token abc` | Returns `"abc"` | Configurable scheme |

**Assertions:**

- Bearer token is extracted correctly
- Scheme comparison is case-insensitive (per RFC 7235)
- Write and Clear operations are no-ops
- Session config matches CLI defaults unless overridden

**Edge Cases:**

- Extra whitespace in header value
- Multiple Authorization headers (use first)
- Empty token after "Bearer "
- Token with special characters

### Gate: RED

- [x] Test file created with all enumerated test cases
- [x] All tests FAIL (implementation does not exist yet)
- [x] Test coverage includes happy path and all edge cases

---

## GREEN: Implement

**Objective:** Implement HeaderCredentialSource for Authorization: Bearer authentication

**Files:**

- `header_credential_source.go`

**Implementation Guidance:**

```go
// HeaderCredentialSource reads session IDs from Authorization header.
// It cannot write sessions (clients must store tokens themselves).
type HeaderCredentialSource struct {
    // Implementation approach:
    // 1. Store configuration: headerName, scheme, sessionConfig
    // 2. Parse Authorization header per RFC 7235
    // 3. Support base64-encoded tokens
}

// HeaderSourceOption configures HeaderCredentialSource
type HeaderSourceOption func(*HeaderCredentialSource)

func NewHeaderCredentialSource(opts ...HeaderSourceOption) *HeaderCredentialSource {
    // Implementation approach:
    // 1. Create with defaults:
    //    - headerName: "Authorization"
    //    - scheme: "Bearer"
    //    - sessionConfig: DefaultCLISessionConfig()
    // 2. Apply options
    // 3. Return configured source
}

// Option functions
func WithHeaderName(name string) HeaderSourceOption { ... }
func WithHeaderScheme(scheme string) HeaderSourceOption { ... }
func WithHeaderSessionConfig(cfg SessionConfig) HeaderSourceOption { ... }

func (h *HeaderCredentialSource) Name() string {
    // Return "header"
}

func (h *HeaderCredentialSource) ReadSessionID(r *http.Request) string {
    // Implementation approach:
    // 1. Get header value: r.Header.Get(h.headerName)
    // 2. If empty -> return ""
    // 3. Split on first space: "<scheme> <token>"
    // 4. Compare scheme case-insensitively (strings.EqualFold)
    // 5. If scheme doesn't match -> return ""
    // 6. Extract token part (trim whitespace)
    // 7. If token empty -> return ""
    // 8. Try base64 decode:
    //    - If valid base64 -> return decoded
    //    - If not valid base64 -> return as-is (raw token)
    // 9. Return token
}

func (h *HeaderCredentialSource) WriteSession(w http.ResponseWriter, session Session) error {
    // No-op: headers cannot be written by server
    // Client is responsible for storing and sending token
    return nil
}

func (h *HeaderCredentialSource) ClearSession(w http.ResponseWriter) error {
    // No-op: headers cannot be cleared by server
    return nil
}

func (h *HeaderCredentialSource) CanWrite() bool {
    // Return false - server cannot write headers to client
    return false
}

func (h *HeaderCredentialSource) SessionConfig() SessionConfig {
    // Return h.sessionConfig
}
```

### Gate: GREEN

- [x] All tests from RED phase now PASS
- [x] Test command: `go test -v -run TestHeaderCredentialSource`
- [x] Implementation follows pseudocode logic flow
- [x] Contract tests also pass for HeaderCredentialSource

---

## REFACTOR: Quality

**Focus:** Code quality, not new functionality.

- Ensure RFC 7235 compliance for Authorization header parsing
- Document that base64 decoding is attempted for compatibility with cookie tokens
- Clear documentation on why CanWrite() returns false

### Gate: REFACTOR

- [x] Commit succeeds (pre-commit handles formatting/linting)

---

## Phase Complete

When all gates pass:

1. Update this file's status to **Complete**
2. Update index.md status table
3. Phase 04 can proceed once both Phase 02 and Phase 03 complete

---

**Previous:** [Phase 01](01-credential-source-interface.md)
**Next:** [Phase 04](04-composite-credential-source.md) (after Phase 02 also completes)
