# Phase 01: Credential Source Interface

**Depends on:** None
**Status:** Pending

---

## RED: Write Tests

**Objective:** Define contract tests for CredentialSource interface and SessionConfig type

**Files:**

- `credential_source_contract_test.go`

**Test Cases:**

Contract tests validate any CredentialSource implementation. Use parameterized approach with factory functions (following existing `contract_test.go` pattern).

### Parameterized: Contract Tests Across Implementations

Run each contract test against all implementations (Cookie, Header, Composite).

| Case Name | Input | Expected | Notes |
|-----------|-------|----------|-------|
| `name_not_empty` | Any implementation | `Name()` returns non-empty string | Identifies source for logging |
| `read_empty_request` | Request with no credentials | `ReadSessionID()` returns `""` | No credentials = empty string |
| `read_returns_consistent` | Same request twice | Same session ID both times | Deterministic read |
| `session_config_valid` | Any implementation | `SessionConfig()` has non-zero `AbsoluteDuration` | Must have absolute deadline |

### Parameterized: Write/Clear Round-Trip (Writable Sources Only)

Run against sources where `CanWrite() == true` (Cookie, Composite with Cookie).

| Case Name | Input | Expected | Notes |
|-----------|-------|----------|-------|
| `write_then_read` | Write session, create request from response | `ReadSessionID()` returns written ID | Round-trip works |
| `clear_then_read` | Clear session, read from response | `ReadSessionID()` returns `""` | Clear removes credential |

### Unique: Non-Writable Source Behavior

Separate test for sources where `CanWrite() == false`.

| Case Name | Input | Expected | Notes |
|-----------|-------|----------|-------|
| `can_write_false_noop` | Header source with `CanWrite() == false` | `WriteSession()` is no-op, no error | Headers can't write |

**Contract Struct:**

```go
type CredentialSourceContract struct {
    Name        string
    NewSource   func() CredentialSource
    // For writable sources: create request that would contain the written credential
    RequestFromResponse func(w *httptest.ResponseRecorder) *http.Request
}
```

**Assertions:**

- `Name()` returns non-empty identifier
- `ReadSessionID()` returns empty string for empty request
- `CanWrite() == true` implies `WriteSession` affects subsequent reads
- `CanWrite() == false` implies `WriteSession` is no-op
- `SessionConfig().AbsoluteDuration > 0`

**Edge Cases:**

- Source with `CanWrite() == false` (HeaderCredentialSource)
- Session with zero idle duration (no idle timeout)
- Multiple calls to same method return consistent results

### Gate: RED

- [ ] Contract test file created with all enumerated test cases
- [ ] All tests FAIL (implementation does not exist yet)
- [ ] Test coverage includes happy path and all edge cases

---

## GREEN: Implement

**Objective:** Define CredentialSource interface and SessionConfig type

**Files:**

- `gosesh.go` (add interface near Gosesh struct - Go convention: define interfaces at consumer)

**Note:** Following Go convention, the `CredentialSource` interface is defined in `gosesh.go` where it's consumed (by the `Gosesh` struct), not in a separate file. This keeps the interface close to its usage and avoids unnecessary file proliferation.

**Implementation Guidance:**

```go
// SessionConfig configures session timeouts for a credential source.
type SessionConfig struct {
    // Implementation approach:
    // 1. IdleDuration: time before idle expiry (0 = no idle timeout)
    // 2. AbsoluteDuration: maximum session lifetime (required, must be > 0)
    // 3. RefreshEnabled: whether AuthenticateAndRefresh extends idle deadline
    //
    // Validation:
    // - AbsoluteDuration must be positive
    // - If IdleDuration > 0, it should be <= AbsoluteDuration
}

// CredentialSource abstracts how session IDs are read from requests
// and written to responses.
type CredentialSource interface {
    // Implementation approach:
    // 1. Name() - Return identifier for logging/debugging
    // 2. ReadSessionID(r) - Extract session ID from request
    //    - Check appropriate location (cookie, header, etc.)
    //    - Return empty string if not present
    //    - Handle base64 decoding if needed
    // 3. WriteSession(w, session) - Write credential to response
    //    - For cookies: Set-Cookie header
    //    - For headers: no-op (client stores token)
    //    - Return error only for write failures
    // 4. ClearSession(w) - Remove credential from response
    //    - For cookies: expire cookie
    //    - For headers: no-op
    // 5. CanWrite() - Return true if source can write to response
    // 6. SessionConfig() - Return timeout configuration
}
```

**Default SessionConfig Values:**

```go
// DefaultBrowserSessionConfig for cookie-based browser sessions
func DefaultBrowserSessionConfig() SessionConfig {
    // 30 min idle, 24h absolute, refresh enabled
}

// DefaultCLISessionConfig for header-based CLI/API sessions
func DefaultCLISessionConfig() SessionConfig {
    // No idle timeout, 30 day absolute, no refresh
}
```

### Gate: GREEN

- [ ] All tests from RED phase now PASS
- [ ] Test command: `go test -v -run TestCredentialSourceContract`
- [ ] Implementation follows pseudocode logic flow

---

## REFACTOR: Quality

**Focus:** Code quality, not new functionality.

- Ensure interface is minimal (no unnecessary methods)
- Documentation comments on all exported types and methods
- SessionConfig validation helper if needed

### Gate: REFACTOR

- [ ] Commit succeeds (pre-commit handles formatting/linting)

---

## Phase Complete

When all gates pass:

1. Update this file's status to **Complete**
2. Update index.md status table
3. Proceed to Phase 02 and Phase 03 (can run in parallel)

---

**Previous:** First phase
**Next:** [Phase 02](02-cookie-credential-source.md) and [Phase 03](03-header-credential-source.md) (parallel)
