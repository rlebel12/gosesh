# Phase 04: Composite Credential Source

**Depends on:** Phase 02, Phase 03
**Status:** Pending

---

## RED: Write Tests

**Objective:** Test CompositeCredentialSource that chains multiple credential sources

**Files:**

- `composite_credential_source_test.go`

**Test Cases:**

### Unique: Basic Properties

| Case Name | Input | Expected | Notes |
|-----------|-------|----------|-------|
| `name_returns_composite` | New source | `Name()` returns `"composite"` | Identifies source type |
| `session_config_first_source` | Cookie + header sources | Returns cookie's config | Config from first source |

### Parameterized: ReadSessionID Priority

| Case Name | Sources (order) | Request Has | Expected | Notes |
|-----------|----------------|-------------|----------|-------|
| `read_first_source` | [Cookie, Header] | Cookie only | Cookie session ID | First matching wins |
| `read_second_source` | [Cookie, Header] | Header only | Header session ID | Fallback to second |
| `read_both_present` | [Cookie, Header] | Cookie AND Header | Cookie session ID | First takes priority |
| `read_neither_present` | [Cookie, Header] | Nothing | `""` | No match = empty |
| `read_reversed_order` | [Header, Cookie] | Both | Header session ID | Order matters |

### Parameterized: CanWrite Based on Composition

| Case Name | Sources | Expected | Notes |
|-----------|---------|----------|-------|
| `can_write_any_writable` | [Cookie, Header] | `true` | Cookie can write |
| `can_write_none_writable` | [Header, Header] | `false` | Neither can write |
| `can_write_all_writable` | [Cookie, Cookie] | `true` | Both can write |

### Unique: Write/Clear Fan-Out Behavior

| Case Name | Input | Expected | Notes |
|-----------|-------|----------|-------|
| `write_to_writable` | [Cookie, Header], write session | Only cookie source writes | Headers can't write |
| `write_multiple_writable` | [Cookie1, Cookie2], write session | Both cookies receive write | All writable get write |
| `clear_to_writable` | [Cookie, Header], clear session | Only cookie source clears | Headers can't clear |

### Unique: Edge Cases

| Case Name | Input | Expected | Notes |
|-----------|-------|----------|-------|
| `empty_sources` | No sources | All operations return empty/no-op | Graceful handling |
| `single_source` | Just cookie source | Behaves like cookie source | Passthrough behavior |

**Assertions:**

- Read returns first non-empty session ID
- Write calls all writable sources
- Clear calls all writable sources
- SessionConfig comes from first source

**Edge Cases:**

- Empty source list
- All sources return empty on read
- Mix of writable and non-writable sources
- Write error from one source (should continue to others? or fail fast?)

### Gate: RED

- [ ] Test file created with all enumerated test cases
- [ ] All tests FAIL (implementation does not exist yet)
- [ ] Test coverage includes happy path and all edge cases

---

## GREEN: Implement

**Objective:** Implement CompositeCredentialSource for chaining multiple sources

**Files:**

- `composite_credential_source.go`

**Implementation Guidance:**

```go
// CompositeCredentialSource chains multiple credential sources.
// Reads from first source that returns a session ID.
// Writes/clears to all sources that can write.
type CompositeCredentialSource struct {
    // Implementation approach:
    // 1. Store ordered list of sources
    // 2. First source determines SessionConfig
    // 3. Read checks sources in order, returns first non-empty
    // 4. Write/Clear fan out to all writable sources
}

func NewCompositeCredentialSource(sources ...CredentialSource) *CompositeCredentialSource {
    // Implementation approach:
    // 1. Store sources in order
    // 2. If empty, create with no sources (all operations no-op)
    // 3. Return configured source
}

func (c *CompositeCredentialSource) Name() string {
    // Return "composite"
}

func (c *CompositeCredentialSource) ReadSessionID(r *http.Request) string {
    // Implementation approach:
    // 1. For each source in order:
    //    a. Call source.ReadSessionID(r)
    //    b. If non-empty -> return it immediately
    // 2. If no source returned non-empty -> return ""
}

func (c *CompositeCredentialSource) WriteSession(w http.ResponseWriter, session Session) error {
    // Implementation approach:
    // 1. For each source:
    //    a. If source.CanWrite():
    //       - Call source.WriteSession(w, session)
    //       - If error -> return error (fail fast)
    // 2. Return nil
    //
    // Design decision: fail fast on first write error
    // Rationale: partial writes are worse than no writes
}

func (c *CompositeCredentialSource) ClearSession(w http.ResponseWriter) error {
    // Implementation approach:
    // 1. For each source:
    //    a. If source.CanWrite():
    //       - Call source.ClearSession(w)
    //       - If error -> return error (fail fast)
    // 2. Return nil
}

func (c *CompositeCredentialSource) CanWrite() bool {
    // Implementation approach:
    // 1. For each source:
    //    a. If source.CanWrite() -> return true
    // 2. Return false (no source can write)
}

func (c *CompositeCredentialSource) SessionConfig() SessionConfig {
    // Implementation approach:
    // 1. If no sources -> return zero SessionConfig
    // 2. Return first source's SessionConfig
    //
    // Rationale: first source is "primary" and determines config
}
```

### Gate: GREEN

- [ ] All tests from RED phase now PASS
- [ ] Test command: `go test -v -run TestCompositeCredentialSource`
- [ ] Implementation follows pseudocode logic flow
- [ ] Contract tests also pass for CompositeCredentialSource

---

## REFACTOR: Quality

**Focus:** Code quality, not new functionality.

- Document source ordering semantics clearly
- Consider if we need a "read from source X, write to source Y" pattern (defer for now)
- Ensure error handling is consistent

### Gate: REFACTOR

- [ ] `go vet ./...` passes
- [ ] `go test ./...` passes
- [ ] `make coverage` shows adequate coverage
- [ ] Code formatting applied (`gofmt`)

---

## Phase Complete

When all gates pass:

1. Update this file's status to **Complete**
2. Update index.md status table
3. Proceed to Phase 05

---

**Previous:** [Phase 02](02-cookie-credential-source.md) and [Phase 03](03-header-credential-source.md)
**Next:** [Phase 05](05-middleware-integration.md)
