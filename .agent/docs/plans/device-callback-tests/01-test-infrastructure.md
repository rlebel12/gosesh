# Phase 01: Test Infrastructure

**Depends on:** None
**Phase Type:** Infrastructure
**Status:** Pending

---

## Existing Test Verification

**Run existing tests:** `go test -v ./...`

**Expected result:** All tests pass before making changes

### Gate: EXISTING TESTS

- [ ] Existing test suite executed
- [ ] All tests PASS before proceeding

---

## GREEN: Implement

**Objective:** Add erroringDeviceCodeStore wrapper for error injection

**Files:**

- `fake_test.go`

**Implementation Guidance:**

```go
// erroringDeviceCodeStore wraps a DeviceCodeStore and injects errors for testing.
// Located in fake_test.go alongside erroringStore.

type erroringDeviceCodeStore struct {
    DeviceCodeStore
    completeDeviceCodeError bool
}

func (s *erroringDeviceCodeStore) CompleteDeviceCode(ctx context.Context, deviceCode string, sessionID Identifier) error {
    // Implementation approach:
    // 1. Check if completeDeviceCodeError flag is set
    // 2. If set -> return errors.New("mock failure")
    // 3. Otherwise -> delegate to underlying store
}
```

**Note:** Only `CompleteDeviceCode` needs error injection for testing `DeviceCodeAuthorizeCallback`. Other DeviceCodeStore methods are not called after the point where we can inject errors (the handler uses the store directly for `CompleteDeviceCode` only).

### Gate: GREEN

- [ ] erroringDeviceCodeStore added to fake_test.go
- [ ] Test command: `go test -v ./...` (all existing tests still pass)
- [ ] Implementation follows pseudocode logic flow

---

## REFACTOR: Quality

**Focus:** Code quality improvements, not new functionality.

**Review Areas:**

- **Consistency**: Ensure `erroringDeviceCodeStore` follows same pattern as `erroringStore`
- **Naming**: Field name matches pattern (`completeDeviceCodeError` like `createSessionError`)
- **Placement**: Add near `erroringStore` in `fake_test.go` for discoverability

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
3. Proceed to next dependent phase

---

**Previous:** First phase
**Next:** [Phase 02](02-callback-tests.md)
