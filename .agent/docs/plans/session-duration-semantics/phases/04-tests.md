# Phase 04: Test Updates

**Depends on:** Phase 03
**Status:** Complete

---

## RED: Write Tests

**Objective:** Ensure all existing tests compile and define new contract tests

**Files:**
- `contract_test.go`
- `middleware_test.go`
- `handlers_test.go`
- `fake_test.go`

**Contract Test Cases for ExtendSession:**

| Case Name | Setup | Action | Expected | Notes |
|-----------|-------|--------|----------|-------|
| `extend_session_success` | Create session with known deadline | ExtendSession with new deadline | GetSession returns updated deadline | Core functionality |
| `extend_session_not_found` | Empty store | ExtendSession with invalid ID | Returns error | Error path |

**Updates Required Per File:**

| File | Updates Needed |
|------|----------------|
| `contract_test.go` | Add ExtendSession tests, rename IdleAt→IdleDeadline, ExpireAt→AbsoluteDeadline |
| `middleware_test.go` | Update for threshold logic, use ExtendSession expectations |
| `handlers_test.go` | Rename method calls in session assertions |
| `fake_test.go` | Add ExtendSession to erroringStore wrapper |

### Gate: RED

- [ ] All test files updated to use new method names
- [ ] ExtendSession contract tests written
- [ ] erroringStore includes ExtendSession wrapper
- [ ] Tests compile (may fail until implementation complete)

---

## GREEN: Implement

**Objective:** Fix all tests to pass with new implementation

**Files:**
- All test files listed above

### contract_test.go Changes

**Implementation Guidance:**

```go
// Add ExtendSession contract test after DeleteUserSessions tests:
t.Run("can extend a session", func(t *testing.T) {
    store := newStore()
    userID, _ := store.UpsertUser(t.Context(), gosesh.StringIdentifier("test"))

    originalDeadline := time.Now().Add(30 * time.Minute)
    absoluteDeadline := time.Now().Add(24 * time.Hour)
    session, err := store.CreateSession(t.Context(), userID, originalDeadline, absoluteDeadline)
    require.NoError(t, err)

    newDeadline := time.Now().Add(1 * time.Hour)
    err = store.ExtendSession(t.Context(), session.ID().String(), newDeadline)
    require.NoError(t, err)

    updated, err := store.GetSession(t.Context(), session.ID().String())
    require.NoError(t, err)
    assert.Equal(t, newDeadline.Unix(), updated.IdleDeadline().Unix())
    assert.Equal(t, absoluteDeadline.Unix(), updated.AbsoluteDeadline().Unix())  // unchanged
})

t.Run("extend session not found", func(t *testing.T) {
    store := newStore()
    err := store.ExtendSession(t.Context(), "nonexistent", time.Now())
    require.Error(t, err)
})
```

```go
// Update existing tests to use new method names:
// IdleAt() -> IdleDeadline()
// ExpireAt() -> AbsoluteDeadline()
```

### middleware_test.go Changes

**Implementation Guidance:**

```go
// Update TestAuthenticateAndRefresh test cases:
// - "session active" -> now checks threshold, not just IdleAt
// - "session idle" tests become "session within threshold" tests
// - Remove expectation of DeleteSession calls
// - Add expectation of ExtendSession calls

// Example updated test case:
t.Run("session within refresh threshold triggers extension", func(t *testing.T) {
    // Session with IdleDeadline 5 minutes away (< 10min threshold)
    session, err := store.CreateSession(t.Context(), userID,
        now.Add(5*time.Minute),   // within threshold
        now.Add(85*time.Minute))  // absolute deadline
    // ... expect ExtendSession to be called
})

t.Run("session outside refresh threshold no extension", func(t *testing.T) {
    // Session with IdleDeadline 15 minutes away (> 10min threshold)
    session, err := store.CreateSession(t.Context(), userID,
        now.Add(15*time.Minute),  // outside threshold
        now.Add(85*time.Minute))  // absolute deadline
    // ... expect no ExtendSession call
})
```

### handlers_test.go Changes

**Implementation Guidance:**

```go
// Update session assertions:
// session.IdleAt() -> session.IdleDeadline()
// session.ExpireAt() -> session.AbsoluteDeadline()
```

### fake_test.go Changes

**Implementation Guidance:**

```go
// Add ExtendSession to erroringStore:
type erroringStore struct {
    gosesh.Storer
    upsertUserError      bool
    createSessionError   bool
    getSessionError      bool
    deleteSessionError   bool
    extendSessionError   bool  // NEW
}

func (s *erroringStore) ExtendSession(ctx context.Context, sessionID string, newIdleDeadline time.Time) error {
    if s.extendSessionError {
        return errors.New("mock failure")
    }
    return s.Storer.ExtendSession(ctx, sessionID, newIdleDeadline)
}
```

### Gate: GREEN

- [ ] All tests compile
- [ ] `go test ./...` passes
- [ ] ExtendSession contract tests pass
- [ ] Middleware tests verify threshold behavior
- [ ] No test references old method names (IdleAt, ExpireAt)

---

## REFACTOR: Quality

**Focus:** Test clarity and coverage.

- Test names reflect new semantics
- No orphaned test helpers for removed functionality
- Coverage maintained or improved

### Gate: REFACTOR

- [ ] Pre-commit passes: `make pc-dirty`
- [ ] `make coverage` shows adequate coverage
- [ ] No dead test code

---

## Phase Complete

When all gates pass:

1. Update this file's status to **Complete**
2. Update index.md status to show 4/4 complete
3. Update CLAUDE.md documentation
4. Delete the issue directory: `.agent/docs/issues/session-duration-semantics/`
5. Delete this plan directory: `.agent/docs/plans/session-duration-semantics/`

---

**Previous:** [Phase 03: Core Logic](03-core-logic.md)
**Next:** Final phase - cleanup
