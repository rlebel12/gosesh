# Phase 02: Fix Cancelled Context in Final Flush

**Depends on:** Phase 01
**Status:** Pending

---

## RED: Write Tests

**Objective:** Add test verifying final flush succeeds even when parent context is cancelled.

**Files:**

- `activity_tracker_test.go`

**Test Cases:**

| Case Name | Setup | Expected | Notes |
|-----------|-------|----------|-------|
| `final_flush_succeeds_after_context_cancel` | Record activity, cancel context, wait for Close() | Activity flushed to store | Critical: flush must use fresh context |

**Test Implementation Guidance:**

```go
t.Run("final flush succeeds after context cancel", func(t *testing.T) {
    // Setup:
    // 1. Create store and tracker with 1-hour interval (won't auto-flush)
    // 2. Start tracker with a cancellable context
    // 3. Create session in store
    // 4. Record activity for that session
    // 5. Cancel the context (simulating shutdown signal)
    // 6. Call Close() and wait for it to complete

    // Assert:
    // - Session's LastActivityAt was updated in the store
    // - This proves flush completed successfully despite cancelled context

    // Why the bug occurs:
    // When ctx.Done() fires, ctx is already cancelled. Calling flush(ctx)
    // passes this cancelled context. Inside flush(), line 102 creates:
    //   context.WithTimeout(ctx, 5*time.Second)
    // But deriving from a cancelled parent produces an immediately-cancelled
    // child context, causing BatchRecordActivity to fail before the 5s timeout.
    //
    // The fix: Pass context.Background() to flush(). This breaks the cancelled
    // parent chain. flush() then creates:
    //   context.WithTimeout(context.Background(), 5*time.Second)
    // which gives the store 5 seconds to persist, even during shutdown.
})
```

### Gate: RED

- [ ] Test file updated with new test case
- [ ] Test FAILS with current implementation (flush uses cancelled context)
- [ ] Test clearly demonstrates the bug

---

## GREEN: Implement

**Objective:** Fix `flushLoop` to use a fresh context for final flush.

**Files:**

- `activity_tracker.go`

**Current Code (buggy):**

```go
func (at *ActivityTracker) flushLoop(ctx context.Context) {
    defer at.ticker.Stop()

    for {
        select {
        case <-at.ticker.C:
            at.flush(ctx)
        case <-ctx.Done():
            at.flush(ctx) // BUG: ctx is already cancelled here!
            return
        }
    }
}
```

**Implementation Guidance:**

```go
func (at *ActivityTracker) flushLoop(ctx context.Context) {
    // Approach:
    // 1. Keep ticker flush using ctx (normal operation allows cancellation)
    // 2. For final flush on ctx.Done(), use context.Background()
    //
    // Why this works:
    // flush() internally creates context.WithTimeout(ctx, 5*time.Second) at line 102.
    // During normal operation, deriving from ctx allows parent cancellation.
    // On shutdown (ctx.Done()), ctx is already cancelled - deriving would fail.
    // Using Background() breaks the chain, allowing the 5s timeout to function.
    //
    // Per context-lifecycle.md: "Use context.Background() with timeout for
    // graceful shutdown cleanup operations that must succeed."

    defer at.ticker.Stop()

    for {
        select {
        case <-at.ticker.C:
            at.flush(ctx)
        case <-ctx.Done():
            // Final flush uses fresh context - parent is already cancelled
            at.flush(context.Background())
            return
        }
    }
}
```

### Gate: GREEN

- [ ] All tests from RED phase now PASS
- [ ] Test command: `go test ./... -v -run TestActivityTracker`
- [ ] Final flush uses `context.Background()` not cancelled `ctx`

---

## REFACTOR: Quality

**Focus:** Ensure the change is clear and well-documented.

**Review Areas:**

- **Comment clarity**: Add comment explaining why Background() is used
- **Consistency**: Verify no other places pass cancelled context to flush

### Gate: REFACTOR

- [ ] Comment explains the context.Background() choice
- [ ] Reviewed for similar patterns elsewhere (none found)

---

## Phase Complete

When all gates pass:

1. Update this file's status to **Complete**
2. Update index.md status table
3. All phases complete → ready for final verification

---

**Previous:** [Phase 01](01-merge-main.md)
**Next:** Final phase (parallel with Phase 03)
