# Phase 03: Fix Test String Conversion

**Depends on:** Phase 01
**Status:** Complete

---

## Objective

Fix the incorrect `string(rune(id))` conversion in the concurrent recording test. This produces unprintable characters for most integer values instead of readable session IDs.

---

## Analysis

**Current Code (buggy):**

```go
t.Run("handles concurrent recording safely", func(t *testing.T) {
    // ...
    for i := 0; i < 100; i++ {
        wg.Add(1)
        go func(id int) {
            defer wg.Done()
            sessionID := "session-" + string(rune(id))  // BUG: produces unprintable chars
            tracker.RecordActivity(sessionID, time.Now().UTC())
        }(i)
    }
    // ...
})
```

**Problem:**
- `rune(0)` is the NULL character
- `rune(1)` through `rune(31)` are control characters
- Only `rune(48)` through `rune(57)` are '0'-'9'
- This makes test output unreadable and session IDs non-deterministic

---

## RED: Verify Bug Exists

**Objective:** Confirm the existing test produces unprintable session IDs.

**Verification Command:**

```bash
# Run the test and inspect output for control characters
go test -v -run "handles concurrent" ./... 2>&1 | od -c | head -20
```

Look for `\0`, `\001`, `\002`, etc. in the output - these are unprintable control characters.

### Gate: RED

- [x] Ran verification command
- [x] Confirmed output contains control characters (unprintable session IDs)
- [x] Bug is reproducible

---

## GREEN: Implement Fix

**Objective:** Use `strconv.Itoa()` or `fmt.Sprintf()` for proper integer-to-string conversion.

**Files:**

- `activity_tracker_test.go`

**Implementation Guidance:**

```go
// Option 1: strconv.Itoa (preferred - no format parsing overhead)
import "strconv"
sessionID := "session-" + strconv.Itoa(id)

// Option 2: fmt.Sprintf (also correct, slightly more overhead)
sessionID := fmt.Sprintf("session-%d", id)
```

**Change Location:** `activity_tracker_test.go`, inside the `handles concurrent recording safely` test.

**Import Check:** Before adding `strconv`, verify current imports in activity_tracker_test.go. If `strconv` is already imported, no import change needed.

### Gate: GREEN

- [x] Test updated to use `strconv.Itoa(id)` instead of `string(rune(id))`
- [x] Import `strconv` added if not present
- [x] All tests pass: `go test ./... -v -run "handles concurrent"`
- [x] Session IDs in test are now readable (e.g., "session-42")

---

## REFACTOR: Quality

**Focus:** Ensure no similar issues elsewhere.

**Review Areas:**

- Search for other `string(rune(` patterns in test files
- Verify the fix is consistent with other ID generation in tests

### Gate: REFACTOR

- [x] Searched for similar patterns: `grep -r "string(rune" *.go`
- [x] No other instances found (or all fixed)

---

## Phase Complete

When all gates pass:

1. Update this file's status to **Complete**
2. Update index.md status table
3. All phases complete → ready for final verification

---

**Previous:** [Phase 01](01-merge-main.md)
**Next:** Final phase (parallel with Phase 02)
