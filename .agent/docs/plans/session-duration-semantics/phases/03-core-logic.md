# Phase 03: Core Logic Updates

**Depends on:** Phase 02
**Status:** Complete

---

## RED: Write Tests

**Objective:** Define test cases for new middleware behavior

**Files:**
- `middleware_test.go` (update for new refresh logic)

**Test Cases for AuthenticateAndRefresh:**

| Case Name | Time Until Idle | Expected Behavior | Notes |
|-----------|-----------------|-------------------|-------|
| `no_refresh_outside_threshold` | 15 min (> 10min threshold) | No ExtendSession call | Session still fresh |
| `refresh_within_threshold` | 5 min (< 10min threshold) | ExtendSession called | Within refresh window |
| `refresh_caps_at_absolute` | 5 min, but absolute in 30min | newIdleDeadline = absoluteDeadline | Cap at maximum |
| `refresh_error_continues` | Within threshold | ExtendSession fails, request continues | Graceful degradation |

**Test Cases for authenticate (dual validation):**

| Case Name | IdleDeadline | AbsoluteDeadline | Expected | Notes |
|-----------|--------------|------------------|----------|-------|
| `both_valid` | Future | Future | Session in context | Happy path |
| `idle_expired` | Past | Future | Cookie expired, no session | Idle timeout |
| `absolute_expired` | Future | Past | Cookie expired, no session | Hard limit |
| `both_expired` | Past | Past | Cookie expired, no session | Fully expired |

### Gate: RED

- [ ] Test cases for threshold-based refresh defined
- [ ] Test cases for dual deadline validation defined
- [ ] Tests reference ExtendSession (not replaceSession)
- [ ] Tests fail (new logic not implemented)

---

## GREEN: Implement

**Objective:** Update handlers and middleware for new semantics

**Files:**
- `handlers.go`
- `middleware.go`

### handlers.go Changes

**Implementation Guidance:**

```go
// OAuth2Callback CreateSession call (lines 105-106)
// Update to use new field names:
session, err := gs.store.CreateSession(
    ctx, id,
    now.Add(gs.sessionIdleTimeout),    // was: sessionActiveDuration
    now.Add(gs.sessionMaxLifetime),    // was: sessionIdleDuration
)
```

### middleware.go Changes

**Implementation Guidance:**

```go
// AuthenticateAndRefresh (lines 26-53)
// Rewrite to use TTL extension with threshold:
func (gs *Gosesh) AuthenticateAndRefresh(next http.Handler) http.Handler {
    return gs.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        session, ok := CurrentSession(r)
        if !ok {
            next.ServeHTTP(w, r)
            return
        }

        now := gs.now().UTC()
        timeUntilIdle := session.IdleDeadline().Sub(now)

        // Only extend if within refresh threshold
        if timeUntilIdle > gs.sessionRefreshThreshold {
            next.ServeHTTP(w, r)
            return
        }

        // Calculate new idle deadline, capped at absolute deadline
        newIdleDeadline := now.Add(gs.sessionIdleTimeout)
        if newIdleDeadline.After(session.AbsoluteDeadline()) {
            newIdleDeadline = session.AbsoluteDeadline()
        }

        if err := gs.store.ExtendSession(r.Context(), session.ID().String(), newIdleDeadline); err != nil {
            gs.logError("extend session", err)
            next.ServeHTTP(w, r)
            return
        }

        // Update cookie expiration
        sessionCookie := gs.sessionCookie(session.ID(), session.AbsoluteDeadline())
        http.SetCookie(w, sessionCookie)

        next.ServeHTTP(w, r)
    }))
}
```

```go
// DELETE replaceSession function (lines 55-70)
// This function is no longer needed - remove entirely
```

```go
// authenticate function (lines 116-151)
// Add dual deadline validation:
func (gs *Gosesh) authenticate(w http.ResponseWriter, r *http.Request) *http.Request {
    // ... existing cookie parsing and session retrieval ...

    now := gs.now().UTC()

    // Check idle deadline (sliding window)
    if session.IdleDeadline().Before(now) {
        gs.logError("session idle expired", ErrSessionExpired)
        http.SetCookie(w, gs.expireSessionCookie())
        return r
    }

    // Check absolute deadline (hard limit)
    if session.AbsoluteDeadline().Before(now) {
        gs.logError("session absolute expired", ErrSessionExpired)
        http.SetCookie(w, gs.expireSessionCookie())
        return r
    }

    return gs.newRequestWithSession(r, session)
}
```

### Gate: GREEN

- [ ] handlers.go uses sessionIdleTimeout and sessionMaxLifetime
- [ ] AuthenticateAndRefresh uses threshold-based refresh
- [ ] AuthenticateAndRefresh calls ExtendSession (not CreateSession/DeleteSession)
- [ ] authenticate checks both IdleDeadline and AbsoluteDeadline
- [ ] replaceSession function removed
- [ ] Cookie expiration set to AbsoluteDeadline

---

## REFACTOR: Quality

**Focus:** Ensure logic is clear and error handling is consistent.

- Error messages use new terminology (idle/absolute)
- No dead code from old implementation
- Logic flow is readable

### Gate: REFACTOR

- [ ] Pre-commit passes: `make pc-dirty`
- [ ] No unused imports or variables
- [ ] replaceSession completely removed (no orphaned code)

---

## Phase Complete

When all gates pass:

1. Update this file's status to **Complete**
2. Update index.md status table
3. Proceed to Phase 04

---

**Previous:** [Phase 02: Memory Store](02-memory-store.md)
**Next:** [Phase 04: Tests](04-tests.md)
