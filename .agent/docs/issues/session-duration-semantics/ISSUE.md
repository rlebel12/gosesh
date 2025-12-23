# Issue: Session Duration Semantics and Implementation

---

title: "Session duration naming, parameter ordering, and refresh strategy need revision"
type: improvement
priority: high
complexity: moderate
estimated_effort: half-day
context:
  files_involved: [gosesh.go, handlers.go, middleware.go, store.go]
  conversation_extract: "Cookie expiration mismatch discovered in scribe project; traced to inverted semantics and parameter swap"

---

## Executive Summary

The session duration system has multiple interrelated problems: field naming conventions are inverted from industry standards, parameters are swapped when calling `CreateSession`, and the session refresh strategy (token rotation) differs from the more common TTL extension pattern. These issues cause confusion when implementing the `Storer` interface and lead to unexpected session expiration behavior.

---

## Problem Areas

### 1. Inverted Naming Conventions

**Current defaults** (gosesh.go:60-61):
```go
sessionActiveDuration: 1 * time.Hour,
sessionIdleDuration:   24 * time.Hour,
```

**Industry convention**:
- "Idle timeout" = shorter duration (session expires after inactivity)
- "Active/absolute timeout" = longer duration (maximum session lifetime)

**Current gosesh convention**:
- `sessionActiveDuration` = 1 hour (shorter)
- `sessionIdleDuration` = 24 hours (longer)

This inverts the typical meaning, causing implementers to configure values backwards.

### 2. Parameter Swap in CreateSession Calls

**Storer interface** (gosesh.go:150):
```go
CreateSession(ctx context.Context, userID Identifier, idleAt, expireAt time.Time) (Session, error)
```

**Actual calls** (handlers.go:105-106, middleware.go:56-60):
```go
gs.store.CreateSession(ctx, id,
    now.Add(gs.sessionActiveDuration),  // passed as idleAt
    now.Add(gs.sessionIdleDuration),    // passed as expireAt
)
```

The interface says `(idleAt, expireAt)` but the call passes `(activeDuration, idleDuration)`.

**Effect with default values**:
- `idleAt` = now + 1 hour
- `expireAt` = now + 24 hours
- Cookie expires at 24 hours, refresh triggers after 1 hour
- This accidentally works correctly

**Effect when user configures conventionally** (e.g., idle=30min, active=24h):
- `idleAt` = now + 24 hours
- `expireAt` = now + 30 minutes
- Cookie expires at 30 minutes
- Refresh never triggers (would need 24 hours)
- Session dies prematurely with no renewal

### 3. Non-Conventional Refresh Strategy

**Current approach** (middleware.go:40, 55-70):
- When refresh is needed, create entirely new session token
- Delete old session from store
- Set new cookie with new token

**Industry-standard approach**:
- Extend `idleDeadline` on activity (sliding window)
- Cap extension at `absoluteDeadline`
- Same token throughout session lifetime
- Simpler, fewer DB writes

**Trade-offs**:

| Approach | Pros | Cons |
|----------|------|------|
| Token rotation (current) | Limits token exposure window; OWASP recommended for sensitive ops | More DB writes; implementation complexity |
| TTL extension | Simpler; fewer DB operations; easier to reason about | Same token valid longer |

Token rotation is more secure but may be overkill for many use cases. The current implementation doesn't clearly document this as a deliberate security choice.

---

## Investigation Roadmap

### Primary Hypothesis: Rename and Reorder for Clarity

Align naming with industry conventions:

1. Rename `sessionIdleDuration` to `sessionAbsoluteDuration` (or keep as longer value)
2. Rename `sessionActiveDuration` to `sessionIdleDuration` (or use as shorter value)
3. Update `CreateSession` calls to pass parameters in correct order
4. Update defaults to conventional values (e.g., idle=30min, absolute=24h)

**If confirmed, resolution approach:**
- Breaking change to configuration API
- Requires major version bump
- Update all documentation

### Alternative Hypothesis: Keep Names, Fix Parameter Order

Minimal change - just fix the parameter swap:

1. Keep current naming (accept it's non-standard)
2. Fix handlers.go and middleware.go to pass parameters correctly
3. Document the unconventional naming clearly

**Trade-off**: Less disruption but ongoing confusion for new users.

### Alternative Hypothesis: Simplify to TTL Extension

Replace token rotation with TTL extension:

1. Remove `CreateSession` from refresh path
2. Add `ExtendSession(ctx, sessionID, newIdleDeadline)` to Storer
3. Update middleware to extend rather than replace
4. Simpler mental model, fewer DB writes

**Trade-off**: Less secure (same token lives longer), but sufficient for most apps.

---

## Technical Context

### Relevant Files

- `gosesh.go:50-72` - Default configuration and field definitions
- `gosesh.go:109-121` - Duration option functions
- `gosesh.go:144-157` - Storer interface definition
- `handlers.go:105-106` - CreateSession call in OAuth2Callback
- `middleware.go:55-70` - replaceSession function (token rotation)
- `middleware.go:35-38` - Refresh trigger condition

### How Validation Currently Works

**Session expiration check** (middleware.go:144):
```go
if session.ExpireAt().Before(gs.now().UTC()) {
    // session expired
}
```

**Refresh trigger** (middleware.go:35-38):
```go
if session.IdleAt().After(now) {
    // IdleAt still in future, skip refresh
    return
}
// IdleAt passed, refresh session
```

### Dependencies & Constraints

- Breaking changes require major version bump
- Existing implementations of `Storer` interface would need updates
- Cookie expiration is tied to `Session.ExpireAt()` return value

---

## Success Criteria

- [ ] Duration field names align with their semantic meaning
- [ ] `CreateSession` parameters match interface definition order
- [ ] Default values produce expected behavior (shorter idle, longer absolute)
- [ ] User configuring `idle=30min, absolute=24h` gets 24h cookie expiration
- [ ] Documentation clearly explains the session lifecycle
- [ ] Existing tests updated and passing
- [ ] If keeping token rotation: document as deliberate security feature

---

## Conversation Context

Discovered while debugging cookie expiration in scribe project. User configured:
```go
idleDuration:   30 * time.Minute,
activeDuration: 24 * time.Hour,
```

Expected: Sessions last up to 24 hours with 30-minute idle refresh.
Actual: Cookies expire after 30 minutes with no refresh opportunity.

Root cause traced to parameter swap combined with inverted naming conventions. The library's defaults accidentally work because both inversions cancel out, but any user following conventional naming patterns will experience broken session behavior.

---

_When issue resolves: Delete this issue directory._
