# Issue: Session Duration Semantics and Implementation

---

title: "Session duration naming, parameter ordering, and refresh strategy need revision"
type: improvement
priority: high
complexity: moderate
estimated_effort: full-day
context:
  files_involved: [gosesh.go, handlers.go, middleware.go, store.go]
  conversation_extract: "Cookie expiration mismatch discovered in scribe project; traced to inverted semantics and parameter swap"

---

## Executive Summary

The session duration system has multiple interrelated problems: field naming conventions are inverted from industry standards, parameters are swapped when calling `CreateSession`, and the session refresh strategy (token rotation) is more complex than needed. This document proposes a revised design with clear naming, TTL extension with a configurable refresh gate, and proper two-timer session protection.

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

**Effect with default values**: Accidentally works (inversions cancel out).

**Effect when user configures conventionally** (e.g., idle=30min, active=24h):
- Cookie expires at 30 minutes
- Refresh never triggers
- Session dies prematurely with no renewal

### 3. Token Rotation Complexity

**Current approach** (middleware.go:40, 55-70):
- When refresh triggers, create new session token
- Delete old session from store
- Set new cookie with new token
- Results in INSERT + DELETE per refresh

**Simpler approach** (TTL extension):
- Extend `idleDeadline` timestamp on activity
- Cap extension at `absoluteDeadline`
- Same token throughout session lifetime
- Single UPDATE per refresh

### 4. No Refresh Threshold Configuration

The current design has no way to configure when refresh should trigger. The refresh gate is implicitly tied to `idleAt`, which is conflated with the idle timeout itself.

---

## Proposed Design

### New Naming Convention

| Current Name | New Name | Meaning | Example |
|--------------|----------|---------|---------|
| `sessionActiveDuration` | `SessionIdleTimeout` | How long without activity before session expires | 30 min |
| `sessionIdleDuration` | `SessionMaxLifetime` | Maximum session duration regardless of activity | 7 days |
| _(none)_ | `SessionRefreshThreshold` | How close to idle expiry before triggering refresh | 5 min |

### Session Lifecycle

```
Login at 9:00 AM
├── IdleTimeout: 30 min
├── MaxLifetime: 7 days
├── RefreshThreshold: 5 min
│
├── IdleDeadline = 9:30 AM
├── AbsoluteDeadline = 9:00 AM + 7 days
│
├── 9:00 - 9:25 AM: Requests served, no DB writes
│                   (time until idle expiry > RefreshThreshold)
├── 9:26 AM: Request arrives, 4 min until idle expiry
│            → Within refresh window
│            → Extend IdleDeadline to 9:56 AM (single UPDATE)
├── 9:26 - 9:51 AM: Requests served, no DB writes
├── 9:52 AM: Within window again, extend to 10:22 AM
│
└── If no activity for 30+ min: session expires
└── After 7 days from login: session expires regardless
```

### Updated Interfaces

**Session interface**:
```go
type Session interface {
    ID() Identifier
    UserID() Identifier
    IdleDeadline() time.Time     // when session expires from inactivity
    AbsoluteDeadline() time.Time // when session expires regardless
}
```

**Storer interface** (add ExtendSession):
```go
type Storer interface {
    UpsertUser(ctx context.Context, authProviderID Identifier) (userID Identifier, err error)
    CreateSession(ctx context.Context, userID Identifier, idleDeadline, absoluteDeadline time.Time) (Session, error)
    ExtendSession(ctx context.Context, sessionID string, newIdleDeadline time.Time) error
    GetSession(ctx context.Context, sessionID string) (Session, error)
    DeleteSession(ctx context.Context, sessionID string) error
    DeleteUserSessions(ctx context.Context, userID Identifier) (int, error)
}
```

**Configuration options**:
```go
func WithSessionIdleTimeout(d time.Duration) func(*Gosesh)
func WithSessionMaxLifetime(d time.Duration) func(*Gosesh)
func WithSessionRefreshThreshold(d time.Duration) func(*Gosesh)
```

**Gosesh struct fields**:
```go
type Gosesh struct {
    // ...
    sessionIdleTimeout      time.Duration // e.g., 30 * time.Minute
    sessionMaxLifetime      time.Duration // e.g., 7 * 24 * time.Hour
    sessionRefreshThreshold time.Duration // e.g., 5 * time.Minute
}
```

### Middleware Logic

```go
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

### Validation Logic

```go
func (gs *Gosesh) authenticate(w http.ResponseWriter, r *http.Request) *http.Request {
    // ... get session from cookie ...

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

### Default Values

```go
func New(store Storer, opts ...NewOpts) *Gosesh {
    gs := &Gosesh{
        // ...
        sessionIdleTimeout:      30 * time.Minute,
        sessionMaxLifetime:      7 * 24 * time.Hour,
        sessionRefreshThreshold: 5 * time.Minute,
    }
    // ...
}
```

---

## Technical Context

### Relevant Files

- `gosesh.go:50-72` - Default configuration and field definitions
- `gosesh.go:109-121` - Duration option functions
- `gosesh.go:144-157` - Storer interface definition
- `handlers.go:105-106` - CreateSession call in OAuth2Callback
- `middleware.go:26-52` - AuthenticateAndRefresh middleware
- `middleware.go:55-70` - replaceSession function (to be removed)
- `middleware.go:116-151` - authenticate function

### Migration Path

1. Add new fields and options alongside old ones
2. Deprecate old option functions with clear messages
3. Add `ExtendSession` to Storer interface
4. Update middleware to use TTL extension
5. Remove `replaceSession` function
6. Major version bump (v1.0.0 or v0.8.0)

### Dependencies & Constraints

- Breaking change to Storer interface (adds `ExtendSession`)
- Breaking change to Session interface (renames methods)
- Breaking change to configuration options (renames)
- Requires major version bump
- Existing implementations need migration guide

---

## Success Criteria

- [ ] New naming: `SessionIdleTimeout`, `SessionMaxLifetime`, `SessionRefreshThreshold`
- [ ] All three durations are configurable via `With*` options
- [ ] Default values: idle=30min, max=7days, threshold=5min
- [ ] Storer interface includes `ExtendSession(ctx, sessionID, newIdleDeadline) error`
- [ ] Session interface uses `IdleDeadline()` and `AbsoluteDeadline()`
- [ ] Middleware uses TTL extension (UPDATE) instead of token rotation (INSERT+DELETE)
- [ ] Refresh only triggers when within threshold of idle expiry
- [ ] Cookie `Expires` set to `AbsoluteDeadline`
- [ ] Validation checks both deadlines
- [ ] Documentation explains the session lifecycle clearly
- [ ] All tests updated and passing
- [ ] Migration guide for existing Storer implementations

---

## Conversation Context

Discovered while debugging cookie expiration in scribe project. User configured:
```go
idleDuration:   30 * time.Minute,
activeDuration: 24 * time.Hour,
```

Expected: Sessions last up to 24 hours with 30-minute idle refresh.
Actual: Cookies expire after 30 minutes with no refresh opportunity.

Root cause traced to parameter swap combined with inverted naming conventions. Investigation led to broader redesign proposal addressing naming, TTL extension, and configurable refresh threshold.

---

_When issue resolves: Delete this issue directory._
