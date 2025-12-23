# Phase 01: Interface Definitions

**Depends on:** None
**Status:** Complete

---

## RED: Write Tests

**Objective:** Define interface contracts that will drive implementation

**Files:**
- `gosesh.go` (interface definitions - no direct tests, validated by compilation)

**Note:** This phase is primarily type definitions. The "tests" are the interface compliance checks at compile time and the contract tests in Phase 04.

**Interface Changes:**

| Interface | Old Method | New Method | Purpose |
|-----------|------------|------------|---------|
| `Session` | `IdleAt()` | `IdleDeadline()` | When session expires from inactivity |
| `Session` | `ExpireAt()` | `AbsoluteDeadline()` | When session expires regardless |
| `Storer` | _(none)_ | `ExtendSession(ctx, sessionID, newIdleDeadline)` | TTL extension |

**Struct Field Changes:**

| Old Field | New Field | Default | Purpose |
|-----------|-----------|---------|---------|
| `sessionActiveDuration` | `sessionIdleTimeout` | 1hr | Idle expiry window |
| `sessionIdleDuration` | `sessionMaxLifetime` | 24hr | Absolute lifetime |
| _(none)_ | `sessionRefreshThreshold` | 10min | When to trigger refresh |

### Gate: RED

- [ ] Interface changes defined (compilation will fail until Phase 02-03)
- [ ] All field renames identified
- [ ] All method renames identified

---

## GREEN: Implement

**Objective:** Update interface definitions in gosesh.go

**Files:**
- `gosesh.go`

**Implementation Guidance:**

```go
// Gosesh struct fields (lines 14-27)
// Rename and add:
type Gosesh struct {
    // ... existing fields ...
    sessionIdleTimeout      time.Duration  // was: sessionActiveDuration
    sessionMaxLifetime      time.Duration  // was: sessionIdleDuration
    sessionRefreshThreshold time.Duration  // NEW
    // ...
}
```

```go
// New() defaults (lines 50-72)
// Update to:
sessionIdleTimeout:      1 * time.Hour,
sessionMaxLifetime:      24 * time.Hour,
sessionRefreshThreshold: 10 * time.Minute,
```

```go
// Option functions (lines 109-121)
// Replace with:
func WithSessionIdleTimeout(d time.Duration) func(*Gosesh) {
    return func(c *Gosesh) {
        c.sessionIdleTimeout = d
    }
}

func WithSessionMaxLifetime(d time.Duration) func(*Gosesh) {
    return func(c *Gosesh) {
        c.sessionMaxLifetime = d
    }
}

func WithSessionRefreshThreshold(d time.Duration) func(*Gosesh) {
    return func(c *Gosesh) {
        c.sessionRefreshThreshold = d
    }
}
```

```go
// Storer interface (lines 144-157)
// Add ExtendSession:
type Storer interface {
    UpsertUser(ctx context.Context, authProviderID Identifier) (userID Identifier, err error)
    CreateSession(ctx context.Context, userID Identifier, idleDeadline, absoluteDeadline time.Time) (Session, error)
    ExtendSession(ctx context.Context, sessionID string, newIdleDeadline time.Time) error  // NEW
    GetSession(ctx context.Context, sessionID string) (Session, error)
    DeleteSession(ctx context.Context, sessionID string) error
    DeleteUserSessions(ctx context.Context, userID Identifier) (int, error)
}
```

```go
// Session interface (lines 159-169)
// Rename methods:
type Session interface {
    ID() Identifier
    UserID() Identifier
    IdleDeadline() time.Time     // was: IdleAt()
    AbsoluteDeadline() time.Time // was: ExpireAt()
}
```

### Gate: GREEN

- [ ] Gosesh struct has new field names
- [ ] New() sets correct defaults
- [ ] Three new With* option functions exist
- [ ] Storer interface includes ExtendSession
- [ ] Session interface uses IdleDeadline/AbsoluteDeadline
- [ ] Code compiles (will fail until Phase 02 completes)

---

## REFACTOR: Quality

**Focus:** Ensure naming is clear and consistent.

- Verify doc comments explain semantics clearly
- Ensure parameter names in CreateSession match new naming (idleDeadline, absoluteDeadline)

### Gate: REFACTOR

- [ ] Doc comments updated for new semantics
- [ ] Parameter names are consistent

---

## Phase Complete

When all gates pass:

1. Update this file's status to **Complete**
2. Update index.md status table
3. Proceed to Phase 02

---

**Previous:** First phase
**Next:** [Phase 02: Memory Store](02-memory-store.md)
