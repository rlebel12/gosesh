# Phase 02: Memory Store Implementation

**Depends on:** Phase 01
**Status:** Pending

---

## RED: Write Tests

**Objective:** Define test cases for ExtendSession and updated method names

**Files:**
- `contract_test.go` (add ExtendSession contract test)

**Test Cases for ExtendSession:**

| Case Name | Setup | Input | Expected | Notes |
|-----------|-------|-------|----------|-------|
| `extend_existing_session` | Create session | Valid sessionID, new deadline | nil error, deadline updated | Happy path |
| `extend_nonexistent_session` | No session | Invalid sessionID | error | Session not found |
| `extend_updates_deadline` | Create session | New deadline | GetSession returns new deadline | Verify persistence |

**Method Rename Verification:**

| Case | Old Method | New Method | Notes |
|------|------------|------------|-------|
| `session_idle_deadline` | `IdleAt()` | `IdleDeadline()` | Compile-time check |
| `session_absolute_deadline` | `ExpireAt()` | `AbsoluteDeadline()` | Compile-time check |

### Gate: RED

- [ ] ExtendSession test cases defined in contract_test.go
- [ ] Tests reference new method names (IdleDeadline, AbsoluteDeadline)
- [ ] Tests fail (ExtendSession not yet implemented)

---

## GREEN: Implement

**Objective:** Update MemoryStore to implement new interfaces

**Files:**
- `store.go`

**Implementation Guidance:**

```go
// MemoryStoreSession struct (lines 28-33)
// Rename fields:
type MemoryStoreSession struct {
    id               MemoryStoreIdentifier
    userID           Identifier
    idleDeadline     time.Time  // was: idleAt
    absoluteDeadline time.Time  // was: expireAt
}
```

```go
// CreateSession (lines 47-60)
// Update field assignments:
func (ms *MemoryStore) CreateSession(ctx context.Context, userID Identifier, idleDeadline, absoluteDeadline time.Time) (Session, error) {
    ms.mu.Lock()
    defer ms.mu.Unlock()

    ms.sequenceID++
    s := &MemoryStoreSession{
        id:               ms.sequenceID,
        userID:           userID,
        idleDeadline:     idleDeadline,
        absoluteDeadline: absoluteDeadline,
    }
    ms.sessions[s.ID().String()] = s
    return s, nil
}
```

```go
// NEW: ExtendSession
// Add after DeleteUserSessions:
func (ms *MemoryStore) ExtendSession(ctx context.Context, sessionID string, newIdleDeadline time.Time) error {
    ms.mu.Lock()
    defer ms.mu.Unlock()

    s, ok := ms.sessions[sessionID]
    if !ok {
        return errors.New("session not found")
    }
    s.idleDeadline = newIdleDeadline
    return nil
}
```

```go
// Rename accessor methods (lines 107-113):
func (s MemoryStoreSession) IdleDeadline() time.Time {  // was: IdleAt
    return s.idleDeadline
}

func (s MemoryStoreSession) AbsoluteDeadline() time.Time {  // was: ExpireAt
    return s.absoluteDeadline
}
```

### Gate: GREEN

- [ ] MemoryStoreSession has renamed fields
- [ ] CreateSession uses new field names
- [ ] ExtendSession implemented and working
- [ ] Accessor methods renamed
- [ ] Interface compliance check passes: `var _ Storer = (*MemoryStore)(nil)`
- [ ] Interface compliance check passes: `var _ Session = (*MemoryStoreSession)(nil)`

---

## REFACTOR: Quality

**Focus:** Ensure consistency and clarity.

- ExtendSession follows same locking pattern as other methods
- Error message matches style of other methods

### Gate: REFACTOR

- [ ] Pre-commit passes: `make pc-dirty` (or equivalent)
- [ ] No new linting warnings
- [ ] Error handling consistent with existing methods

---

## Phase Complete

When all gates pass:

1. Update this file's status to **Complete**
2. Update index.md status table
3. Proceed to Phase 03

---

**Previous:** [Phase 01: Interfaces](01-interfaces.md)
**Next:** [Phase 03: Core Logic](03-core-logic.md)
