# Phase 02: Interface Updates and Test Infrastructure

**Depends on:** Phase 01
**Phase Type:** Standard
**Status:** Pending

---

## RED: Write Tests

**Objective:** Update all interface definitions to use typed session IDs, then update fakes, contracts, and test helpers to match.

> **Note:** This phase updates interfaces, fakes, and contracts atomically — they cannot compile independently. The RED gate means: updated interfaces compile, updated fakes compile, contract tests run but fail because `MemoryStore` (production implementation) does not yet match the new signatures. `MemoryStore` will temporarily not compile until Phase 03 fixes it. Tests in this phase target the fakes/contracts only.

**Files:**

- `fake_test.go` (update existing fakes)
- `contract_test.go` (update existing contracts)
- `credential_source_contract_test.go` (update existing contract)
- `device_code_store_contract_test.go` (update existing contract)

**Test Cases:**

### Updated Storer Contract Tests

The existing `StorerContract` tests must be updated to reflect the new `CreateSession` signature (`hashedID HashedSessionID` as first param after `ctx`) and all session ID parameters becoming `HashedSessionID`. The contract tests themselves verify behavior, so the changes are mechanical signature updates.

**Discrete Tests:**

- **Test CreateSession accepts HashedSessionID**: Contract test for `CreateSession(ctx, hashedID, userID, idleDeadline, absoluteDeadline)` creates and retrieves session
- **Test GetSession accepts HashedSessionID**: Contract test for `GetSession(ctx, hashedID)` returns correct session
- **Test DeleteSession accepts HashedSessionID**: Contract test for `DeleteSession(ctx, hashedID)` removes session
- **Test ExtendSession accepts HashedSessionID**: Contract test for `ExtendSession(ctx, hashedID, newIdleDeadline)` updates deadline

### Updated CredentialSource Contract Tests

The existing `CredentialSourceContract` tests must be updated to reflect that `ReadSessionID` returns `RawSessionID` and `WriteSession` accepts `RawSessionID`.

**Discrete Tests:**

- **Test WriteSession accepts RawSessionID parameter**: Contract test for `WriteSession(w, rawID, session)` sets credential correctly
- **Test ReadSessionID returns RawSessionID**: Contract test for `ReadSessionID(r)` returns typed `RawSessionID`
- **Test write-then-read round-trip with new types**: Write with `RawSessionID`, read back, verify type and value match

### Updated ActivityRecorder Contract Tests

The existing `ActivityRecorderContract` tests must be updated to use `map[HashedSessionID]time.Time`.

**Discrete Tests:**

- **Test BatchRecordActivity accepts HashedSessionID keys**: Contract test for `BatchRecordActivity(ctx, map[HashedSessionID]time.Time)` updates sessions correctly

### Updated DeviceCodeStore Contract Tests

The existing `DeviceCodeStoreContract` tests must be updated for `CompleteDeviceCode` accepting `RawSessionID` instead of `Identifier`.

**Discrete Tests:**

- **Test CompleteDeviceCode accepts RawSessionID**: Contract test for `CompleteDeviceCode(ctx, deviceCode, RawSessionID("raw-id"))` completes successfully
- **Test completed entry stores RawSessionID**: After completion, `GetDeviceCode` returns entry with `SessionID` as `RawSessionID`

### Updated erroringStore Fake

All methods on `erroringStore` must match new interface signatures.

**Assertions:**

- All interface compliance checks (`var _ Storer = ...`, etc.) compile successfully
- Contract tests pass with updated signatures
- Fake implementations work with new types

**Edge Cases:**

- Empty `HashedSessionID` in store operations
- Empty `RawSessionID` in credential source operations

### Gate: RED

- [ ] Test file created with all enumerated test cases
- [ ] All tests FAIL (implementation does not exist yet)
- [ ] Test coverage includes happy path and all edge cases

---

## GREEN: Implement

**Objective:** Update interface definitions and all test infrastructure to use typed session IDs.

**Files:**

- `gosesh.go` (interface definitions: `Session`, `Storer`, `CredentialSource`, `ActivityRecorder`)
- `device_code.go` (interface definition: `DeviceCodeStore`, type: `DeviceCodeEntry`)
- `fake_test.go` (update `erroringStore`, `erroringDeviceCodeStore`, `FakeSession` usage patterns)
- `contract_test.go` (update `StorerContract`, `ActivityRecorderContract`)
- `credential_source_contract_test.go` (update `CredentialSourceContract`)
- `device_code_store_contract_test.go` (update `DeviceCodeStoreContract`)

**Implementation Guidance:**

```go
// Updated Session interface in gosesh.go
type Session interface {
    """Update ID() return type from Identifier to HashedSessionID.

    Changes:
    1. ID() Identifier -> ID() HashedSessionID
    2. This is a breaking change - all Session implementations must return HashedSessionID
    3. The ID is what was passed to CreateSession (the hashed value)
    4. Other methods (UserID, IdleDeadline, AbsoluteDeadline, LastActivityAt) unchanged
    """
}
```

```go
// Updated Storer interface in gosesh.go
type Storer interface {
    """Update all session ID parameters to use HashedSessionID.

    Changes:
    1. CreateSession: add hashedID HashedSessionID as second param (after ctx)
    2. GetSession: sessionID string -> hashedID HashedSessionID
    3. ExtendSession: sessionID string -> hashedID HashedSessionID
    4. DeleteSession: sessionID string -> hashedID HashedSessionID
    5. DeleteUserSessions: unchanged (uses userID, not session ID)
    """
}
```

```go
// Updated CredentialSource interface in gosesh.go
type CredentialSource interface {
    """Update read/write methods to use RawSessionID.

    Changes:
    1. ReadSessionID: return type string -> RawSessionID
    2. WriteSession: add rawID RawSessionID param, keep session Session
    3. Name(), ClearSession(), CanWrite(), SessionConfig(): unchanged
    """
}
```

```go
// Updated ActivityRecorder interface in gosesh.go
type ActivityRecorder interface {
    """Update map key type.

    Changes:
    1. BatchRecordActivity: map[string]time.Time -> map[HashedSessionID]time.Time
    """
}
```

```go
// Updated DeviceCodeStore interface in device_code.go
type DeviceCodeStore interface {
    """Update CompleteDeviceCode to accept RawSessionID.

    Changes:
    1. CompleteDeviceCode: sessionID Identifier -> rawSessionID RawSessionID
    2. Other methods unchanged
    """
}

// Updated DeviceCodeEntry in device_code.go
type DeviceCodeEntry struct {
    """Update SessionID field type.

    Changes:
    1. SessionID Identifier -> SessionID RawSessionID
    2. This stores the raw ID so the poll endpoint returns it to the device client
    3. The device client uses this raw ID as a Bearer token
    """
}
```

```go
// Updated erroringStore in fake_test.go
// All method signatures must match new Storer interface:
//   CreateSession(ctx, hashedID HashedSessionID, userID, idle, absolute) -> (Session, error)
//   GetSession(ctx, hashedID HashedSessionID) -> (Session, error)
//   ExtendSession(ctx, hashedID HashedSessionID, newIdle) -> error
//   DeleteSession(ctx, hashedID HashedSessionID) -> error
//   BatchRecordActivity(ctx, map[HashedSessionID]time.Time) -> (int, error)
```

```go
// Updated StorerContract in contract_test.go
// All test cases that call store methods must pass HashedSessionID values.
// CreateSession calls must pass a HashedSessionID as the second argument.
// GetSession, DeleteSession, ExtendSession calls must pass HashedSessionID.
// Use HashedSessionID("test-hash-id") for test values.
```

```go
// Updated CredentialSourceContract in credential_source_contract_test.go
// WriteSession calls must pass RawSessionID as second argument.
// ReadSessionID assertions must check RawSessionID type.
```

```go
// Updated DeviceCodeStoreContract in device_code_store_contract_test.go
// CompleteDeviceCode calls must pass RawSessionID instead of Identifier.
// GetDeviceCode assertions must check SessionID is RawSessionID type.
```

```go
// Updated erroringDeviceCodeStore in fake_test.go
// CompleteDeviceCode signature: sessionID Identifier -> rawSessionID RawSessionID
```

### Gate: GREEN

- [ ] All tests from RED phase now PASS
- [ ] Test command: `go test ./...` (all tests, since interface changes are pervasive)
- [ ] Implementation follows pseudocode logic flow

---

## REFACTOR: Quality

**Focus:** Code quality improvements, not new functionality.

**Review Areas:**

- **Duplication**: Contract tests may have repeated HashedSessionID creation; extract helper if needed
- **Naming**: Ensure test variable names reflect new types (e.g., `hashedID` not `sessionID` for store calls)
- **Simplification**: Verify fakes are minimal and only implement what is needed
- **Error Messages**: Ensure contract test failure messages are descriptive
- **Readability**: Interface method signatures are well-documented with godoc

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

**Previous:** [Phase 01](01-core-types-and-generators.md)
**Next:** [Phase 03](03-store-and-credential-sources.md)
