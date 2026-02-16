# Phase 02: Interface Updates and Test Infrastructure

## Summary

Phase 02 updated all core interfaces to use the new RawSessionID and HashedSessionID types. The Session interface now returns HashedSessionID from ID(). The Storer interface accepts HashedSessionID parameters. The CredentialSource interface reads/writes RawSessionID. Production code was updated with stub implementations to maintain compilation while test infrastructure was updated.

**Status:** Core interface work complete. Test file mechanical updates in progress (see Issues section).

## Files

**Interface Definitions:**
- gosesh.go - Updated Session, Storer, CredentialSource, ActivityRecorder interfaces
- device_code.go - Updated DeviceCodeStore interface and DeviceCodeEntry.SessionID type

**Test Infrastructure:**
- fake_test.go - Updated FakeSession, erroringStore, erroringDeviceCodeStore for new signatures
- contract_test.go - Updated SessionContract, StorerContract, ActivityRecorderContract
- credential_source_contract_test.go - Updated CredentialSourceContract
- device_code_store_contract_test.go - Updated DeviceCodeStoreContract

**Production Code (Stub Implementations):**
- store.go - Added stub implementations for new Storer signatures
- device_code_memory_store.go - Updated CompleteDeviceCode signature
- cookie_credential_source.go - Updated ReadSessionID and WriteSession
- header_credential_source.go - Updated ReadSessionID and WriteSession
- composite_credential_source.go - Updated ReadSessionID and WriteSession
- activity_tracker.go - Updated internal map type to use HashedSessionID
- handlers.go - Added stub HashedSessionID parameters to CreateSession calls
- handlers_device.go - Added stub parameters
- middleware.go - Added stub hashing logic

## Tests

<!-- Test count, what behaviors are covered -->

## Implementation Notes

**Compilation Strategy for RED Phase:**
The phase plan notes that "MemoryStore will temporarily not compile until Phase 03." However, Go's compilation model requires all files in a package to compile together. To achieve the RED gate (tests compile and run but fail), I need to make minimal updates to production code so it compiles, even though the implementations are incomplete/wrong. These will be properly fixed in Phase 03.

Files requiring minimal compilation fixes:
- composite_credential_source.go - update signatures only
- activity_tracker.go - update map type only
- cookie_credential_source.go - update ReadSessionID return type only
- header_credential_source.go - update ReadSessionID return type only
- store.go - add stub methods with panic() to make tests compilable (implementations in Phase 03)
- device_code_memory_store.go - add stub method with panic() to make tests compilable (implementation in Phase 03)
- handlers.go - add temporary HashedSessionID("stub") conversions to compile (will be fixed in Phase 04)
- handlers_device.go - add temporary conversions (will be fixed in Phase 04)

The stub implementations will cause tests to fail (RED gate), but allow test infrastructure to compile and run.

## Issues

**Issue: Go Package Compilation Model**

The phase plan expected that "interfaces, fakes, and contracts compile" while "MemoryStore will temporarily not compile." However, Go's compilation model requires all files in a package to compile together - you cannot have some files compile while others don't within the same package.

Resolution approach needed:
1. Update MemoryStore method signatures to match new interfaces (add HashedSessionID param, change return types)
2. Provide stub implementations that panic() or return errors
3. This allows tests to compile and run
4. Tests will fail (RED gate) because implementations are intentionally wrong
5. Phase 03 will provide proper implementations (GREEN gate)

Status: Interface updates complete. Stub implementations added. Test file updates in progress.

**Completed:**
- All interface definitions updated (Session, Storer, CredentialSource, ActivityRecorder, DeviceCodeStore)
- Test infrastructure updated (FakeSession, erroringStore, all contract tests)
- Production code updated with stub implementations - package compiles
- activity_tracker_test.go partially updated

**Remaining Work:**
Approximately 15-20 test files still have compilation errors due to missing mechanical updates. Common patterns:
1. `store.CreateSession` calls missing HashedSessionID("test-hash") parameter
2. `store.CompleteDeviceCode` calls using StringIdentifier instead of RawSessionID
3. `NewFakeSession` calls using StringIdentifier instead of HashedSessionID
4. Variables created but not used (rawID, hashedID)

These are mechanical sed replacements that don't affect the core phase goal. The interface definitions and test infrastructure (contracts, fakes) are fully updated and represent the RED phase deliverable.

**Recommendation:** Complete remaining test file updates as bulk mechanical work, then proceed to GREEN phase (Phase 03) to implement proper hash generation and storage logic.
