# Phase 03: Store and Credential Source Implementations

**Depends on:** Phase 02
**Phase Type:** Standard
**Status:** Complete

---

## RED: Write Tests

**Objective:** Update tests for MemoryStore, CookieCredentialSource, HeaderCredentialSource, and CompositeCredentialSource to work with new typed session IDs.

**Files:**

- `store_test.go` (update existing MemoryStore tests)
- `cookie_credential_source_test.go` (update existing tests)
- `header_credential_source_test.go` (update existing tests)
- `composite_credential_source_test.go` (update existing tests)
- `device_code_memory_store_test.go` (update existing tests)
- `example_test.go` (update `MemoryStoreIdentifier` references)

**Test Cases:**

### MemoryStore Tests

**Parameterized Tests** (table format):

| Case | HashedSessionID | UserID | Assertion | Notes |
|------|----------------|--------|-----------|-------|
| `create_and_get` | `HashedSessionID("abc123hash")` | `StringIdentifier("user-1")` | Created session retrieved by same hashed ID | Happy path round-trip |
| `delete_by_hashed_id` | `HashedSessionID("to-delete")` | `StringIdentifier("user-1")` | Deleted session not found on subsequent get | Deletion works with typed IDs |
| `extend_by_hashed_id` | `HashedSessionID("to-extend")` | `StringIdentifier("user-1")` | Extended session has updated idle deadline | Extension works with typed IDs |
| `get_nonexistent` | `HashedSessionID("nonexistent")` | N/A | Error returned | Not found case |

**Discrete Tests:**

- **Test MemoryStore no longer has generateSessionID**: Verify the function is removed (compilation will enforce this)
- **Test MemoryStore session ID comes from caller**: CreateSession stores the HashedSessionID passed in, not a generated one. Retrieve it and verify ID matches what was passed.
- **Test MemoryStore BatchRecordActivity with HashedSessionID keys**: Pass `map[HashedSessionID]time.Time`, verify sessions are updated
- **Test MemoryStore contract still passes**: Run `StorerContract` and `ActivityRecorderContract` with updated MemoryStore
- **Test MemoryStoreSession.ID() returns HashedSessionID**: Verify that the session returned by `CreateSession` has `ID()` returning the same `HashedSessionID` that was passed in

### CookieCredentialSource Tests

**Discrete Tests:**

- **Test ReadSessionID returns RawSessionID type**: Read from cookie, verify return is `RawSessionID`
- **Test WriteSession accepts RawSessionID**: Pass `RawSessionID("test-raw-id")` and session to WriteSession, verify cookie contains base64-encoded raw ID
- **Test write-then-read round-trip with RawSessionID**: Write raw ID "my-raw-session", read back, verify `RawSessionID("my-raw-session")` returned
- **Test WriteSession uses rawID not session.ID()**: WriteSession must base64-encode the rawID parameter, not session.ID() (which is now hashed)

### HeaderCredentialSource Tests

**Discrete Tests:**

- **Test ReadSessionID returns RawSessionID type**: Read from Authorization header, verify return is `RawSessionID`
- **Test WriteSession signature accepts RawSessionID**: WriteSession is a no-op but must accept the new parameter
- **Test round-trip with Bearer token**: Set `Authorization: Bearer <token>`, ReadSessionID returns `RawSessionID(<token>)`

### CompositeCredentialSource Tests

**Discrete Tests:**

- **Test ReadSessionID returns RawSessionID type**: First source that returns non-empty wins, return type is `RawSessionID`
- **Test WriteSession passes RawSessionID to all writable sources**: Verify rawID is forwarded to each sub-source's WriteSession
- **Test contract still passes**: Run `CredentialSourceContract` with CompositeCredentialSource

### MemoryDeviceCodeStore Tests

**Discrete Tests:**

- **Test MemoryDeviceCodeStore CompleteDeviceCode accepts RawSessionID**: Pass `RawSessionID("raw-id")`, verify entry stores it
- **Test MemoryDeviceCodeStore contract still passes**: Run `DeviceCodeStoreContract` with updated MemoryDeviceCodeStore

### example_test.go Updates

**Discrete Tests:**

- **Test example_test.go compiles**: Update `MemoryStoreIdentifier` references to use `StringIdentifier` or appropriate replacement if `MemoryStoreIdentifier` is removed

**Assertions:**

- MemoryStore stores sessions keyed by the HashedSessionID string, not a generated ID
- CookieCredentialSource base64-encodes `rawID` (not `session.ID()`) for the cookie value
- HeaderCredentialSource ReadSessionID returns `RawSessionID`
- CompositeCredentialSource delegates correctly with new types

**Edge Cases:**

- Empty HashedSessionID passed to MemoryStore CreateSession
- Empty RawSessionID passed to CookieCredentialSource WriteSession

### Gate: RED

- [x] Test file created with all enumerated test cases
- [x] All tests FAIL (implementation does not exist yet)
- [x] Test coverage includes happy path and all edge cases

---

## GREEN: Implement

**Objective:** Update all store and credential source implementations to work with typed session IDs.

**Files:**

- `store.go` (MemoryStore, MemoryStoreSession)
- `cookie_credential_source.go`
- `header_credential_source.go`
- `composite_credential_source.go`
- `device_code_memory_store.go` (MemoryDeviceCodeStore)
- `example_test.go` (update MemoryStoreIdentifier references)

**Implementation Guidance:**

```go
// store.go - MemoryStore updates
// 1. Delete generateSessionID() function entirely
// 2. Change sessions map type: map[string]*MemoryStoreSession -> map[HashedSessionID]*MemoryStoreSession
// 3. MemoryStoreSession.id field type: MemoryStoreIdentifier -> HashedSessionID
// 4. Remove MemoryStoreIdentifier type (or keep for backward compat, but README says replace)

func (ms *MemoryStore) CreateSession(ctx context.Context, hashedID HashedSessionID, userID Identifier, idleDeadline, absoluteDeadline time.Time) (Session, error) {
    """Store session keyed by hashedID.

    Implementation approach:
    1. Lock mutex
    2. Create MemoryStoreSession with hashedID as its ID
    3. Store in ms.sessions[hashedID]
    4. Return session

    Note: No ID generation - caller provides the hashed ID.
    """
}

func (ms *MemoryStore) GetSession(ctx context.Context, hashedID HashedSessionID) (Session, error) {
    """Lookup by HashedSessionID.

    Implementation approach:
    1. RLock mutex
    2. Lookup ms.sessions[hashedID]
    3. Return session or error
    """
}

// ExtendSession, DeleteSession: same pattern - accept HashedSessionID
// DeleteUserSessions: unchanged (iterates by userID)
// BatchRecordActivity: map key changes to HashedSessionID
```

```go
// store.go - MemoryStoreSession.ID() update
func (s *MemoryStoreSession) ID() HashedSessionID {
    """Return HashedSessionID to implement updated Session interface.

    Implementation approach:
    1. Return s.id directly (already HashedSessionID type after field change)
    """
}
```

```go
// device_code_memory_store.go - CompleteDeviceCode update
func (m *MemoryDeviceCodeStore) CompleteDeviceCode(ctx context.Context, deviceCode string, rawSessionID RawSessionID) error {
    """Accept RawSessionID instead of Identifier.

    Implementation approach:
    1. Same logic as before, but store rawSessionID in entry.SessionID
    2. entry.SessionID field is now RawSessionID type
    """
}
```

```go
// cookie_credential_source.go updates

func (c *CookieCredentialSource) ReadSessionID(r *http.Request) RawSessionID {
    """Return RawSessionID instead of string.

    Implementation approach:
    1. Same cookie reading and base64 decoding logic
    2. Return RawSessionID(decoded) instead of string(decoded)
    3. Return RawSessionID("") for empty/error cases
    """
}

func (c *CookieCredentialSource) WriteSession(w http.ResponseWriter, rawID RawSessionID, session Session) error {
    """Use rawID parameter for cookie value.

    Implementation approach:
    1. Base64 encode string(rawID) (NOT session.ID().String())
    2. Set cookie with encoded value
    3. Cookie expiry from session.AbsoluteDeadline()

    Critical: The rawID is what goes in the cookie. session.ID() is hashed
    and must NOT be stored in the cookie.
    """
}
```

```go
// header_credential_source.go updates

func (h *HeaderCredentialSource) ReadSessionID(r *http.Request) RawSessionID {
    """Return RawSessionID instead of string.

    Implementation approach:
    1. Same header reading and scheme validation logic
    2. Return RawSessionID(token) instead of string
    3. Return RawSessionID("") for empty/error cases
    """
}

func (h *HeaderCredentialSource) WriteSession(w http.ResponseWriter, rawID RawSessionID, session Session) error {
    """Accept new parameter, remain a no-op.

    Implementation approach:
    1. No-op, return nil (header sources cannot write)
    """
}
```

```go
// composite_credential_source.go updates

func (c *CompositeCredentialSource) ReadSessionID(r *http.Request) RawSessionID {
    """Return RawSessionID from first non-empty source.

    Implementation approach:
    1. Iterate sources, call ReadSessionID
    2. Return first non-empty RawSessionID
    3. Return RawSessionID("") if all empty
    """
}

func (c *CompositeCredentialSource) WriteSession(w http.ResponseWriter, rawID RawSessionID, session Session) error {
    """Forward rawID to all writable sub-sources.

    Implementation approach:
    1. Iterate sources
    2. If source.CanWrite(), call source.WriteSession(w, rawID, session)
    3. Fail fast on first error
    """
}
```

### Gate: GREEN

- [x] All tests from RED phase now PASS
- [x] Test command: `go test ./...` (all tests)
- [x] Implementation follows pseudocode logic flow

---

## REFACTOR: Quality

**Focus:** Code quality improvements, not new functionality.

**Review Areas:**

- **Duplication**: MemoryStore methods share similar lock/lookup patterns; acceptable for clarity
- **Naming**: `hashedID` parameter name used consistently across MemoryStore methods
- **Simplification**: Remove any dead code from MemoryStoreIdentifier if fully replaced
- **Error Messages**: Store "session not found" errors remain clear
- **Readability**: CookieCredentialSource WriteSession comment clearly states it uses rawID not session.ID()

### Gate: REFACTOR

- [x] Reviewed for code duplication and extracted common patterns
- [x] Variable and function names are clear and descriptive
- [x] Complex logic simplified where possible
- [x] Error messages are helpful and actionable

---

## Phase Complete

When all gates pass:

1. Update this file's status to **Complete**
2. Update index.md status table
3. Proceed to next dependent phase

---

**Previous:** [Phase 02](02-interface-updates-and-test-infra.md)
**Next:** [Phase 04](04-handlers-and-middleware.md)
