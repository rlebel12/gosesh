# Phase 04: Handlers and Middleware

**Depends on:** Phase 03
**Phase Type:** Standard
**Status:** Complete

---

## RED: Write Tests

**Objective:** Test that handlers generate and hash session IDs correctly, middleware hashes before store lookup, raw IDs are available in context, and ActivityTracker uses HashedSessionID.

**Files:**

- `handlers_test.go` (update existing tests)
- `middleware_test.go` (update existing tests)
- `activity_tracker_test.go` (update existing tests)
- `middleware_credential_source_test.go` (update existing tests)
- `gosesh_test.go` (new round-trip integration tests)

**Test Cases:**

### OAuth2Callback Handler Tests

**Discrete Tests:**

- **Test OAuth2Callback generates session ID via gosesh.idGenerator**: Inject a custom generator that returns a known RawSessionID. Verify the store receives the hashed version.
- **Test OAuth2Callback hashes before calling store.CreateSession**: Verify `store.CreateSession` is called with `HashedSessionID`, not `RawSessionID`.
- **Test OAuth2Callback passes raw ID to WriteSession**: Verify `credentialSource.WriteSession` receives the `RawSessionID`, not the hashed ID.
- **Test OAuth2Callback generator error returns 500**: Inject a generator that errors, verify done handler receives error.

### ExchangeExternalToken Handler Tests

**Discrete Tests:**

- **Test ExchangeExternalToken generates session ID via gosesh.idGenerator**: Inject a custom generator, verify store receives hashed version.
- **Test ExchangeExternalToken returns raw ID in JSON response**: Verify `session_id` field in response body is the raw ID string, not the hashed ID.
- **Test ExchangeExternalToken hashes before calling store.CreateSession**: Same pattern as OAuth2Callback.
- **Test ExchangeExternalToken generator error**: Inject failing generator, verify error response.

### Logout Handler Tests

**Discrete Tests:**

- **Test Logout calls store.DeleteSession with session.ID()**: Verify `session.ID()` (which returns `HashedSessionID` directly) is passed to `DeleteSession`. No type conversion needed.
- **Test Logout calls store.DeleteUserSessions unchanged**: UserID-based deletion is not affected by session ID changes.

### authenticate Middleware Tests

**Discrete Tests:**

- **Test authenticate reads raw ID from credential source and hashes before store lookup**: Set up a credential source returning `RawSessionID("raw-abc")`. Verify `store.GetSession` is called with `HashedSessionID(sha256("raw-abc"))`.
- **Test authenticate stores raw ID in request context**: After authentication, verify `RawSessionIDFromContext(r.Context())` returns the original raw ID.
- **Test authenticate with empty raw ID skips store lookup**: Credential source returns empty RawSessionID, no store call made.
- **Test authenticate with invalid session clears credential**: Store returns error, credential source ClearSession is called.

### AuthenticateAndRefresh Middleware Tests

**Discrete Tests:**

- **Test AuthenticateAndRefresh passes hashed ID to ExtendSession**: Verify `store.ExtendSession` receives `HashedSessionID`.
- **Test AuthenticateAndRefresh passes raw ID to WriteSession**: After extending, verify `credentialSource.WriteSession` receives the `RawSessionID` from context (not from session.ID()).

### ActivityTracker Tests

**Discrete Tests:**

- **Test RecordActivity accepts HashedSessionID**: Verify `RecordActivity(HashedSessionID("hash"), time)` records correctly.
- **Test flush sends map[HashedSessionID]time.Time to store**: Verify `BatchRecordActivity` receives correctly typed map.
- **Test authenticate passes hashed ID to RecordActivity**: Set up credential source returning `RawSessionID("raw-xyz")`. Verify activity tracker's `RecordActivity` is called with `HashedSessionID(sha256("raw-xyz"))`, not the raw ID.

### Device Code Handler Tests

**Discrete Tests:**

- **Test DeviceCodeAuthorizeCallback generates session ID and hashes for store**: Same generate-hash-store pattern as OAuth2Callback.
- **Test DeviceCodeAuthorizeCallback passes rawID to CompleteDeviceCode**: The device code store receives the `RawSessionID` (not hashed), so the poll endpoint can return it to the device client as a Bearer token. This prevents double-hashing when the device client sends the token back through middleware.

### Round-Trip Integration Tests

**Parameterized Tests** (table format):

| Case | Generator | Hasher | Flow | Assertion | Notes |
|------|-----------|--------|------|-----------|-------|
| `default_sha256_cookie` | default | default SHA-256 | Generate -> hash -> store -> read cookie -> hash -> lookup | Lookup succeeds, returns correct session | Full cookie round-trip |
| `default_sha256_header` | default | default SHA-256 | Generate -> hash -> store -> read header -> hash -> lookup | Lookup succeeds, returns correct session | Full header round-trip |
| `hmac_sha256_cookie` | default | HMAC-SHA256 | Generate -> hash -> store -> read cookie -> hash -> lookup | Lookup succeeds, returns correct session | HMAC variant |
| `custom_generator` | returns `RawSessionID("custom-id")` | default SHA-256 | Custom ID -> hash -> store -> set in cookie -> read -> hash -> lookup | Lookup succeeds | Custom generator override |

**Assertions:**

- Handlers never pass raw session IDs to any store method
- Handlers always pass raw session IDs (not hashed) to credential source WriteSession
- ExchangeExternalToken JSON response contains raw ID, not hashed ID
- ActivityTracker records use hashed IDs
- Context contains raw ID after authentication

**Edge Cases:**

- Generator failure propagates as error through handler done func
- Session created with one Gosesh instance can be looked up by another with the same hasher

### Gate: RED

- [x] Test file created with all enumerated test cases
- [x] All tests FAIL (implementation does not exist yet)
- [x] Test coverage includes happy path and all edge cases

---

## GREEN: Implement

**Objective:** Update all handlers, middleware, and activity tracker to use the new generate-hash-store flow.

**Files:**

- `handlers.go` (OAuth2Callback, ExchangeExternalToken, Logout)
- `handlers_device.go` (DeviceCodeAuthorizeCallback)
- `middleware.go` (authenticate, AuthenticateAndRefresh)
- `activity_tracker.go` (RecordActivity, flush, pending map type)

**Implementation Guidance:**

```go
// handlers.go - OAuth2Callback updates
func (gs *Gosesh) OAuth2Callback(...) http.HandlerFunc {
    """Generate raw ID, hash, pass hashed to store, raw to credential source.

    New flow after UpsertUser succeeds:
    1. rawID, err := gs.idGenerator()
       - If err -> done(w, r, fmt.Errorf("generate session ID: %w", err))
    2. hashedID := gs.idHasher(rawID)
    3. session, err := gs.store.CreateSession(ctx, hashedID, id, idle, absolute)
    4. gs.credentialSource.WriteSession(w, rawID, session)

    Critical: WriteSession gets rawID, store gets hashedID.
    """
}
```

```go
// handlers.go - ExchangeExternalToken updates
func (gs *Gosesh) ExchangeExternalToken(...) http.HandlerFunc {
    """Same generate-hash-store pattern. Return raw ID in JSON.

    New flow after UpsertUser succeeds:
    1. rawID, err := gs.idGenerator()
    2. hashedID := gs.idHasher(rawID)
    3. session, err := gs.store.CreateSession(ctx, hashedID, userID, idle, absolute)
    4. Response JSON: SessionID = string(rawID) (NOT session.ID())
    5. No WriteSession call needed (JSON response handles it)
    """
}
```

```go
// handlers.go - Logout updates
func (gs *Gosesh) Logout(...) http.HandlerFunc {
    """DeleteSession uses session.ID() directly - no conversion needed.

    Changes:
    1. store.DeleteSession(ctx, session.ID())
       - session.ID() returns HashedSessionID directly (updated Session interface)
       - No type conversion needed
    """
}
```

```go
// middleware.go - authenticate updates
func (gs *Gosesh) authenticate(w http.ResponseWriter, r *http.Request) *http.Request {
    """Read raw ID, hash, lookup in store, store raw ID in context.

    New flow:
    1. rawID := gs.credentialSource.ReadSessionID(r)
       - Returns RawSessionID (may be empty)
    2. If rawID == "" -> return r (no session)
    3. hashedID := gs.idHasher(rawID)
    4. session, err := gs.store.GetSession(ctx, hashedID)
    5. If activity tracker: gs.activityTracker.RecordActivity(hashedID, now)
    6. Store raw ID in context: context.WithValue(ctx, rawSessionIDKey, rawID)
    7. Store session in context (existing behavior)
    """
}
```

```go
// middleware.go - AuthenticateAndRefresh updates
func (gs *Gosesh) AuthenticateAndRefresh(...) http.Handler {
    """Use hashed ID for store, raw ID for WriteSession.

    Changes:
    1. store.ExtendSession: pass session.ID() directly (returns HashedSessionID)
    2. credentialSource.WriteSession: get rawID from RawSessionIDFromContext(r.Context())
       - Pass rawID to WriteSession(w, rawID, session)
       - If rawID not in context (shouldn't happen), log warning and skip write
    """
}
```

```go
// activity_tracker.go updates
type ActivityTracker struct {
    """Change pending map type.

    Changes:
    1. pending field: map[string]time.Time -> map[HashedSessionID]time.Time
    2. RecordActivity signature: sessionID string -> hashedID HashedSessionID
    3. flush: batch map type matches new pending type
    """
}
```

```go
// handlers_device.go - DeviceCodeAuthorizeCallback updates
func (gs *Gosesh) DeviceCodeAuthorizeCallback(...) http.HandlerFunc {
    """Same generate-hash-store pattern as OAuth2Callback.

    New flow after UpsertUser succeeds:
    1. rawID, err := gs.idGenerator()
    2. hashedID := gs.idHasher(rawID)
    3. session, err := gs.store.CreateSession(ctx, hashedID, userID, idle, absolute)
    4. store.CompleteDeviceCode(ctx, deviceCode, rawID)
       - Pass rawID (NOT session.ID()) so the poll endpoint returns it to the device
       - The device client sends this rawID as a Bearer token
       - Middleware hashes it once for store lookup (preventing double-hash)

    Note: No WriteSession needed here (device flow returns session via poll endpoint).
    DeviceCodeBegin and DeviceCodePoll are unchanged - they don't create sessions.
    """
}
```

### Gate: GREEN

- [x] All tests from RED phase now PASS
- [x] Test command: `go test ./...` (all tests including e2e if applicable)
- [x] Implementation follows pseudocode logic flow

---

## REFACTOR: Quality

**Focus:** Code quality improvements, not new functionality.

**Review Areas:**

- **Duplication**: The generate-hash-store pattern repeats in OAuth2Callback, ExchangeExternalToken, and DeviceCodeAuthorizeCallback. If the pattern is identical in all three handlers after the GREEN phase, extract a helper like `(gs *Gosesh) generateAndHashSessionID() (RawSessionID, HashedSessionID, error)` during this REFACTOR phase. Do not extract during GREEN — implement inline first to keep the flow clear.
- **Naming**: Ensure `rawID` and `hashedID` variable names are used consistently across all handlers and middleware
- **Simplification**: Remove any leftover `session.ID().String()` patterns where `HashedSessionID` can be used directly
- **Error Messages**: All new error wrapping uses concise verb+object format (e.g., "generate session ID: %w")
- **Readability**: Add comments in authenticate explaining the raw->hash->lookup flow
- **Context Safety**: Verify RawSessionIDFromContext never panics, always returns ("", false) for missing values

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
3. All phases complete - run full test suite as final verification

---

**Previous:** [Phase 03](03-store-and-credential-sources.md)
**Next:** Final phase
