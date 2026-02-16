# Design Summary: Secure Session ID Generation and Hashed Storage

**Status:** Pending Review

## Problem Statement

Currently, gosesh delegates session ID generation to `Storer` implementations (`CreateSession` generates its own ID internally). Session IDs are stored as plain text in the backing store. This creates two problems:

1. **No standardized security guarantees** - each store implementation must independently ensure cryptographically secure ID generation. Implementers may get this wrong.
2. **Database compromise exposes session IDs** - if the backing store is compromised, attackers obtain valid session IDs that can be used directly for session hijacking. Hashing session IDs before storage means a database leak does not yield usable credentials.

## Proposed Solution

Move session ID lifecycle management into gosesh core:

1. **Gosesh generates session IDs** using `crypto/rand` (URL-safe, base64url-encoded, 256 bits of entropy). A functional option allows overriding the generator.
2. **Raw session IDs are set in cookies/tokens** and sent to clients as-is.
3. **Before any store interaction**, gosesh hashes the raw ID (SHA-256 by default). The store only ever sees and stores the hashed ID.
4. **On authentication**, gosesh reads the raw ID from the cookie/header, hashes it, and uses the hash for store lookups.

This is analogous to how passwords are hashed before storage - the store never handles raw credentials.

## Referenced Patterns

| Pattern | Source | Application |
|---------|--------|-------------|
| Dependency Injection | `~/.agent/docs/go/references/dependency-injection.md` | Functional options for ID generator and hasher |
| Error Handling | `~/.agent/docs/go/references/error-handling.md` | Wrapping crypto/rand failures with `fmt.Errorf` |
| Structured Logging | `~/.agent/docs/go/references/structured-logging-slog.md` | Audit logging for session creation with hashed IDs |

## Design Decisions

### Decision 1: Gosesh Owns Session ID Generation

**Context:** Who should generate session IDs - the library or the store?

**Options Considered:**
- **Option A: Store generates (current)** - Each implementation handles its own ID generation. Simple for the library, but inconsistent security guarantees.
- **Option B: Gosesh generates** - Library guarantees cryptographic quality. Store receives a pre-generated hashed ID.

**Decision:** Option B - Gosesh generates session IDs.

**Rationale:** Security-critical operations should have a single, auditable implementation. The library can guarantee 256 bits of entropy from `crypto/rand` regardless of which store backend is used.

**Tradeoffs:** Store implementations lose control over ID format (e.g., UUID vs random string). Mitigated by the generator override option.

### Decision 2: Breaking Change to Storer Interface

**Context:** `CreateSession` currently generates its own ID. Now gosesh passes the hashed ID.

**Options Considered:**
- **Option A: Add `hashedID` parameter to `CreateSession`** - Clean, but breaking change for all implementers.
- **Option B: New method + deprecate old** - Gradual migration, but adds interface surface area.

**Decision:** Option A - Modify `CreateSession` signature directly.

**Rationale:** This is a security improvement that warrants a major version bump. A clean break is better than carrying deprecated methods. All `Storer` methods that accept session IDs will use `HashedSessionID` type for consistency.

**Tradeoffs:** All existing `Storer` implementations must be updated. This is acceptable for a major version release.

### Decision 3: Distinct Types for Raw and Hashed IDs

**Context:** Should raw and hashed session IDs be type-safe?

**Options Considered:**
- **Option A: Both `string`** - Simple API, no type overhead. Risk of accidentally passing raw where hashed is expected.
- **Option B: Named string types** - Compile-time safety prevents mixing up raw and hashed IDs.

**Decision:** Option B - `RawSessionID` and `HashedSessionID` as named `string` types.

**Rationale:** Session ID handling is security-critical. Compile-time prevention of mixing raw and hashed IDs eliminates an entire class of bugs. The types are lightweight (zero runtime overhead).

### Decision 4: SHA-256 Default, HMAC-SHA256 Option

**Context:** What hash algorithm should be used?

**Options Considered:**
- **Option A: SHA-256 only** - Simple, well-understood, sufficient for session ID hashing.
- **Option B: SHA-256 default + HMAC-SHA256 option** - HMAC adds a secret key, providing an additional layer if the hash algorithm alone is considered insufficient.
- **Option C: Fully configurable hash function** - Maximum flexibility, but more complex API.

**Decision:** Option B - Two fixed choices.

**Rationale:** SHA-256 is the right default for most cases (session IDs have high entropy, so rainbow tables are not practical). HMAC-SHA256 adds defense-in-depth for users who want it. A fully configurable hasher adds complexity without clear benefit.

### Decision 5: Gosesh Writes Raw ID Directly to CredentialSource

**Context:** `WriteSession` currently uses `session.ID()` for the cookie value. With hashing, `session.ID()` returns the hashed ID, but cookies need the raw ID.

**Options Considered:**
- **Option A: Pass raw ID to WriteSession** - Gosesh holds the raw ID after generation and passes it explicitly.
- **Option B: Session carries both IDs** - Session interface gains a `RawID()` method.
- **Option C: Write before hashing** - Write cookie before creating session in store.

**Decision:** Option A - Modify `CredentialSource.WriteSession` to accept the raw ID.

**Rationale:** The raw ID is a transient value that gosesh generates and passes through. It should not be stored in the `Session` interface (which represents persisted state). The credential source needs the raw ID and session metadata (expiry), so adding the parameter is natural.

## Component Scope

**In Scope:**
- New types: `RawSessionID`, `HashedSessionID`
- Function types: `SessionIDGenerator`, `SessionIDHasher`
- Default generator (crypto/rand, base64url, 256-bit)
- Default hasher (SHA-256, hex-encoded output)
- HMAC-SHA256 hasher option (`WithHMACSessionIDHasher(secret)`)
- Custom generator option (`WithSessionIDGenerator(gen)`)
- Updated `Session` interface (`ID()` returns `HashedSessionID` instead of `Identifier`)
- Updated `Storer` interface (all session ID params become `HashedSessionID`)
- Updated `CredentialSource` interface (`ReadSessionID` returns `RawSessionID`, `WriteSession` accepts `RawSessionID`)
- Updated `ActivityRecorder` interface (`map[HashedSessionID]time.Time`)
- Updated `DeviceCodeStore` interface (`CompleteDeviceCode` accepts `RawSessionID` instead of `Identifier`)
- Updated `DeviceCodeEntry.SessionID` field type from `Identifier` to `RawSessionID`
- Updated `MemoryStore` to accept hashed IDs (remove internal `generateSessionID`)
- Updated handlers (`OAuth2Callback`, `ExchangeExternalToken`, `DeviceCodeAuthorizeCallback`) to use new flow
- Updated middleware (`authenticate`, `AuthenticateAndRefresh`) to hash before store lookup
- Request context carries raw ID for use in middleware chain

**Out of Scope:**
- Migration tooling for existing session data (documented as a breaking change)
- Device code begin/poll endpoints (these don't create sessions; poll returns the raw ID stored via `CompleteDeviceCode`)
- Encrypted session IDs (hashing is sufficient; encryption would imply needing to decrypt)
- Key rotation for HMAC (users manage their own secrets)

## Interface Definitions

### New Types

```go
// RawSessionID is a plaintext session ID as stored in cookies/tokens.
// This value is sent to clients and must never be stored in the backing store.
type RawSessionID string

func (r RawSessionID) String() string { return string(r) }

// HashedSessionID is a hashed session ID as stored in the backing store.
// The backing store only ever sees and stores this value.
type HashedSessionID string

func (h HashedSessionID) String() string { return string(h) }

// SessionIDGenerator generates cryptographically secure session IDs.
type SessionIDGenerator func() (RawSessionID, error)

// SessionIDHasher converts a raw session ID to its hashed form for storage.
type SessionIDHasher func(RawSessionID) HashedSessionID
```

### Updated Session Interface

```go
type Session interface {
	// ID returns the hashed session ID as stored in the backing store.
	ID() HashedSessionID
	UserID() Identifier
	IdleDeadline() time.Time
	AbsoluteDeadline() time.Time
	LastActivityAt() time.Time
}
```

### Updated Storer Interface

```go
type Storer interface {
	UpsertUser(ctx context.Context, authProviderID Identifier) (userID Identifier, err error)
	CreateSession(ctx context.Context, hashedID HashedSessionID, userID Identifier, idleDeadline, absoluteDeadline time.Time) (Session, error)
	GetSession(ctx context.Context, hashedID HashedSessionID) (Session, error)
	ExtendSession(ctx context.Context, hashedID HashedSessionID, newIdleDeadline time.Time) error
	DeleteSession(ctx context.Context, hashedID HashedSessionID) error
	DeleteUserSessions(ctx context.Context, userID Identifier) (int, error)
}
```

### Updated CredentialSource Interface

```go
type CredentialSource interface {
	Name() string
	ReadSessionID(r *http.Request) RawSessionID
	WriteSession(w http.ResponseWriter, rawID RawSessionID, session Session) error
	ClearSession(w http.ResponseWriter) error
	CanWrite() bool
	SessionConfig() SessionConfig
}
```

### Updated ActivityRecorder Interface

```go
type ActivityRecorder interface {
	BatchRecordActivity(ctx context.Context, updates map[HashedSessionID]time.Time) (int, error)
}
```

### Updated DeviceCodeStore Interface

```go
type DeviceCodeStore interface {
	// ... other methods unchanged ...
	// CompleteDeviceCode marks an authorization as complete with the raw session ID.
	// The raw ID is stored so the poll endpoint can return it to the device client.
	CompleteDeviceCode(ctx context.Context, deviceCode string, rawSessionID RawSessionID) error
}
```

### Updated DeviceCodeEntry

```go
type DeviceCodeEntry struct {
	// ... other fields unchanged ...
	// SessionID stores the raw (unhashed) session ID so the poll endpoint can
	// return it to the device client for use as a Bearer token.
	SessionID RawSessionID
}
```

### New Functional Options

```go
// WithSessionIDGenerator overrides the default session ID generator.
func WithSessionIDGenerator(gen SessionIDGenerator) NewOpts

// WithHMACSessionIDHasher switches from SHA-256 to HMAC-SHA256 using the provided secret.
func WithHMACSessionIDHasher(secret []byte) NewOpts
```

### New Gosesh Fields

```go
type Gosesh struct {
	// ... existing fields ...
	idGenerator SessionIDGenerator
	idHasher    SessionIDHasher
}
```

### Request Context Additions

```go
// RawSessionIDFromContext retrieves the raw session ID from the request context.
// Available after authentication middleware runs.
func RawSessionIDFromContext(ctx context.Context) (RawSessionID, bool)
```

> **Note on `Session.ID()` return type change:** This is a breaking change to the `Session` interface. All implementations of `Session` must update `ID()` to return `HashedSessionID` instead of `Identifier`. This is deliberate — `Session.ID()` always returns the value that was passed to `CreateSession`, which is now always a `HashedSessionID`. This eliminates the need for `HashedSessionID(session.ID().String())` conversions throughout the codebase.

## Dependencies

**Internal Dependencies:**
- `gosesh.go` - Core types, Gosesh struct, functional options
- `store.go` - MemoryStore implementation
- `handlers.go` - OAuth2Callback, ExchangeExternalToken
- `middleware.go` - authenticate, AuthenticateAndRefresh
- `cookie_credential_source.go` - Cookie-based credential source
- `header_credential_source.go` - Header-based credential source
- `composite_credential_source.go` - Multi-source credential handler
- `activity_tracker.go` - Activity tracking (uses session ID strings)

**External Dependencies (stdlib only):**
- `crypto/rand` - Secure random byte generation
- `crypto/sha256` - SHA-256 hashing
- `crypto/hmac` - HMAC-SHA256 hashing
- `encoding/base64` - URL-safe base64 encoding for raw IDs
- `encoding/hex` - Hex encoding for hashed IDs

## Testing Strategy

**Approach:** Unit tests for each new component, updated contract tests for interface changes, updated integration tests for end-to-end flows.

**Key Test Areas:**
- **Generator**: Produces URL-safe output, correct entropy, uniqueness across calls
- **SHA-256 hasher**: Deterministic output, correct hash length, different inputs produce different outputs
- **HMAC-SHA256 hasher**: Correct output with known test vectors, different secrets produce different outputs
- **Round-trip flow**: Generate raw ID → hash → store with hash → read raw from cookie → hash → lookup succeeds
- **Type safety**: Verify `HashedSessionID` and `RawSessionID` cannot be accidentally swapped at compile time (this is a design property, not a runtime test)
- **MemoryStore**: Updated to accept `HashedSessionID` in all methods
- **Middleware**: Raw ID from cookie is hashed before store lookup; raw ID is available in context for WriteSession
- **CredentialSource implementations**: Updated signatures work correctly
- **ExchangeExternalToken**: Returns raw ID (not hashed) in JSON response

## Risks and Tradeoffs

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Breaking change invalidates all existing Storer implementations | Certain | High | Major version bump. Document migration guide in CHANGELOG. Changes are mechanical (parameter additions + type changes). |
| Existing sessions become invalid after upgrade | Certain | Medium | Document that this is expected. Users must invalidate existing sessions or implement a transition period in their store. No library-level migration support (out of scope). |
| Generator override produces weak IDs | Low | High | Document security requirements for custom generators. Default is secure-by-default. |
| Performance overhead of hashing on every request | Low | Low | SHA-256 of a ~43-byte string is ~200ns. Negligible compared to store I/O. |
| HMAC secret management burden on users | Low | Low | HMAC is opt-in. Default SHA-256 requires no secret management. |

## File Layout

```
gosesh.go                          # [modify] Add RawSessionID, HashedSessionID types,
                                   #          SessionIDGenerator, SessionIDHasher types,
                                   #          new fields on Gosesh struct,
                                   #          WithSessionIDGenerator, WithHMACSessionIDHasher opts,
                                   #          default generator/hasher in New(),
                                   #          update Storer interface,
                                   #          update CredentialSource interface,
                                   #          update ActivityRecorder interface,
                                   #          add RawSessionIDFromContext
store.go                           # [modify] Remove generateSessionID(),
                                   #          update MemoryStore methods to accept HashedSessionID,
                                   #          update MemoryStoreSession to use HashedSessionID,
                                   #          update BatchRecordActivity signature
handlers.go                        # [modify] Update OAuth2Callback to generate+hash+pass to store,
                                   #          update ExchangeExternalToken similarly,
                                   #          pass raw ID to WriteSession
middleware.go                      # [modify] Update authenticate to hash before store lookup,
                                   #          store raw ID in context,
                                   #          update AuthenticateAndRefresh to use hashed ID
cookie_credential_source.go        # [modify] Update ReadSessionID return type to RawSessionID,
                                   #          update WriteSession to accept RawSessionID param
header_credential_source.go        # [modify] Update ReadSessionID return type to RawSessionID,
                                   #          update WriteSession to accept RawSessionID param
composite_credential_source.go     # [modify] Update ReadSessionID return type to RawSessionID,
                                   #          update WriteSession to accept RawSessionID param
activity_tracker.go                # [modify] Update RecordActivity to use HashedSessionID,
                                   #          update internal map type
device_code.go                     # [modify] Update DeviceCodeStore.CompleteDeviceCode to accept RawSessionID,
                                   #          update DeviceCodeEntry.SessionID type to RawSessionID
device_code_memory_store.go        # [modify] Update MemoryDeviceCodeStore.CompleteDeviceCode signature
gosesh_test.go                     # [modify] Update tests for new Storer/CredentialSource signatures
store_test.go                      # [modify] Update MemoryStore tests for new CreateSession signature
handlers_test.go                   # [modify] Update handler tests for new flow
middleware_test.go                  # [modify] Update middleware tests for hashing behavior
cookie_credential_source_test.go   # [modify] Update credential source tests
header_credential_source_test.go   # [modify] Update credential source tests
contract_test.go                   # [modify] Update contract tests for new interface signatures
fake_test.go                       # [modify] Update fake store/credential source implementations
activity_tracker_test.go           # [modify] Update activity tracker tests
example_test.go                    # [modify] Update MemoryStoreIdentifier references if type is removed
device_code_test.go                # [modify] Update DeviceCodeAuthorizeCallback tests for new flow
device_code_store_contract_test.go # [modify] Update CompleteDeviceCode contract tests
device_code_memory_store_test.go   # [modify] Update MemoryDeviceCodeStore tests
```

## Implementation Strategy

### Architectural Concerns

- **Interface-first changes**: Update all interface definitions (`Storer`, `CredentialSource`, `ActivityRecorder`, `Session`) before implementations. This surfaces compile errors that guide the remaining work.
- **Type safety as guardrail**: `RawSessionID` and `HashedSessionID` types prevent accidental misuse at compile time. The implementation should leverage this to catch errors early.
- **Test infrastructure first**: Update fake implementations (`fake_test.go`, `contract_test.go`) to match new interfaces before updating production code. This enables TDD for each subsequent change.

### Key Implementation Notes

- Default generator: 32 bytes from `crypto/rand` → `base64.RawURLEncoding.EncodeToString` → ~43 character URL-safe string with 256 bits of entropy.
- Default hasher: `sha256.Sum256([]byte(rawID))` → `hex.EncodeToString` → 64 character hex string.
- HMAC hasher: `hmac.New(sha256.New, secret)` → `Write([]byte(rawID))` → `hex.EncodeToString(Sum(nil))` → 64 character hex string.
- The `authenticate` middleware stores `RawSessionID` in request context (via `RawSessionIDFromContext`) so `AuthenticateAndRefresh` can pass it to `WriteSession` without re-reading from the cookie.
- `ExchangeExternalToken` returns `string(rawID)` in the JSON response, not the hashed ID.
- `MemoryStore.generateSessionID()` is deleted entirely. `MemoryStoreIdentifier` may be replaced by `HashedSessionID` or kept as a thin wrapper.

---

_This summary is ephemeral - it will be deleted with the plan after implementation completes._
