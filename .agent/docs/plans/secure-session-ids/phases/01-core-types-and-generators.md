# Phase 01: Core Types and Generators

**Depends on:** None
**Phase Type:** Standard
**Status:** Complete

---

## RED: Write Tests

**Objective:** Test the new session ID types, default generator, SHA-256 hasher, HMAC-SHA256 hasher, functional options, and context helpers.

**Files:**

- `gosesh_test.go` (new tests added to existing file)

**Test Cases:**

### Default Generator Tests

**Parameterized Tests** (table format):

| Case | Assertion | Notes |
|------|-----------|-------|
| `output_is_url_safe` | Result matches `^[A-Za-z0-9_-]+$` | base64url with no padding |
| `output_length` | `len(rawID) == 43` | 32 bytes base64url-encoded = 43 chars (no padding) |
| `uniqueness` | 100 calls produce 100 distinct values | Statistical uniqueness check |

**Discrete Tests:**

- **Test default generator error handling**: Use a custom generator that returns an error, verify it propagates

### SHA-256 Hasher Tests

**Parameterized Tests** (table format):

| Case | Input (RawSessionID) | Expected Output (HashedSessionID) | Notes |
|------|---------------------|-----------------------------------|-------|
| `known_vector` | `"test-session-id"` | SHA-256 hex of "test-session-id" | Deterministic known-good output |
| `output_length` | `"any-input"` | `len(result) == 64` | SHA-256 hex is always 64 chars |
| `different_inputs_different_outputs` | `"input-a"` vs `"input-b"` | Outputs differ | No collisions for distinct inputs |
| `deterministic` | `"same-input"` hashed twice | Both outputs equal | Same input always produces same hash |

### HMAC-SHA256 Hasher Tests

**Parameterized Tests** (table format):

| Case | Input (RawSessionID) | Secret | Expected | Notes |
|------|---------------------|--------|----------|-------|
| `known_vector` | `"test-session-id"` | `[]byte("secret-key")` | HMAC-SHA256 hex with known secret | Deterministic known-good output |
| `rfc4231_test_case_2` | `RawSessionID("what do ya want for nothing?")` | `[]byte("Jefe")` | `5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843` | RFC 4231 test vector for HMAC-SHA256 correctness |
| `output_length` | `"any-input"` | `[]byte("key")` | `len(result) == 64` | HMAC-SHA256 hex is always 64 chars |
| `different_secrets_different_outputs` | `"same-input"` | `[]byte("key-a")` vs `[]byte("key-b")` | Outputs differ | Different keys produce different hashes |
| `different_from_sha256` | `"same-input"` | `[]byte("key")` | Output differs from SHA-256 of same input | HMAC != plain SHA-256 |

### Functional Options Tests

**Discrete Tests:**

- **Test WithSessionIDGenerator overrides default**: Create Gosesh with custom generator, verify it is stored on the struct
- **Test WithHMACSessionIDHasher sets HMAC hasher**: Create Gosesh with HMAC option, verify hasher uses HMAC (hash output differs from SHA-256 default)
- **Test default generator and hasher in New()**: Create Gosesh without options, verify `idGenerator` and `idHasher` fields are non-nil

### RawSessionID Type Tests

**Parameterized Tests** (table format):

| Case | Input | Expected String() | Expected IsZero() | Notes |
|------|-------|--------------------|-------------------|-------|
| `non_empty` | `RawSessionID("abc123")` | `"abc123"` | `false` | String conversion and non-zero |
| `empty` | `RawSessionID("")` | `""` | `true` | Zero value |

### HashedSessionID Type Tests

**Parameterized Tests** (table format):

| Case | Input | Expected String() | Expected IsZero() | Notes |
|------|-------|--------------------|-------------------|-------|
| `non_empty` | `HashedSessionID("deadbeef")` | `"deadbeef"` | `false` | String conversion and non-zero |
| `empty` | `HashedSessionID("")` | `""` | `true` | Zero value |

### Context Helper Tests

**Discrete Tests:**

- **Test RawSessionIDFromContext with value present**: Set raw ID in context, verify retrieval returns (value, true)
- **Test RawSessionIDFromContext with no value**: Empty context returns ("", false)

**Assertions:**

- Generator returns `(RawSessionID, error)` with non-empty ID on success
- Hashers return `HashedSessionID` that is deterministic and correct length
- Functional options modify the Gosesh struct fields correctly
- Context helpers round-trip correctly

**Edge Cases:**

- Empty `RawSessionID` hashed still produces valid output
- HMAC with empty secret still works (degenerate case)

### Gate: RED

- [x] Test file created with all enumerated test cases
- [x] All tests FAIL (implementation does not exist yet)
- [x] Test coverage includes happy path and all edge cases

---

## GREEN: Implement

**Objective:** Add new types, generator, hashers, functional options, and context helpers to `gosesh.go`.

**Files:**

- `gosesh.go`

**Implementation Guidance:**

```go
// New types - add near top of file after existing type declarations

type RawSessionID string
// String() method returns string(r)
// IsZero() method returns r == ""

type HashedSessionID string
// String() method returns string(h)
// IsZero() method returns h == ""

type SessionIDGenerator func() (RawSessionID, error)

type SessionIDHasher func(RawSessionID) HashedSessionID
```

```go
// Default generator function
func defaultSessionIDGenerator() (RawSessionID, error) {
    """Generate 32 random bytes from crypto/rand.

    Implementation approach:
    1. Allocate 32-byte slice
    2. Fill with crypto/rand.Read
    3. Encode with base64.RawURLEncoding (no padding)
    4. Return as RawSessionID

    Error handling:
    - crypto/rand failure -> return ("", fmt.Errorf("generate session ID: %w", err))
    """
}
```

```go
// Default SHA-256 hasher
func defaultSessionIDHasher(raw RawSessionID) HashedSessionID {
    """Hash raw session ID with SHA-256.

    Implementation approach:
    1. sha256.Sum256([]byte(raw))
    2. hex.EncodeToString the result
    3. Return as HashedSessionID
    """
}
```

```go
// HMAC-SHA256 hasher factory
func newHMACSessionIDHasher(secret []byte) SessionIDHasher {
    """Create HMAC-SHA256 hasher with captured secret.

    Implementation approach:
    1. Return a closure that:
       a. Creates hmac.New(sha256.New, secret)
       b. Writes []byte(raw) to it
       c. hex.EncodeToString(h.Sum(nil))
       d. Returns as HashedSessionID
    """
}
```

```go
// Add fields to Gosesh struct:
//   idGenerator SessionIDGenerator
//   idHasher   SessionIDHasher

// In New(), set defaults:
//   gs.idGenerator = defaultSessionIDGenerator
//   gs.idHasher = defaultSessionIDHasher
// (before applying options, so options can override)
```

```go
// Functional options
func WithSessionIDGenerator(gen SessionIDGenerator) NewOpts {
    """Set custom ID generator on Gosesh.

    Implementation approach:
    1. Return func that sets gs.idGenerator = gen
    """
}

func WithHMACSessionIDHasher(secret []byte) NewOpts {
    """Set HMAC-SHA256 hasher on Gosesh.

    Implementation approach:
    1. Return func that sets gs.idHasher = newHMACSessionIDHasher(secret)
    """
}
```

```go
// Context key and helper for raw session ID
type rawSessionIDContextKey struct{}

var rawSessionIDKey = rawSessionIDContextKey{}

func RawSessionIDFromContext(ctx context.Context) (RawSessionID, bool) {
    """Retrieve raw session ID from context.

    Implementation approach:
    1. Type-assert ctx.Value(rawSessionIDKey) to RawSessionID
    2. Return (value, ok)
    """
}
```

### Gate: GREEN

- [x] All tests from RED phase now PASS
- [x] Test command: `go test ./... -run "TestDefault(Generator|Hasher)|TestHMAC|TestWithSession|TestRawSessionID|TestHashedSessionID|TestRawSessionIDFromContext"` (all new tests)
- [x] Implementation follows pseudocode logic flow

---

## REFACTOR: Quality

**Focus:** Code quality improvements, not new functionality.

**Review Areas:**

- **Duplication**: Ensure generator and hasher functions are DRY
- **Naming**: `RawSessionID` and `HashedSessionID` clearly convey their purpose
- **Simplification**: Keep type definitions near their related functions
- **Error Messages**: Generator error wrapping uses concise verb+object format
- **Readability**: Group new types, then functions, then options logically in `gosesh.go`
- **Ordering**: Public types and functions defined before private ones

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

**Previous:** First phase
**Next:** [Phase 02](02-interface-updates-and-test-infra.md)
