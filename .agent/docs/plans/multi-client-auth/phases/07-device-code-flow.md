# Phase 07: Device Code Flow

**Depends on:** Phase 05
**Status:** Complete

---

## RED: Write Tests

**Objective:** Test device code flow for headless CLI authentication

**Files:**

- `device_code_test.go`
- `device_code_store_contract_test.go`

**Test Cases - DeviceCodeStore Contract:**

### Parameterized: Store CRUD Operations

| Case Name | Operation | Input | Expected | Notes |
|-----------|-----------|-------|----------|-------|
| `create_returns_device_code` | Create | Valid user code | Non-empty device code | Device code generated |
| `create_stores_entry` | Create + Get | Valid entry | Get returns same entry | Persistence works |
| `delete_success` | Delete + Get | Existing code | Get returns not found | Deletion works |
| `delete_nonexistent` | Delete | Unknown code | No error | Idempotent delete |

### Parameterized: Store Error Conditions

| Case Name | Operation | Input | Expected Error | Notes |
|-----------|-----------|-------|----------------|-------|
| `get_nonexistent` | Get | Unknown device code | `ErrDeviceCodeNotFound` | Not found handling |
| `get_expired` | Get | Expired device code | `ErrDeviceCodeExpired` | Expiry check |
| `complete_nonexistent` | Complete | Unknown code | `ErrDeviceCodeNotFound` | Not found handling |
| `complete_already_complete` | Complete | Already completed | `ErrDeviceCodeAlreadyComplete` | Idempotency |

### Unique: Store Special Cases

| Case Name | Input | Expected | Notes |
|-----------|-------|----------|-------|
| `complete_success` | Complete with session ID | Entry marked complete, SessionID set | Completion works |
| `create_user_code_collision` | Create with colliding user code | Retry generates new unique code | Collision handling |

**Test Cases - Device Code Handlers:**

### Unique: DeviceCodeBegin Response Structure

| Case Name | Request | Expected | Notes |
|-----------|---------|----------|-------|
| `begin_returns_codes` | POST /auth/device/begin | JSON with device_code, user_code, verification_uri, expires_in, interval | All fields present |
| `begin_user_code_format` | POST /auth/device/begin | user_code is `XXXX-XXXX` format, safe alphabet only | Human-readable |
| `begin_expires_in` | POST /auth/device/begin | expires_in between 300-900 seconds | 5-15 min range |
| `begin_interval` | POST /auth/device/begin | interval is 5 | 5 second polling |

### Parameterized: DeviceCodePoll Status Cases

| Case Name | Device Code State | Expected Response | Notes |
|-----------|-------------------|-------------------|-------|
| `poll_pending` | Created, not completed | `{"status": "pending"}` | Not yet authorized |
| `poll_complete` | Completed with session | `{"status": "complete", "session_id": "..."}` | Authorization done |
| `poll_expired` | Past expiry time | `{"status": "expired"}` | Device code expired |

### Parameterized: DeviceCodePoll Error Cases

| Case Name | Input | Expected | Notes |
|-----------|-------|----------|-------|
| `poll_invalid_code` | Unknown device_code | 400 Bad Request | Invalid code |
| `poll_missing_code` | No device_code in body | 400 Bad Request | Required field |
| `poll_rate_limit` | Poll within 5 seconds of last | 429 Too Many Requests | Rate limiting |

### Unique: DeviceCodeAuthorize Flow

| Case Name | Request | Expected | Notes |
|-----------|---------|----------|-------|
| `authorize_page_get` | GET /auth/device | HTML page with form | User enters code |
| `authorize_submit_valid` | POST with valid user_code | Redirect to OAuth provider | Initiates OAuth |
| `authorize_submit_invalid` | POST with unknown user_code | Error message on page | Invalid code |
| `authorize_callback` | OAuth callback after authorization | Device code completed, success page | Links session to device |

**Assertions:**

- Device codes are unique and unpredictable
- User codes are short and human-readable
- Polling respects rate limits
- Expired codes are rejected
- Session created with CLI session config

**Edge Cases:**

- Concurrent poll requests
- User code collision (regenerate)
- Device code used after expiry
- OAuth failure during device authorization

### Gate: RED

- [ ] Test files created with all enumerated test cases
- [ ] All tests FAIL (implementation does not exist yet)
- [ ] Test coverage includes happy path and all edge cases

---

## GREEN: Implement

**Objective:** Implement device code flow for headless CLI authentication

**Files:**

- `device_code.go` (types and store interface)
- `device_code_memory_store.go` (in-memory implementation)
- `handlers_device.go` (HTTP handlers)

**Implementation Guidance:**

```go
// device_code.go

// DeviceCodeEntry represents a pending device authorization
type DeviceCodeEntry struct {
    DeviceCode string
    UserCode   string
    ExpiresAt  time.Time
    Interval   time.Duration
    SessionID  Identifier // nil until completed
    Completed  bool
    LastPoll   time.Time // for rate limiting
}

// DeviceCodeStore manages pending device authorizations
type DeviceCodeStore interface {
    // CreateDeviceCode creates a new pending authorization
    // Returns device code (long, secret) for the device
    CreateDeviceCode(ctx context.Context, userCode string, expiresAt time.Time) (deviceCode string, err error)

    // GetDeviceCode retrieves a pending authorization by device code
    GetDeviceCode(ctx context.Context, deviceCode string) (DeviceCodeEntry, error)

    // GetByUserCode retrieves by user code (for authorization page)
    GetByUserCode(ctx context.Context, userCode string) (DeviceCodeEntry, error)

    // CompleteDeviceCode marks authorization as complete with session ID
    CompleteDeviceCode(ctx context.Context, deviceCode string, sessionID Identifier) error

    // UpdateLastPoll updates the last poll time (for rate limiting)
    UpdateLastPoll(ctx context.Context, deviceCode string, pollTime time.Time) error

    // DeleteDeviceCode removes an authorization
    DeleteDeviceCode(ctx context.Context, deviceCode string) error

    // CleanupExpired removes expired entries (call periodically)
    CleanupExpired(ctx context.Context) error
}

// Errors
var (
    ErrDeviceCodeNotFound        = errors.New("device code not found")
    ErrDeviceCodeExpired         = errors.New("device code expired")
    ErrDeviceCodeAlreadyComplete = errors.New("device code already completed")
    ErrDeviceCodeRateLimited     = errors.New("polling too frequently")
)
```

```go
// device_code_memory_store.go

type MemoryDeviceCodeStore struct {
    // Implementation approach:
    // 1. Map device_code -> DeviceCodeEntry
    // 2. Map user_code -> device_code (for lookup)
    // 3. Mutex for thread safety
}

func NewMemoryDeviceCodeStore() *MemoryDeviceCodeStore { ... }

// Implementation follows store interface
// CleanupExpired iterates and removes expired entries
```

```go
// handlers_device.go

// DeviceCodeBeginResponse is returned by begin endpoint
type DeviceCodeBeginResponse struct {
    DeviceCode      string `json:"device_code"`
    UserCode        string `json:"user_code"`
    VerificationURI string `json:"verification_uri"`
    ExpiresIn       int    `json:"expires_in"`
    Interval        int    `json:"interval"`
}

// DeviceCodePollResponse is returned by poll endpoint
type DeviceCodePollResponse struct {
    Status    string `json:"status"` // "pending", "complete", "expired"
    SessionID string `json:"session_id,omitempty"`
    ExpiresAt string `json:"expires_at,omitempty"`
}

// DeviceCodeBegin creates a new device authorization request
func (gs *Gosesh) DeviceCodeBegin(store DeviceCodeStore) http.HandlerFunc {
    // Implementation approach:
    // 1. Generate user code: 8 alphanumeric chars, easy to type
    //    - Use charset: BCDFGHJKLMNPQRSTVWXYZ23456789 (no vowels, no 0/1/O/I)
    //    - Format: XXXX-XXXX (with hyphen for readability)
    // 2. Generate device code: 32 random bytes, hex encoded
    // 3. Set expiry: 15 minutes from now
    // 4. Store in DeviceCodeStore
    // 5. Return JSON response with codes and verification_uri
}

// DeviceCodePoll checks status of device authorization
func (gs *Gosesh) DeviceCodePoll(store DeviceCodeStore) http.HandlerFunc {
    // Implementation approach:
    // 1. Parse device_code from request body
    // 2. Get entry from store
    // 3. Check if expired -> return "expired" status
    // 4. Check rate limiting (5 second interval)
    //    - If last poll < 5 seconds ago -> return 429
    // 5. Update last poll time
    // 6. Check if completed:
    //    - If completed -> return "complete" with session_id
    //    - If not -> return "pending"
}

// DeviceCodeAuthorize shows authorization page to user
func (gs *Gosesh) DeviceCodeAuthorize(store DeviceCodeStore) http.HandlerFunc {
    // Implementation approach:
    // GET: Show HTML form to enter user code
    // POST: Validate user code, redirect to OAuth
}

// DeviceCodeAuthorizeCallback handles OAuth callback for device flow
func (gs *Gosesh) DeviceCodeAuthorizeCallback(
    store DeviceCodeStore,
    oauthCfg *oauth2.Config,
    request RequestFunc,
    unmarshal UnmarshalFunc,
) http.HandlerFunc {
    // Implementation approach:
    // 1. Complete OAuth flow (exchange code, fetch user, upsert)
    // 2. Create session with CLI session config
    // 3. Get device code from state/cookie
    // 4. Complete device code entry with session ID
    // 5. Show "authorization complete" page to user
}

// generateUserCode creates a human-readable code with collision detection
func generateUserCode(store DeviceCodeStore, ctx context.Context) (string, error) {
    // Implementation approach:
    // 1. Generate random code from safe alphabet: BCDFGHJKLMNPQRSTVWXYZ23456789
    //    - 8 chars formatted as XXXX-XXXX for readability
    // 2. Check if code exists in store via GetByUserCode
    // 3. If collision, retry (max 10 attempts)
    // 4. If max attempts exceeded, return error
    // 5. Return unique code
    //
    // Collision probability is low (~1 in 17 million) but must be handled
    // to prevent authorization hijacking
}
```

### Gate: GREEN

- [ ] All tests from RED phase now PASS
- [ ] Test command: `go test -v -run TestDeviceCode`
- [ ] Contract tests pass for MemoryDeviceCodeStore
- [ ] Implementation follows pseudocode logic flow

---

## REFACTOR: Quality

**Focus:** Code quality, not new functionality.

- Ensure user codes are truly unambiguous (no 0/O, 1/I/L confusion)
- Document rate limiting behavior
- Consider making interval/expiry configurable

### Gate: REFACTOR

- [ ] Commit succeeds (pre-commit handles formatting/linting)

---

## Phase Complete

When all gates pass:

1. Update this file's status to **Complete**
2. Update index.md status table
3. Phase 08 can proceed once both Phase 06 and Phase 07 complete

---

**Previous:** [Phase 05](05-middleware-integration.md)
**Next:** [Phase 08](08-e2e-integration-tests.md) (after Phase 06 also completes)
