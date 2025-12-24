# Phase 05: Middleware Integration

**Depends on:** Phase 04
**Status:** Pending

---

## RED: Write Tests

**Objective:** Test updated middleware that uses credential sources instead of hardcoded cookies

**Files:**

- `middleware_credential_source_test.go`

**Test Cases:**

| Case Name | Input | Expected | Notes |
|-----------|-------|----------|-------|
| `authenticate_cookie_source` | Gosesh with cookie source, request with cookie | Session in context | Cookie auth works |
| `authenticate_header_source` | Gosesh with header source, request with Bearer token | Session in context | Header auth works |
| `authenticate_composite_source` | Gosesh with composite, request with cookie | Session in context | First source wins |
| `authenticate_composite_fallback` | Gosesh with composite, request with header only | Session in context | Fallback to header |
| `authenticate_no_credentials` | Request without credentials | No session in context | Graceful handling |
| `authenticate_invalid_session` | Request with non-existent session ID | No session, credential cleared | Invalid session handling |
| `authenticate_expired_idle` | Request with idle-expired session | No session, credential cleared | Idle expiry works |
| `authenticate_expired_absolute` | Request with absolute-expired session | No session, credential cleared | Absolute expiry works |
| `refresh_header_source_disabled` | Header source with RefreshEnabled=false | No refresh occurs | Respect config |
| `refresh_cookie_source_enabled` | Cookie source with RefreshEnabled=true | Session refreshed | Respect config |
| `require_auth_header_source` | Header source, no token | 401 Unauthorized | Auth required |
| `require_auth_cookie_source` | Cookie source, no cookie | 401 Unauthorized | Auth required |
| `backward_compat_no_source` | Gosesh without explicit source | Cookie source default | Backward compatibility |
| `backward_compat_old_options` | Gosesh with WithSessionCookieName | Cookie source uses that name | Old options work |
| `backward_compat_existing_sessions` | Session created with old API, read with new | Session still valid | Zero-downtime upgrade |

**Assertions:**

- Middleware reads from configured credential source
- Invalid sessions trigger ClearSession on source
- AuthenticateAndRefresh respects source's RefreshEnabled
- Backward compatibility: no explicit source = cookie source with existing options

**Edge Cases:**

- Source that can't write receiving a clear request (no-op)
- Composite source with mixed RefreshEnabled configs
- Multiple middlewares with different sources (not recommended but should work)

### Gate: RED

- [ ] Test file created with all enumerated test cases
- [ ] All tests FAIL (implementation does not exist yet)
- [ ] Test coverage includes happy path and all edge cases

---

## GREEN: Implement

**Objective:** Refactor middleware to use credential sources

**Files:**

- `middleware.go` (modify existing)
- `gosesh.go` (add credential source field and options)

**Implementation Guidance:**

```go
// In gosesh.go - add to Gosesh struct
type Gosesh struct {
    // ... existing fields ...
    credentialSource CredentialSource
}

// New options
func WithCredentialSource(source CredentialSource) Option {
    // Implementation approach:
    // 1. Set gs.credentialSource = source
    // 2. If source provides SessionConfig, update session durations
}

func WithCredentialSources(sources ...CredentialSource) Option {
    // Implementation approach:
    // 1. Create CompositeCredentialSource from sources
    // 2. Call WithCredentialSource with composite
}

// Backward compatibility in New()
func New(store Storer, opts ...Option) *Gosesh {
    // Implementation approach:
    // 1. Apply all options
    // 2. If credentialSource is nil after options:
    //    a. Create CookieCredentialSource with existing config:
    //       - Cookie name from sessionCookieName
    //       - Domain from cookieDomain
    //       - Secure from existing secure setting
    //       - SessionConfig from sessionIdleTimeout/sessionActiveDuration
    //    b. Set as credential source
    // This ensures backward compatibility
}
```

```go
// In middleware.go - update authenticate function
func (gs *Gosesh) authenticate(w http.ResponseWriter, r *http.Request) (*http.Request, Session) {
    // Implementation approach:
    // 1. Read session ID from credential source:
    //    sessionID := gs.credentialSource.ReadSessionID(r)
    // 2. If empty -> return (no session)
    // 3. Get session from store (existing logic)
    // 4. Validate deadlines (existing logic)
    // 5. On invalid/expired session:
    //    - Call gs.credentialSource.ClearSession(w)
    //    - Return (no session)
    // 6. Store session in context, return
}

func (gs *Gosesh) AuthenticateAndRefresh(next http.Handler) http.Handler {
    // Implementation approach:
    // 1. Call authenticate (gets session)
    // 2. Check if source's SessionConfig().RefreshEnabled
    // 3. If not enabled -> skip refresh
    // 4. If enabled -> existing refresh logic
    // 5. On refresh: call gs.credentialSource.WriteSession(w, session)
}
```

**Migration of existing cookie code:**

The existing `sessionCookie()`, `expireSessionCookie()` functions in `cookies.go` become internal to `CookieCredentialSource`. The middleware now only interacts via the `CredentialSource` interface.

### Gate: GREEN

- [ ] All tests from RED phase now PASS
- [ ] Test command: `go test -v -run TestMiddleware`
- [ ] All existing middleware tests still pass
- [ ] Implementation follows pseudocode logic flow

---

## REFACTOR: Quality

**Focus:** Code quality, not new functionality.

- Remove dead code from old cookie handling in middleware
- Ensure backward compatibility is clearly documented
- Consider deprecation warnings for old options (or keep silently compatible)

### Gate: REFACTOR

- [ ] `go vet ./...` passes
- [ ] `go test ./...` passes
- [ ] All existing tests pass (backward compatibility)
- [ ] `make coverage` shows adequate coverage
- [ ] Code formatting applied (`gofmt`)

---

## Phase Complete

When all gates pass:

1. Update this file's status to **Complete**
2. Update index.md status table
3. Proceed to Phase 06 and Phase 07 (can run in parallel)

---

**Previous:** [Phase 04](04-composite-credential-source.md)
**Next:** [Phase 06](06-localhost-callback.md) and [Phase 07](07-device-code-flow.md) (parallel)
