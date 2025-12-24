# Implementation Plan: Multi-Client Authentication

**Related Architecture:** None (see justification below)
**Related Spec:** N/A

## Architecture Justification

A separate architecture document is not required for this implementation because:

1. **Extension, not redesign**: This work extends existing patterns rather than introducing new architectural paradigms. The `CredentialSource` interface follows the same interface-based design already used by `Storer`, `Session`, and `Identifier`.

2. **Existing patterns sufficient**: The codebase already demonstrates:
   - Interface-based abstractions (`gosesh.go`)
   - Functional options pattern (`WithLogger`, `WithSessionCookieName`)
   - Middleware composition (`middleware.go`)
   - Contract testing (`contract_test.go`)

3. **Additive change**: New functionality (header auth, device code flow) adds to existing OAuth2 flows without modifying their fundamental structure.

4. **Clear interface contract**: The `CredentialSource` interface is fully specified in this plan's Key Design Decisions section, serving as the architectural contract.

## Pattern Decisions

### Error Handling

This plan uses **sentinel errors** (`var ErrX = errors.New(...)`) to match the existing codebase pattern in `errors.go`. While structured errors (BaseError) offer richer context, consistency with existing code takes precedence. Migrating to structured errors could be addressed in a future refactoring effort.

## Overview

Extend gosesh to support multiple authentication methods beyond cookies:
1. **Credential Source abstraction** - Interface-based design for pluggable auth methods
2. **Header-based authentication** - `Authorization: Bearer <session_id>` for CLI/API clients
3. **Per-source session configuration** - Different timeout settings per credential source
4. **Localhost callback flow** - OAuth2 completion for CLI clients with browser access
5. **Device code flow** - OAuth2 for headless CLI clients (no browser)
6. **End-to-end integration tests** - Full flow testing with real server and CLI client

## Phase Overview

| Phase | Description | Depends On | Status |
|-------|-------------|------------|--------|
| [01-credential-source-interface](phases/01-credential-source-interface.md) | Define CredentialSource interface and SessionConfig type | None | Complete |
| [02-cookie-credential-source](phases/02-cookie-credential-source.md) | Refactor existing cookie logic into CookieCredentialSource | Phase 01 | Pending |
| [03-header-credential-source](phases/03-header-credential-source.md) | Implement HeaderCredentialSource for Bearer token auth | Phase 01 | Pending |
| [04-composite-credential-source](phases/04-composite-credential-source.md) | Implement CompositeCredentialSource for multiple sources | Phase 02, 03 | Pending |
| [05-middleware-integration](phases/05-middleware-integration.md) | Update middleware to use credential sources | Phase 04 | Pending |
| [06-localhost-callback](phases/06-localhost-callback.md) | OAuth2 localhost callback flow for CLI clients | Phase 05 | Pending |
| [07-device-code-flow](phases/07-device-code-flow.md) | Device code flow for headless CLI authentication | Phase 05 | Pending |
| [08-e2e-integration-tests](phases/08-e2e-integration-tests.md) | End-to-end tests with real server and CLI client | Phase 06, 07 | Pending |

## Dependencies

**Dependency Types:**

- **None**: Phase can start immediately
- **Phase NN**: Must wait for specified phase to complete (all gates passed)
- **Parallel**: Phases 02 and 03 can execute concurrently after Phase 01
- **Parallel**: Phases 06 and 07 can execute concurrently after Phase 05

## Success Criteria

- Existing cookie-based authentication continues to work unchanged (backward compatible)
- CLI/API clients can authenticate using `Authorization: Bearer <session_id>` header
- Different credential sources can have different session timeout configurations
- CLI clients with browser access can complete OAuth2 via localhost callback
- Headless CLI clients can complete OAuth2 via device code flow
- All authentication flows are covered by contract tests and integration tests
- End-to-end tests demonstrate full CLI-to-server authentication flow

## Key Design Decisions

### Interface Definition

```go
// CredentialSource abstracts how session IDs are read/written.
type CredentialSource interface {
    // Name identifies this source (for logging, debugging)
    Name() string

    // ReadSessionID extracts session ID from request. Empty string if not present.
    ReadSessionID(r *http.Request) string

    // WriteSession writes session credential to response.
    // No-op for sources that can't write (e.g., headers).
    WriteSession(w http.ResponseWriter, session Session) error

    // ClearSession removes credential from response.
    ClearSession(w http.ResponseWriter) error

    // CanWrite returns whether this source can write to responses.
    CanWrite() bool

    // SessionConfig returns timeout configuration for sessions from this source.
    SessionConfig() SessionConfig
}

type SessionConfig struct {
    IdleDuration     time.Duration // 0 means no idle timeout
    AbsoluteDuration time.Duration
    RefreshEnabled   bool          // whether AuthenticateAndRefresh extends sessions
}
```

### Backward Compatibility

- Default to CookieCredentialSource if no source configured
- Existing `WithSessionIdleTimeout`, `WithSessionActiveDuration` options continue to work
- New `WithCredentialSource(...)` and `WithCredentialSources(...)` options added

### Testing Strategy

- Contract tests for CredentialSource implementations
- Fake implementations for testing (following project pattern)
- Integration tests for OAuth2 flows
- End-to-end tests with real HTTP server and minimal CLI client

## Status

**Progress:** 1/8 phases complete
**Current Phase:** Phase 01 complete, ready for Phase 02 and 03 (can run in parallel)
**Blocked:** None

---

_When implementation completes: Delete this plan directory. Preserve architectural learnings in architecture docs._
