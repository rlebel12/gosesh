# Implementation Plan: Session Duration Semantics Revision

**Related Issue:** [Session Duration Semantics](.agent/docs/issues/session-duration-semantics/ISSUE.md)

## Summary

Revise session duration naming conventions, replace token rotation with TTL extension, and add configurable refresh threshold. This is a breaking change with direct API replacement.

**Key Decisions:**
- Backward compatibility: Replace directly (no deprecation period)
- Defaults: idle=1hr, max=24hr, threshold=10min
- Validation: Check both IdleDeadline and AbsoluteDeadline

## Phase Overview

| Phase | Description | Depends On | Status |
|-------|-------------|------------|--------|
| [01-interfaces](phases/01-interfaces.md) | Update Session, Storer interfaces and Gosesh config | None | Complete |
| [02-memory-store](phases/02-memory-store.md) | Update MemoryStore with new methods | Phase 01 | Complete |
| [03-core-logic](phases/03-core-logic.md) | Update handlers and middleware | Phase 02 | Complete |
| [04-tests](phases/04-tests.md) | Update all test files | Phase 03 | Complete |

## Dependencies

- **Phase 01**: Foundational - defines new interfaces
- **Phase 02**: Implements MemoryStore against new interfaces
- **Phase 03**: Updates business logic to use new semantics
- **Phase 04**: Ensures all tests pass with new implementation

## Success Criteria

- New naming: `SessionIdleTimeout`, `SessionMaxLifetime`, `SessionRefreshThreshold`
- All three durations configurable via `With*` options
- Default values: idle=1hr, max=24hr, threshold=10min
- Storer interface includes `ExtendSession(ctx, sessionID, newIdleDeadline) error`
- Session interface uses `IdleDeadline()` and `AbsoluteDeadline()`
- Middleware uses TTL extension (UPDATE) instead of token rotation (INSERT+DELETE)
- Refresh only triggers when within threshold of idle expiry
- Cookie `Expires` set to `AbsoluteDeadline`
- Validation checks both deadlines
- All tests pass
- Issue document deleted when complete

## Status

**Progress:** 4/4 phases complete
**Current Phase:** Complete
**Blocked:** None

---

_When implementation completes: Delete this plan directory and the issue directory._
