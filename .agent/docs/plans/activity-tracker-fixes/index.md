# Implementation Plan: Activity Tracker Bug Fixes

**Design Summary:** Established in conversation (code review of PR)
**Related PR:** Branch `claude/gosesh-pr-12-nf0bX`

## Context

Code review identified several issues in the activity tracking implementation that need to be addressed before merge:

1. **Critical**: Final flush uses cancelled context - `context.WithTimeout` derives from cancelled parent, resulting in immediately-cancelled timeout context (silent failure)
2. **Dependency**: oauth2 version downgrade from v0.27.0 to v0.21.0 (unintentional)
3. **Minor**: Test uses incorrect `string(rune(id))` conversion producing unprintable characters

## Phase Overview

| Phase | Description | Depends On | Status |
|-------|-------------|------------|--------|
| [01-merge-main](phases/01-merge-main.md) | Merge origin/main to fix go.mod | None | Pending |
| [02-final-flush-context](phases/02-final-flush-context.md) | Fix cancelled context in final flush | Phase 01 | Pending |
| [03-test-string-fix](phases/03-test-string-fix.md) | Fix rune-to-string conversion in test | Phase 01 | Pending |

## Dependencies

- **Phase 01**: Must complete first (ensures clean go.mod)
- **Phases 02-03**: Can proceed in parallel after Phase 01

## Success Criteria

- All tests pass (`go test ./...`)
- Test `final_flush_succeeds_after_context_cancel` passes (verifies activity persists to store after context cancellation)
- `go.mod` shows `golang.org/x/oauth2 v0.27.0`
- Session IDs in `handles concurrent recording safely` test are readable (e.g., "session-42")

## Status

**Progress:** 0/3 phases complete
**Current Phase:** Not started
**Blocked:** None

---

_When implementation completes: Delete this entire plan directory._
