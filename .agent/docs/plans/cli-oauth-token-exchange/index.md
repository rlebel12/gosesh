# Implementation Plan: CLI OAuth Token Exchange Security Fix

**Related Issue:** [cli-oauth-session-token-url-exposure](../../issues/cli-oauth-session-token-url-exposure/issue.md)

## Summary

Replace insecure CLI OAuth flow (session token in URL) with a secure token exchange endpoint. Desktop clients will handle OAuth/PKCE directly with the identity provider, then exchange the access token for a gosesh session via POST request body.

## Phase Overview

| Phase | Description | Depends On | Status |
|-------|-------------|------------|--------|
| [01-exchange-endpoint](phases/01-exchange-endpoint.md) | Add ExchangeExternalToken handler | None | Pending |
| [02-remove-cli-handlers](phases/02-remove-cli-handlers.md) | Remove OAuth2BeginCLI and OAuth2CallbackCLI | Phase 01 | Pending |

## Dependencies

- **Phase 01**: Can start immediately
- **Phase 02**: Must wait for Phase 01 to complete (new endpoint provides replacement functionality)

## Success Criteria

- Session tokens never appear in redirect URLs
- Desktop clients can authenticate via new `ExchangeExternalToken` endpoint
- Device code flow remains unchanged for headless environments
- All existing tests pass (minus removed CLI handler tests)
- New endpoint has comprehensive test coverage

## Status

**Progress:** 0/2 phases complete
**Current Phase:** Not started
**Blocked:** None

---

_When implementation completes: Delete this plan directory and the related issue directory._
