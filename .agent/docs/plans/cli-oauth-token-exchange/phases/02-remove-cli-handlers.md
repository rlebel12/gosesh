# Phase 02: Remove CLI OAuth Handlers

**Depends on:** Phase 01
**Status:** Pending

---

## RED: Write Tests

**Objective:** Verify removal doesn't break existing functionality

**Files:**

- No new test files needed

**Verification approach:**

This is a removal phase. The "RED" gate here confirms:
1. Existing non-CLI tests still pass before removal
2. We identify which tests in `localhost_callback_test.go` will be removed

**Pre-removal verification:**

| Check | Command | Expected |
|-------|---------|----------|
| All tests pass | `go test ./...` | PASS |
| New endpoint works | `go test -v -run TestExchangeExternalToken` | PASS |

**Tests to REMOVE (entire file `localhost_callback_test.go`):**
- `TestOAuth2BeginCLI_*` - All CLI begin handler tests
- `TestOAuth2CallbackCLI_*` - All CLI callback handler tests
- `Test_isLocalhostURL` - Localhost validation tests

**Tests to KEEP (in `handlers_test.go`):**
- All `TestOAuth2Callback_*` tests (browser flow)
- All `TestLogout_*` tests
- All `TestCallbackRedirect_*` tests
- New `TestExchangeExternalToken_*` tests (from Phase 01)

### Gate: RED

- [ ] All existing tests pass before removal
- [ ] New ExchangeExternalToken endpoint tests pass
- [ ] No tests outside `localhost_callback_test.go` depend on CLI handlers

---

## GREEN: Remove Code

**Objective:** Remove CLI OAuth handlers and related code

**Files to delete:**

- `handlers_cli.go` (entire file)
- `localhost_callback_test.go` (entire file)

**Code to remove from other files:**

- `getCLISessionConfig()` method if only used by CLI handlers (check references first)

**Removal checklist:**

```
Implementation approach:
1. Search for references to OAuth2BeginCLI, OAuth2CallbackCLI
2. Search for references to CLIStateData, isLocalhostURL
3. Search for references to getCLISessionConfig
4. If getCLISessionConfig is used elsewhere, keep it
5. Delete handlers_cli.go
6. Delete localhost_callback_test.go
7. Run go build to verify no compile errors
8. Run go test ./... to verify all remaining tests pass
```

**Expected removals (~300 lines):**

- `CLIStateData` struct
- `isLocalhostURL()` helper
- `OAuth2BeginCLI()` handler
- `OAuth2CallbackCLI()` handler
- `getCLISessionConfig()` method (if unused elsewhere)
- All tests in `localhost_callback_test.go`

### Gate: GREEN

- [ ] `handlers_cli.go` deleted
- [ ] `localhost_callback_test.go` deleted
- [ ] `go build ./...` succeeds
- [ ] `go test ./...` passes

---

## REFACTOR: Quality

**Focus:** Clean up any orphaned code or references

**Review Areas:**

- **Dead code**: Check for any helper functions that were only used by CLI handlers
- **Imports**: Remove unused imports in any files that referenced CLI types
- **Documentation**: Update any comments referencing the removed CLI flow

### Gate: REFACTOR

- [ ] No orphaned helper functions remain
- [ ] No unused imports
- [ ] No stale comments referencing removed CLI flow

---

## Phase Complete

When all gates pass:

1. Update this file's status to **Complete**
2. Update index.md status table
3. Delete issue directory: `.agent/docs/issues/cli-oauth-session-token-url-exposure/`
4. Delete this plan directory

---

**Previous:** [Phase 01](01-exchange-endpoint.md)
**Next:** Final phase - cleanup
