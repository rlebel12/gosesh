# Issue: Improve Test Coverage Before Public Release

---

title: "Improve Test Coverage Before Public Release"
type: improvement
priority: medium
complexity: moderate
estimated_effort: half-day
status: open
context:
  files_involved:
    - providers/google.go
    - providers/discord.go
    - providers/twitch.go
    - providers/provider.go
  conversation_extract: "Code review for potential employer presentation identified low test coverage"

---

## Executive Summary

Test coverage across the gosesh library is uneven, with the providers package at only 7.5% coverage compared to 52.9% for the main package. For a library intended for production use and demonstration to potential employers, this coverage gap undermines confidence in the provider implementations and may raise concerns about code quality during technical reviews.

---

## Current Coverage Levels

### Coverage Report (as of 2026-02-01)

| Package | Coverage | Assessment |
|---------|----------|------------|
| `github.com/rlebel12/gosesh` | 52.9% | Acceptable |
| `github.com/rlebel12/gosesh/e2e` | 45.3% | Expected (E2E tests) |
| `github.com/rlebel12/gosesh/providers` | 7.5% | **Critically Low** |

### Coverage Breakdown by Area

**Well-Covered Areas (Main Package):**
- Handlers and middleware: Good coverage via unit and E2E tests
- Cookie credential source: 342 lines of tests
- Composite credential source: 328 lines of tests
- Activity tracker: 290 lines of tests
- Device code flow: Comprehensive E2E coverage

**Poorly-Covered Areas:**
- `providers/google.go` - User data parsing, error handling
- `providers/discord.go` - Key mode switching, email scope handling
- `providers/twitch.go` - Client-Id header injection, key mode logic
- `providers/provider.go` - Base provider HTTP handling

---

## Investigation Roadmap

### Primary Hypothesis: Provider Tests Rely Too Heavily on E2E

The provider package has low unit test coverage because most testing happens via E2E tests with a fake OAuth provider. While E2E tests validate the flow works, they don't exercise provider-specific edge cases.

**Investigation steps:**
1. Review existing provider tests in `providers/*_test.go`
2. Identify which provider methods lack direct unit tests
3. Check if E2E tests cover provider-specific error paths

**Expected findings:** Provider unit tests exist but only cover happy paths; error handling and edge cases are untested

**If confirmed, resolution approach:** Add targeted unit tests for:
- User data unmarshaling with malformed JSON
- HTTP error responses from provider APIs
- Key mode switching behavior (Discord, Twitch)
- Missing required fields in user data

### Alternative Hypotheses

#### Hypothesis 2: Contract Tests Don't Exercise Implementation Details

- **Investigation steps:** Review `providers/contract_test.go` coverage
- **Expected findings:** Contract tests verify interface compliance but not implementation logic
- **If confirmed, resolution approach:** Add implementation-specific tests alongside contract tests

#### Hypothesis 3: Provider Code Has Low Cyclomatic Complexity

- **Investigation steps:** Analyze provider code for branches and conditionals
- **Expected findings:** Providers may have few code paths, making low coverage less concerning
- **If confirmed, resolution approach:** Document that coverage is acceptable given simplicity; add edge case tests only

---

## Technical Context

### Relevant Files

- `providers/google.go:64` - GoogleUser struct and String() method
- `providers/discord.go:106` - DiscordUser with key mode switching
- `providers/twitch.go:115` - TwitchUser with nested Data array
- `providers/provider.go:104` - Base Provider with HTTP request handling
- `providers/google_audience.go:89` - Token validation (may need more tests)

### Existing Test Files

- `providers/contract_test.go` - Interface compliance verification
- `providers/google_test.go` - Google-specific tests
- `providers/discord_test.go` - Discord-specific tests
- `providers/twitch_test.go` - Twitch-specific tests
- `providers/fake_test.go` - Test helper implementations

### Key Test Gaps

1. **User unmarshaling error paths** - What happens with invalid JSON?
2. **HTTP error handling** - Provider API returns 401, 500, etc.
3. **Key mode edge cases** - Discord/Twitch email mode with missing email
4. **Google audience validator** - Network errors, malformed responses

---

## Success Criteria

- [ ] Provider package coverage reaches at least 50%
- [ ] All provider user types have unmarshaling tests (valid and invalid input)
- [ ] HTTP error scenarios are tested for each provider
- [ ] Key mode switching is tested for Discord and Twitch
- [ ] `make coverage` runs without failures
- [ ] No regression in existing test suite

---

## Conversation Context

Coverage was identified during a comprehensive code review preparing the project for demonstration to potential employers:

```
$ make coverage
ok  	github.com/rlebel12/gosesh	0.200s	coverage: 52.9% of statements in ./...
ok  	github.com/rlebel12/gosesh/e2e	40.265s	coverage: 45.3% of statements in ./...
ok  	github.com/rlebel12/gosesh/providers	0.026s	coverage: 7.5% of statements in ./...
```

The 7.5% provider coverage was flagged as a concern that could undermine confidence during technical reviews with potential employers.

---

## Recommended Test Additions

### Priority 1: User Unmarshaling

```go
func TestGoogleUser_Unmarshal_InvalidJSON(t *testing.T) { ... }
func TestDiscordUser_String_EmailModeNoEmail(t *testing.T) { ... }
func TestTwitchUser_String_EmptyData(t *testing.T) { ... }
```

### Priority 2: HTTP Error Handling

```go
func TestProvider_RequestUser_HTTPError(t *testing.T) { ... }
func TestProvider_RequestUser_NonJSON(t *testing.T) { ... }
```

### Priority 3: Configuration Options

```go
func TestDiscord_WithEmailScope(t *testing.T) { ... }
func TestTwitch_WithEmailScope(t *testing.T) { ... }
```

---

_When issue resolves: Delete this issue directory._
