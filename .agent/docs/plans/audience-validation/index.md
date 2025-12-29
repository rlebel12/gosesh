# Implementation Plan: Audience Validation for External Token Exchange

**Related Architecture:** [audience-validation.md](../../architecture/audience-validation.md)

## Phase Overview

| Phase | Description | Depends On | Status |
|-------|-------------|------------|--------|
| [01-types-and-errors](phases/01-types-and-errors.md) | Define ExchangeOption, exchangeConfig, AudienceValidator interface, and error types | None | Complete |
| [02-functional-options](phases/02-functional-options.md) | Implement WithAudienceValidator and WithExpectedAudiences options | Phase 01 | Complete |
| [03-handler-integration](phases/03-handler-integration.md) | Update ExchangeExternalToken to accept and apply options with audience validation logic | Phase 02 | Complete |
| [04-google-validator](phases/04-google-validator.md) | Implement GoogleTokenInfoValidator in providers package | Phase 03 | Pending |

## Dependencies

- **Phase 01 (types-and-errors)**: No dependencies - foundational types
- **Phase 02 (functional-options)**: Requires types from Phase 01
- **Phase 03 (handler-integration)**: Requires options from Phase 02
- **Phase 04 (google-validator)**: Requires interface from Phase 01, can be parallelized with Phase 03 if desired

## Success Criteria

- Existing `ExchangeExternalToken(request, unmarshal, done)` calls continue to work unchanged (backward compatibility)
- Audience validation is opt-in via `WithAudienceValidator` and `WithExpectedAudiences` options
- `AudienceValidationError` provides structured error context with expected vs actual audiences
- `errors.Is(err, ErrFailedValidatingAudience)` works for sentinel error checking
- GoogleTokenInfoValidator correctly calls Google's tokeninfo endpoint and extracts audience
- When validator configured but no expected audiences set, validation is skipped (permissive behavior per architecture Decision 5)
- All new code follows gosesh's existing patterns (functional options, error handling, testing)

## Status

**Progress:** 3/4 phases complete
**Current Phase:** Phase 04 - Google Validator
**Blocked:** None

---

_When implementation completes: Delete this plan directory. Preserve architectural learnings in architecture docs._
