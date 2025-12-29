# Phase 03: Handler Integration

**Depends on:** Phase 02
**Status:** Complete

---

## RED: Write Tests

**Objective:** Test updated `ExchangeExternalToken` handler with audience validation logic.

**Files:**

- `handlers_test.go` (extend existing TestExchangeExternalToken)

**Test Cases:**

**Parameterized Tests** (table format - extend existing test table):

| Case Name | Options | Validator Returns | Expected Outcome | Notes |
|-----------|---------|-------------------|------------------|-------|
| `no_options_backward_compat` | none | N/A | Session created | Existing behavior unchanged |
| `validator_audience_matches` | `WithAudienceValidator(v), WithExpectedAudiences("client-a")` | `"client-a", nil` | Session created | Happy path |
| `validator_audience_mismatch` | `WithAudienceValidator(v), WithExpectedAudiences("client-a")` | `"client-b", nil` | `AudienceValidationError` | Security case |
| `validator_multiple_audiences_match` | `WithAudienceValidator(v), WithExpectedAudiences("a", "b", "c")` | `"b", nil` | Session created | One of many matches |
| `validator_error` | `WithAudienceValidator(v), WithExpectedAudiences("a")` | `"", someError` | Error propagated | Validator failure |
| `validator_no_expected_audiences` | `WithAudienceValidator(v)` | `"any", nil` | Session created | Permissive per Decision 5 |
| `expected_audiences_no_validator` | `WithExpectedAudiences("a")` | N/A | Session created | No validator = no check |

**Discrete Tests:**

- **Test error wrapping**: `AudienceValidationError` is wrapped with `ErrFailedValidatingAudience` sentinel, and both `errors.Is()` and `errors.As()` work:
  ```go
  // Verify sentinel check works
  assert.True(errors.Is(capturedErr, ErrFailedValidatingAudience))
  // Verify structured error extraction works
  var audErr *AudienceValidationError
  assert.True(errors.As(capturedErr, &audErr))
  ```
- **Test done handler receives error**: When validation fails, done handler gets the error
- **Test validation happens before RequestFunc**: If validation fails, RequestFunc should not be called
- **Test context cancellation**: When context is cancelled during validation, error is propagated correctly

**Assertions:**

- Backward compatibility: no options = existing behavior
- Audience match: session created with correct session ID
- Audience mismatch: `AudienceValidationError` with correct Expected/Actual
- `errors.Is(err, ErrFailedValidatingAudience)` returns true for validation errors
- Validator error: original error propagated (not wrapped in AudienceValidationError)

**Edge Cases:**

- Validator returns empty audience string (should fail if expected audiences set)
- Context cancellation during validation
- Multiple options applied in different orders

**Test Data:**

```go
// Fake validator for testing
type fakeAudienceValidator struct {
    audience string
    err      error
    called   bool
    gotToken string
}

func (f *fakeAudienceValidator) ValidateAudience(ctx context.Context, token string) (string, error) {
    f.called = true
    f.gotToken = token
    return f.audience, f.err
}

// Test case structure extension
tests := map[string]struct {
    giveRequestBody   string
    giveRequestFunc   RequestFunc
    giveUnmarshalFunc UnmarshalFunc
    giveOptions       []ExchangeOption  // NEW
    giveStoreSetup    func(t *testing.T, store *erroringStore)
    wantStatusCode    int
    wantErrContains   string
    wantSessionID     bool
    wantValidatorCall bool  // NEW - verify validator was/wasn't called
}{
    // ... test cases
}
```

### Gate: RED

- [x] Test file created with all enumerated test cases
- [x] All tests FAIL (implementation does not exist yet)
- [x] Test coverage includes happy path and all edge cases

---

## GREEN: Implement

**Objective:** Update `ExchangeExternalToken` to accept options and perform audience validation.

**Files:**

- `handlers.go` (modify ExchangeExternalToken)

**Implementation Guidance:**

```go
// File imports (add to existing):
import "slices"  // Go 1.21+ for Contains

// ExchangeExternalToken creates a handler that exchanges an external OAuth2 access token
// for a gosesh session.
//
// Implementation approach:
// 1. Add variadic opts ...ExchangeOption parameter (backward compatible)
// 2. Create exchangeConfig and apply options at handler construction time
// 3. Inside handler closure, after parsing request body:
//    a. If audienceValidator is set, call ValidateAudience with context and token
//    b. If validator returns error, wrap with ErrFailedValidatingAudience and call done
//    c. If expectedAudiences is non-empty, check if returned audience is in list
//    d. If no match, create AudienceValidationError wrapped with sentinel, call done
// 4. Continue to existing RequestFunc flow if validation passes
func (gs *Gosesh) ExchangeExternalToken(
    request RequestFunc,
    unmarshal UnmarshalFunc,
    done HandlerDoneFunc,
    opts ...ExchangeOption,
) http.HandlerFunc {
    // Apply options to config at construction time
    cfg := &exchangeConfig{}
    for _, opt := range opts {
        opt(cfg)
    }

    return func(w http.ResponseWriter, r *http.Request) {
        // Existing: parse request body to get access token

        // NEW: Audience validation block
        if cfg.audienceValidator != nil {
            // Call validator with request context.
            // The validator implementation is responsible for timeout handling.
            // Context cancellation/deadline from r.Context() propagates to validator.
            audience, err := cfg.audienceValidator.ValidateAudience(r.Context(), token)
            if err != nil {
                // Wrap validator error with sentinel.
                // This enables: errors.Is(err, ErrFailedValidatingAudience) == true
                // The underlying error (network, timeout, etc.) is preserved in the chain.
                done(w, r, fmt.Errorf("%w: %w", ErrFailedValidatingAudience, err))
                return
            }

            // Check against expected audiences (only if non-empty - permissive behavior per Decision 5)
            if len(cfg.expectedAudiences) > 0 {
                if !slices.Contains(cfg.expectedAudiences, audience) {
                    // Create structured error with context, wrapped with sentinel.
                    // This enables both:
                    //   errors.Is(err, ErrFailedValidatingAudience) == true
                    //   errors.As(err, &audErr) == true (extracts AudienceValidationError)
                    err := &AudienceValidationError{
                        Expected: cfg.expectedAudiences,
                        Actual:   audience,
                    }
                    done(w, r, fmt.Errorf("%w: %w", ErrFailedValidatingAudience, err))
                    return
                }
            }
        }

        // Continue with existing flow: call RequestFunc, create session, etc.
    }
}
```

**Key Implementation Notes:**

1. **Use `slices.Contains`** from Go 1.21+ for clean audience matching
2. **Error wrapping strategy**: Both validator errors and mismatch errors are wrapped with `ErrFailedValidatingAudience` sentinel using `fmt.Errorf("%w: %w", sentinel, err)`. This enables:
   - `errors.Is(err, ErrFailedValidatingAudience)` returns true for any audience validation failure
   - `errors.As(err, &audErr)` extracts `*AudienceValidationError` when it's an audience mismatch
3. **Context propagation**: The request context `r.Context()` is passed to the validator. The validator is responsible for respecting cancellation and deadlines. Callers can set timeouts via middleware or the HTTP server's timeouts.

### Gate: GREEN

- [x] All tests from RED phase now PASS
- [x] Test command: `go test -v -run TestExchangeExternalToken ./...`
- [x] Implementation follows pseudocode logic flow

---

## REFACTOR: Quality

**Focus:** Code quality improvements, not new functionality.

**Review Areas:**

- **Error wrapping clarity**: Ensure error chain is clear for debugging - verify `errors.Is` and `errors.As` both work as documented
- **Handler complexity**: Consider extracting validation logic to helper if handler becomes too long
- **Import organization**: Ensure `slices` import is grouped with other stdlib imports

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

**Previous:** [Phase 02: Functional Options](02-functional-options.md)
**Next:** [Phase 04: Google Validator](04-google-validator.md)
