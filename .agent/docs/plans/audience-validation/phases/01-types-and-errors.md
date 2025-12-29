# Phase 01: Types and Errors

**Depends on:** None
**Status:** Pending

---

## RED: Write Tests

**Objective:** Define and test foundational types: `ExchangeOption`, `exchangeConfig`, `AudienceValidator` interface, and error types.

**Files:**

- `audience_test.go` (new)

**Test Cases:**

**Parameterized Tests** (table format):

| Case Name | Input | Expected | Notes |
|-----------|-------|----------|-------|
| `error_message_single_audience` | `AudienceValidationError{Expected: []string{"client-a"}, Actual: "client-b"}` | `"validate audience: want=[client-a] got=\"client-b\""` | Single expected audience |
| `error_message_multiple_audiences` | `AudienceValidationError{Expected: []string{"client-a", "client-b"}, Actual: "client-c"}` | `"validate audience: want=[client-a client-b] got=\"client-c\""` | Multiple expected audiences |
| `error_message_empty_actual` | `AudienceValidationError{Expected: []string{"client-a"}, Actual: ""}` | `"validate audience: want=[client-a] got=\"\""` | Empty actual audience |

**Discrete Tests:**

- **Test ErrFailedValidatingAudience sentinel**: Verify `errors.Is()` works with wrapped errors:
  ```go
  wrappedErr := fmt.Errorf("%w: %w", ErrFailedValidatingAudience, &AudienceValidationError{...})
  assert.True(errors.Is(wrappedErr, ErrFailedValidatingAudience))
  ```
- **Test error unwrapping preserves structured error**: Verify `errors.As()` extracts the structured error:
  ```go
  var audErr *AudienceValidationError
  assert.True(errors.As(wrappedErr, &audErr))
  assert.Equal([]string{"client-a"}, audErr.Expected)
  ```

**Assertions:**

- `AudienceValidationError.Error()` returns correctly formatted message
- `errors.Is(wrappedErr, ErrFailedValidatingAudience)` returns true when wrapped
- `errors.As(wrappedErr, &audErr)` returns true and extracts the `AudienceValidationError`

**Edge Cases:**

- Empty expected audiences slice
- Empty actual audience string
- Error wrapping preserves sentinel for `errors.Is()` checks

**Test Data:**

```go
// Test error struct creation
validationErr := &AudienceValidationError{
    Expected: []string{"client-a", "client-b"},
    Actual:   "client-c",
}

// Wrapped error for sentinel testing
wrappedErr := fmt.Errorf("some context: %w", ErrFailedValidatingAudience)
```

### Gate: RED

- [ ] Test file created with all enumerated test cases
- [ ] All tests FAIL (implementation does not exist yet)
- [ ] Test coverage includes happy path and all edge cases

---

## GREEN: Implement

**Objective:** Implement the foundational types and error definitions.

**Files:**

- `audience.go` (new - types and interface)
- `errors.go` (add sentinel error)

**Implementation Guidance:**

```go
// audience.go

// ExchangeOption configures optional behavior for ExchangeExternalToken.
// Following gosesh's functional options pattern (see NewOpts in gosesh.go).
//
// Implementation approach:
// 1. Define as function type that modifies *exchangeConfig
// 2. Keep unexported exchangeConfig for internal use only
type ExchangeOption func(*exchangeConfig)

// exchangeConfig holds optional configuration for token exchange.
//
// Implementation approach:
// 1. Struct with two fields: audienceValidator and expectedAudiences
// 2. Zero values indicate "not configured"
// 3. Unexported - only accessed via options
type exchangeConfig struct {
    // ...
}

// AudienceValidator validates an OAuth2 access token and returns the audience claim.
//
// Implementation approach:
// 1. Single method interface for flexibility
// 2. Accept context for timeout/cancellation control
// 3. Return audience string on success, error on failure
type AudienceValidator interface {
    ValidateAudience(ctx context.Context, accessToken string) (audience string, err error)
}

// AudienceValidationError indicates a token's audience didn't match expected values.
//
// Implementation approach:
// 1. Struct with Expected []string and Actual string fields
// 2. Error() method formats: "validate audience: want=%v got=%q"
// 3. Follows gosesh pattern of structured errors with context
type AudienceValidationError struct {
    // ...
}

func (e *AudienceValidationError) Error() string {
    // Format: "validate audience: want=[client-a client-b] got="client-c""
    // Use fmt.Sprintf with %v for slice and %q for quoted string
}
```

```go
// errors.go (addition)

// ErrFailedValidatingAudience is a sentinel for audience validation failures.
// Use with errors.Is() to check if an error is related to audience validation.
//
// Implementation approach:
// 1. Add to existing error definitions in errors.go
// 2. Simple errors.New() sentinel
var ErrFailedValidatingAudience = errors.New("failed validating audience")
```

### Gate: GREEN

- [ ] All tests from RED phase now PASS
- [ ] Test command: `go test -v -run TestAudience ./...`
- [ ] Implementation follows pseudocode logic flow

---

## REFACTOR: Quality

**Focus:** Code quality improvements, not new functionality.

**Review Areas:**

- **Naming**: Ensure type names match architecture doc exactly
- **Documentation**: GoDoc comments on exported types following existing gosesh style
- **Consistency**: Error message format matches other gosesh errors

### Gate: REFACTOR

- [ ] Reviewed for code duplication and extracted common patterns
- [ ] Variable and function names are clear and descriptive
- [ ] Complex logic simplified where possible
- [ ] Error messages are helpful and actionable

---

## Phase Complete

When all gates pass:

1. Update this file's status to **Complete**
2. Update index.md status table
3. Proceed to next dependent phase

---

**Previous:** First phase
**Next:** [Phase 02: Functional Options](02-functional-options.md)
