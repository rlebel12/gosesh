# Phase 02: Functional Options

**Depends on:** Phase 01
**Status:** Pending

---

## RED: Write Tests

**Objective:** Test `WithAudienceValidator` and `WithExpectedAudiences` functional option functions.

**Files:**

- `audience_test.go` (extend)

**Test Cases:**

**Parameterized Tests** (table format):

| Case Name | Options Applied | Expected Config State | Notes |
|-----------|-----------------|----------------------|-------|
| `with_validator_sets_validator` | `WithAudienceValidator(fakeValidator)` | `cfg.audienceValidator == fakeValidator` | Validator is set |
| `with_single_audience` | `WithExpectedAudiences("client-a")` | `cfg.expectedAudiences == []string{"client-a"}` | Single audience |
| `with_multiple_audiences` | `WithExpectedAudiences("client-a", "client-b")` | `cfg.expectedAudiences == []string{"client-a", "client-b"}` | Multiple audiences |
| `with_empty_audiences` | `WithExpectedAudiences()` | `cfg.expectedAudiences == []string{}` | Empty variadic |
| `with_both_options` | `WithAudienceValidator(v), WithExpectedAudiences("a")` | Both fields set | Combined usage |

**Discrete Tests:**

- **Test option ordering independence**: Options can be applied in any order with same result

**Assertions:**

- After applying option, config field is set to expected value
- Multiple options compose correctly
- Options don't affect unrelated config fields

**Edge Cases:**

- Nil validator passed to `WithAudienceValidator` (should set nil)
- Empty variadic to `WithExpectedAudiences` (should set empty slice)
- Calling same option twice (last wins)

**Test Data:**

```go
// Fake validator for testing
type fakeAudienceValidator struct {
    audience string
    err      error
}

func (f *fakeAudienceValidator) ValidateAudience(ctx context.Context, token string) (string, error) {
    return f.audience, f.err
}

// Helper to inspect config after applying options
func applyOptions(opts ...ExchangeOption) *exchangeConfig {
    cfg := &exchangeConfig{}
    for _, opt := range opts {
        opt(cfg)
    }
    return cfg
}
```

### Gate: RED

- [ ] Test file created with all enumerated test cases
- [ ] All tests FAIL (implementation does not exist yet)
- [ ] Test coverage includes happy path and all edge cases

---

## GREEN: Implement

**Objective:** Implement the two functional option constructor functions.

**Files:**

- `audience.go` (extend)

**Implementation Guidance:**

```go
// WithAudienceValidator sets a validator for checking token audience claims.
//
// Implementation approach:
// 1. Return ExchangeOption function that sets cfg.audienceValidator
// 2. Accept nil to explicitly disable (allows clearing a previously set validator)
// 3. Follow same pattern as WithLogger, WithSessionCookieName in gosesh.go
func WithAudienceValidator(v AudienceValidator) ExchangeOption {
    return func(cfg *exchangeConfig) {
        cfg.audienceValidator = v
    }
}

// WithExpectedAudiences sets the allowed audience values for token validation.
//
// Implementation approach:
// 1. Return ExchangeOption function that sets cfg.expectedAudiences
// 2. Accept variadic string arguments for flexibility
// 3. Copy slice to avoid external mutation (defensive copy)
// 4. Empty variadic results in empty slice (which triggers permissive behavior per Decision 5)
func WithExpectedAudiences(audiences ...string) ExchangeOption {
    return func(cfg *exchangeConfig) {
        // Create defensive copy to prevent external mutation of the slice.
        // If we stored audiences directly, the caller could modify the slice
        // after passing it, causing unexpected behavior in the handler.
        cfg.expectedAudiences = append([]string(nil), audiences...)
    }
}
```

### Gate: GREEN

- [ ] All tests from RED phase now PASS
- [ ] Test command: `go test -v -run TestAudience ./...`
- [ ] Implementation follows pseudocode logic flow

---

## REFACTOR: Quality

**Focus:** Code quality improvements, not new functionality.

**Review Areas:**

- **Documentation**: GoDoc comments explain when to use each option
- **Consistency**: Option function style matches existing gosesh options
- **Defensive copying**: Ensure audiences slice is copied, not referenced

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

**Previous:** [Phase 01: Types and Errors](01-types-and-errors.md)
**Next:** [Phase 03: Handler Integration](03-handler-integration.md)
