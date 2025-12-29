package gosesh

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAudienceValidationError_ErrorMessage tests the error message formatting
// for AudienceValidationError with different audience configurations.
func TestAudienceValidationError_ErrorMessage(t *testing.T) {
	tests := []struct {
		name     string
		err      *AudienceValidationError
		expected string
	}{
		{
			name: "error_message_single_audience",
			err: &AudienceValidationError{
				Expected: []string{"client-a"},
				Actual:   "client-b",
			},
			expected: `validate audience: want=[client-a] got="client-b"`,
		},
		{
			name: "error_message_multiple_audiences",
			err: &AudienceValidationError{
				Expected: []string{"client-a", "client-b"},
				Actual:   "client-c",
			},
			expected: `validate audience: want=[client-a client-b] got="client-c"`,
		},
		{
			name: "error_message_empty_actual",
			err: &AudienceValidationError{
				Expected: []string{"client-a"},
				Actual:   "",
			},
			expected: `validate audience: want=[client-a] got=""`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.err.Error()
			assert.Equal(t, tt.expected, actual)
		})
	}
}

// TestErrFailedValidatingAudience_Sentinel tests that the sentinel error
// works correctly with errors.Is() when wrapped.
func TestErrFailedValidatingAudience_Sentinel(t *testing.T) {
	wrappedErr := fmt.Errorf("%w: %w", ErrFailedValidatingAudience, &AudienceValidationError{
		Expected: []string{"client-a"},
		Actual:   "client-b",
	})

	assert.True(t, errors.Is(wrappedErr, ErrFailedValidatingAudience))
}

// TestErrFailedValidatingAudience_Unwrap tests that errors.As() can extract
// the structured AudienceValidationError from a wrapped error.
func TestErrFailedValidatingAudience_Unwrap(t *testing.T) {
	originalErr := &AudienceValidationError{
		Expected: []string{"client-a"},
		Actual:   "client-b",
	}
	wrappedErr := fmt.Errorf("some context: %w", originalErr)

	var audErr *AudienceValidationError
	assert.True(t, errors.As(wrappedErr, &audErr))
	assert.Equal(t, []string{"client-a"}, audErr.Expected)
	assert.Equal(t, "client-b", audErr.Actual)
}

// fakeAudienceValidator is a test double for the AudienceValidator interface.
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

// applyOptions is a helper to inspect config after applying options.
func applyOptions(opts ...ExchangeOption) *exchangeConfig {
	t := &testing.T{} // Dummy for helper
	t.Helper()
	cfg := &exchangeConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

// TestFunctionalOptions_Parameterized tests WithAudienceValidator and
// WithExpectedAudiences functional options with various configurations.
func TestFunctionalOptions_Parameterized(t *testing.T) {
	fakeValidator := &fakeAudienceValidator{audience: "test-aud", err: nil}

	tests := []struct {
		name             string
		options          []ExchangeOption
		checkValidator   bool
		expectedValidator AudienceValidator
		checkAudiences   bool
		expectedAudiences []string
	}{
		{
			name:             "with_validator_sets_validator",
			options:          []ExchangeOption{WithAudienceValidator(fakeValidator)},
			checkValidator:   true,
			expectedValidator: fakeValidator,
			checkAudiences:   false,
		},
		{
			name:             "with_single_audience",
			options:          []ExchangeOption{WithExpectedAudiences("client-a")},
			checkValidator:   false,
			checkAudiences:   true,
			expectedAudiences: []string{"client-a"},
		},
		{
			name:             "with_multiple_audiences",
			options:          []ExchangeOption{WithExpectedAudiences("client-a", "client-b")},
			checkValidator:   false,
			checkAudiences:   true,
			expectedAudiences: []string{"client-a", "client-b"},
		},
		{
			name:             "with_empty_audiences",
			options:          []ExchangeOption{WithExpectedAudiences()},
			checkValidator:   false,
			checkAudiences:   true,
			expectedAudiences: []string{},
		},
		{
			name: "with_both_options",
			options: []ExchangeOption{
				WithAudienceValidator(fakeValidator),
				WithExpectedAudiences("a"),
			},
			checkValidator:   true,
			expectedValidator: fakeValidator,
			checkAudiences:   true,
			expectedAudiences: []string{"a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := applyOptions(tt.options...)

			if tt.checkValidator {
				assert.Equal(t, tt.expectedValidator, cfg.audienceValidator)
			}
			if tt.checkAudiences {
				assert.Equal(t, tt.expectedAudiences, cfg.expectedAudiences)
			}
		})
	}
}

// TestFunctionalOptions_OrderingIndependence verifies that options can be
// applied in any order with the same result.
func TestFunctionalOptions_OrderingIndependence(t *testing.T) {
	validator := &fakeAudienceValidator{audience: "test", err: nil}

	// Apply options in different orders
	cfg1 := applyOptions(
		WithAudienceValidator(validator),
		WithExpectedAudiences("client-a", "client-b"),
	)

	cfg2 := applyOptions(
		WithExpectedAudiences("client-a", "client-b"),
		WithAudienceValidator(validator),
	)

	assert.Equal(t, cfg1.audienceValidator, cfg2.audienceValidator)
	assert.Equal(t, cfg1.expectedAudiences, cfg2.expectedAudiences)
}

// TestFunctionalOptions_EdgeCases tests edge cases for functional options.
func TestFunctionalOptions_EdgeCases(t *testing.T) {
	t.Run("nil_validator_sets_nil", func(t *testing.T) {
		cfg := applyOptions(WithAudienceValidator(nil))
		assert.Nil(t, cfg.audienceValidator)
	})

	t.Run("empty_variadic_audiences", func(t *testing.T) {
		cfg := applyOptions(WithExpectedAudiences())
		assert.NotNil(t, cfg.expectedAudiences)
		assert.Empty(t, cfg.expectedAudiences)
	})

	t.Run("calling_same_option_twice_last_wins", func(t *testing.T) {
		validator1 := &fakeAudienceValidator{audience: "first", err: nil}
		validator2 := &fakeAudienceValidator{audience: "second", err: nil}

		cfg := applyOptions(
			WithAudienceValidator(validator1),
			WithAudienceValidator(validator2),
		)

		assert.Equal(t, validator2, cfg.audienceValidator)
	})

	t.Run("calling_audiences_twice_last_wins", func(t *testing.T) {
		cfg := applyOptions(
			WithExpectedAudiences("first"),
			WithExpectedAudiences("second", "third"),
		)

		assert.Equal(t, []string{"second", "third"}, cfg.expectedAudiences)
	})
}

// TestFunctionalOptions_NoSideEffects ensures options don't affect unrelated
// config fields.
func TestFunctionalOptions_NoSideEffects(t *testing.T) {
	validator := &fakeAudienceValidator{audience: "test", err: nil}

	// Set validator, ensure audiences remain nil
	cfg1 := applyOptions(WithAudienceValidator(validator))
	assert.NotNil(t, cfg1.audienceValidator)
	assert.Nil(t, cfg1.expectedAudiences)

	// Set audiences, ensure validator remains nil
	cfg2 := applyOptions(WithExpectedAudiences("client-a"))
	assert.Nil(t, cfg2.audienceValidator)
	assert.NotNil(t, cfg2.expectedAudiences)
}

// TestWithExpectedAudiences_DefensiveCopy verifies that the audiences slice
// is copied to prevent external mutation.
func TestWithExpectedAudiences_DefensiveCopy(t *testing.T) {
	audiences := []string{"client-a", "client-b"}
	cfg := applyOptions(WithExpectedAudiences(audiences...))

	// Mutate the original slice
	audiences[0] = "mutated"

	// Config should still have the original values
	assert.Equal(t, []string{"client-a", "client-b"}, cfg.expectedAudiences)
}
