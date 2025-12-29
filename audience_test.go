package gosesh

import (
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
