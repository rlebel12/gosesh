package gosesh

import (
	"context"
	"fmt"
)

// ExchangeOption configures optional behavior for ExchangeExternalToken.
// Following gosesh's functional options pattern (see NewOpts in gosesh.go).
type ExchangeOption func(*exchangeConfig)

// exchangeConfig holds optional configuration for token exchange.
// Zero values indicate "not configured". Unexported - only accessed via options.
type exchangeConfig struct {
	audienceValidator AudienceValidator
	expectedAudiences []string
}

// AudienceValidator validates an OAuth2 access token and returns the audience claim.
// Implementations should verify the token with the identity provider and extract the
// audience (aud) claim. The context parameter allows for timeout/cancellation control.
type AudienceValidator interface {
	ValidateAudience(ctx context.Context, accessToken string) (audience string, err error)
}

// AudienceValidationError indicates a token's audience didn't match expected values.
// It provides structured error context with both expected and actual audience values.
// Use with ErrFailedValidatingAudience sentinel via errors.Is() and errors.As().
type AudienceValidationError struct {
	Expected []string
	Actual   string
}

// Error implements the error interface, formatting the error message to show
// expected vs actual audience values.
func (e *AudienceValidationError) Error() string {
	return fmt.Sprintf("validate audience: want=%v got=%q", e.Expected, e.Actual)
}

// WithAudienceValidator sets a validator for checking token audience claims.
// The validator is called during token exchange to verify the access token's
// audience matches expected values. Pass nil to explicitly disable validation.
func WithAudienceValidator(v AudienceValidator) ExchangeOption {
	return func(cfg *exchangeConfig) {
		cfg.audienceValidator = v
	}
}

// WithExpectedAudiences sets the allowed audience values for token validation.
// During token exchange, if an audience validator is configured, the actual
// audience claim will be checked against this list. Empty list allows any audience.
func WithExpectedAudiences(audiences ...string) ExchangeOption {
	return func(cfg *exchangeConfig) {
		// Create defensive copy to prevent external mutation of the slice.
		// If we stored audiences directly, the caller could modify the slice
		// after passing it, causing unexpected behavior in the handler.
		// Use make to ensure we always get a non-nil slice, even when empty.
		cfg.expectedAudiences = make([]string, len(audiences))
		copy(cfg.expectedAudiences, audiences)
	}
}
