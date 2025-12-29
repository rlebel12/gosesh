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
