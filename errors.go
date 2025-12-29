package gosesh

import "errors"

var (
	ErrFailedGettingStateCookie = errors.New("failed getting state cookie")
	ErrInvalidStateCookie       = errors.New("invalid state cookie")
	ErrFailedExchangingToken    = errors.New("failed exchanging token")
	ErrFailedUnmarshallingData  = errors.New("failed unmarshalling data")
	ErrFailedUpsertingUser      = errors.New("failed upserting user")
	ErrFailedCreatingSession    = errors.New("failed creating session")
	ErrSessionExpired           = errors.New("session expired")

	// ErrFailedValidatingAudience is a sentinel error indicating that audience
	// validation failed during token exchange. Use errors.Is() to check for this
	// error, and errors.As() to extract the AudienceValidationError with details.
	ErrFailedValidatingAudience = errors.New("failed validating audience")
)
