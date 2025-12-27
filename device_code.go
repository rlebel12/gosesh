package gosesh

import (
	"context"
	"errors"
	"time"
)

// DeviceCodeEntry represents a pending device authorization.
// It tracks the state of a device code flow, which allows headless clients
// (like native apps or CLI tools) to authenticate by having the user enter a short code
// on another device with a browser.
type DeviceCodeEntry struct {
	// DeviceCode is the long, secret code that the device uses for polling.
	// This should be 32 random bytes, hex encoded (64 characters).
	DeviceCode string

	// UserCode is the short, human-readable code shown to the user.
	// Format: XXXX-XXXX (8 chars from safe alphabet, with hyphen for readability).
	UserCode string

	// ExpiresAt is when this device code authorization expires.
	// Typically 15 minutes from creation.
	ExpiresAt time.Time

	// Interval is the minimum time between poll requests (in seconds).
	// Typically 5 seconds to prevent excessive polling.
	Interval time.Duration

	// SessionID is set when the authorization is completed.
	// Nil until the user authorizes on the web.
	SessionID Identifier

	// Completed indicates whether the user has authorized this device.
	Completed bool

	// LastPoll is the last time the device polled for status.
	// Used for rate limiting to enforce the Interval.
	LastPoll time.Time
}

// DeviceCodeStore manages pending device authorizations.
// Implementations must be thread-safe as they will be accessed concurrently
// by polling devices and authorization callbacks.
type DeviceCodeStore interface {
	// CreateDeviceCode creates a new pending authorization.
	// Returns the device code (long, secret) for the device to use when polling.
	// The userCode should be validated as unique before calling this method.
	CreateDeviceCode(ctx context.Context, userCode string, expiresAt time.Time) (deviceCode string, err error)

	// GetDeviceCode retrieves a pending authorization by device code.
	// Returns ErrDeviceCodeNotFound if the code doesn't exist.
	// Returns ErrDeviceCodeExpired if the code has expired.
	GetDeviceCode(ctx context.Context, deviceCode string) (DeviceCodeEntry, error)

	// GetByUserCode retrieves a pending authorization by user code.
	// This is used when the user enters their code on the authorization page.
	// Returns ErrDeviceCodeNotFound if the code doesn't exist.
	GetByUserCode(ctx context.Context, userCode string) (DeviceCodeEntry, error)

	// CompleteDeviceCode marks an authorization as complete with the session ID.
	// Returns ErrDeviceCodeNotFound if the code doesn't exist.
	// Returns ErrDeviceCodeAlreadyComplete if already completed (idempotency check).
	CompleteDeviceCode(ctx context.Context, deviceCode string, sessionID Identifier) error

	// UpdateLastPoll updates the last poll time for rate limiting.
	// Returns ErrDeviceCodeNotFound if the code doesn't exist.
	UpdateLastPoll(ctx context.Context, deviceCode string, pollTime time.Time) error

	// DeleteDeviceCode removes an authorization.
	// Should be idempotent - deleting a non-existent code returns nil.
	DeleteDeviceCode(ctx context.Context, deviceCode string) error

	// CleanupExpired removes expired entries.
	// Should be called periodically to prevent unbounded growth.
	CleanupExpired(ctx context.Context) error
}

// Device code flow errors
var (
	// ErrDeviceCodeNotFound is returned when a device code doesn't exist in the store.
	ErrDeviceCodeNotFound = errors.New("device code not found")

	// ErrDeviceCodeExpired is returned when attempting to use an expired device code.
	ErrDeviceCodeExpired = errors.New("device code expired")

	// ErrDeviceCodeAlreadyComplete is returned when attempting to complete a device code
	// that has already been completed. This helps prevent race conditions and ensures
	// that each device code can only be used once.
	ErrDeviceCodeAlreadyComplete = errors.New("device code already completed")

	// ErrDeviceCodeRateLimited is returned when a device polls too frequently.
	// Devices should wait at least the interval duration between polls.
	ErrDeviceCodeRateLimited = errors.New("polling too frequently")
)
