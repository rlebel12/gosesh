package gosesh

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

// Gosesh is the main type that provides OAuth2 authentication and session management.
// It handles the OAuth2 flow, session creation and validation, and provides middleware
// for protecting routes.
type Gosesh struct {
	store                  Storer
	logger                 *slog.Logger
	origin                 *url.URL
	allowedHosts           []string
	sessionCookieName      string
	oAuth2StateCookieName  string
	redirectCookieName     string
	redirectParamName      string
	deviceCodeCookieName   string
	now                    func() time.Time
	cookieDomain           func() string
	credentialSource       CredentialSource
	activityTracker        *ActivityTracker
	activityTrackingConfig *ActivityTrackingConfig
}

// Identifier is an interface that represents a unique identifier for users and sessions.
// It must implement fmt.Stringer to provide a string representation of the identifier.
type Identifier interface {
	fmt.Stringer
}

// Host returns the hostname of the application's origin.
func (gs *Gosesh) Host() string {
	return gs.origin.Host
}

// Scheme returns the scheme (http/https) of the application's origin.
func (gs *Gosesh) Scheme() string {
	return gs.origin.Scheme
}

// CookieDomain returns the domain that cookies should be set for.
func (gs *Gosesh) CookieDomain() string {
	return gs.cookieDomain()
}

// New creates a new Gosesh instance with the provided store and options.
// The store is responsible for persisting user and session data.
func New(store Storer, opts ...NewOpts) *Gosesh {
	url, _ := url.Parse("http://localhost")
	gs := &Gosesh{
		store:                 store,
		logger:                slog.New(slog.NewTextHandler(io.Discard, nil)),
		sessionCookieName:     "session",
		oAuth2StateCookieName: "oauthstate",
		redirectCookieName:    "redirect",
		redirectParamName:     "next",
		deviceCodeCookieName:  "devicecode",
		origin:                url,
		allowedHosts:          []string{url.Hostname()},
		now:                   time.Now,
	}
	gs.cookieDomain = func() string { return gs.origin.Hostname() }

	// Apply all options first
	for _, opt := range opts {
		opt(gs)
	}

	// After all options applied, create activity tracker if enabled.
	// This ensures logger is finalized before tracker creation.
	// The tracker must be started by calling StartBackgroundTasks(ctx) before use.
	if gs.activityTrackingConfig != nil {
		recorder, ok := store.(ActivityRecorder)
		if !ok {
			panic("activity tracking enabled but store does not implement ActivityRecorder interface")
		}
		gs.activityTracker = NewActivityTracker(
			recorder,
			gs.activityTrackingConfig.FlushInterval,
			gs.logger,
		)
	}

	// If no credential source specified, create a default cookie source
	if gs.credentialSource == nil {
		gs.credentialSource = NewCookieCredentialSource(
			WithCookieSourceName(gs.sessionCookieName),
			WithCookieSourceDomain(gs.cookieDomain()),
			WithCookieSourceSecure(gs.Scheme() == "https"),
		)
	}

	return gs
}

// StartBackgroundTasks begins background processing for the Gosesh instance.
// If activity tracking is enabled, this starts the background flush loop.
// The provided context controls the lifetime of background goroutines.
// Returns an error channel for background task errors (nil if no background tasks).
// Callers can type-assert errors to specific types (e.g., *FlushError) for context.
func (gs *Gosesh) StartBackgroundTasks(ctx context.Context) <-chan error {
	if gs.activityTracker != nil {
		gs.activityTracker.Start(ctx)
		return gs.activityTracker.Errors()
	}
	return nil
}

// WithLogger sets a custom logger for the Gosesh instance.
func WithLogger(logger *slog.Logger) func(*Gosesh) {
	return func(gs *Gosesh) {
		gs.logger = logger
	}
}

// WithSessionCookieName sets the name of the session cookie.
func WithSessionCookieName(name string) func(*Gosesh) {
	return func(c *Gosesh) {
		c.sessionCookieName = name
	}
}

// WithOAuth2StateCookieName sets the name of the OAuth2 state cookie.
func WithOAuth2StateCookieName(name string) func(*Gosesh) {
	return func(c *Gosesh) {
		c.oAuth2StateCookieName = name
	}
}

// WithRedirectCookieName sets the name of the redirect cookie.
func WithRedirectCookieName(name string) func(*Gosesh) {
	return func(c *Gosesh) {
		c.redirectCookieName = name
	}
}

// WithDeviceCodeCookieName sets the name of the device code cookie.
func WithDeviceCodeCookieName(name string) func(*Gosesh) {
	return func(c *Gosesh) {
		c.deviceCodeCookieName = name
	}
}

// WithRedirectParamName sets the name of the redirect URL parameter.
func WithRedirectParamName(name string) func(*Gosesh) {
	return func(c *Gosesh) {
		c.redirectParamName = name
	}
}

// WithOrigin sets the application's origin URL.
func WithOrigin(origin *url.URL) func(*Gosesh) {
	return func(c *Gosesh) {
		c.origin = origin
	}
}

// WithAllowedHosts sets the list of allowed hosts for redirects.
func WithAllowedHosts(hosts ...string) func(*Gosesh) {
	return func(c *Gosesh) {
		c.allowedHosts = append(c.allowedHosts, hosts...)
	}
}

// WithCookieDomain sets a custom function to determine the cookie domain.
func WithCookieDomain(fn func(*Gosesh) func() string) func(*Gosesh) {
	return func(c *Gosesh) {
		c.cookieDomain = fn(c)
	}
}

// WithCredentialSource sets the credential source for reading and writing session credentials.
// This allows supporting different authentication methods (cookies, headers, etc.).
// If not specified, a default cookie-based credential source will be created using the
// existing cookie configuration options.
func WithCredentialSource(source CredentialSource) func(*Gosesh) {
	return func(gs *Gosesh) {
		gs.credentialSource = source
	}
}

// WithCredentialSources creates a composite credential source from multiple sources.
// Sources are tried in order - the first one that returns a credential is used.
// This allows supporting multiple authentication methods simultaneously
// (e.g., cookies for browsers and headers for native app/API clients).
func WithCredentialSources(sources ...CredentialSource) func(*Gosesh) {
	return func(gs *Gosesh) {
		gs.credentialSource = NewCompositeCredentialSource(sources...)
	}
}

// WithActivityTracking enables batched activity timestamp tracking.
// Activity timestamps are recorded in memory and flushed to the store at the specified interval.
// This reduces database write load while providing session activity auditability.
// If not specified, activity timestamps are only updated during session extension (ExtendSession).
//
// The store must implement the ActivityRecorder interface. If it doesn't, New() will panic.
func WithActivityTracking(config ActivityTrackingConfig) func(*Gosesh) {
	return func(gs *Gosesh) {
		gs.activityTrackingConfig = &config
	}
}

// Storer is the interface that must be implemented by storage backends.
// It defines the methods required for managing users and sessions.
type Storer interface {
	// UpsertUser creates or updates a user based on their OAuth2 provider ID.
	UpsertUser(ctx context.Context, authProviderID Identifier) (userID Identifier, err error)
	// CreateSession creates a new session for a user with the specified deadlines.
	// idleDeadline is when the session expires from inactivity.
	// absoluteDeadline is when the session expires regardless of activity.
	CreateSession(ctx context.Context, userID Identifier, idleDeadline, absoluteDeadline time.Time) (Session, error)
	// ExtendSession extends the idle deadline of an existing session.
	// This is used to refresh a session's TTL without creating a new session.
	ExtendSession(ctx context.Context, sessionID string, newIdleDeadline time.Time) error
	// GetSession retrieves a session by its ID.
	GetSession(ctx context.Context, sessionID string) (Session, error)
	// DeleteSession deletes a session by its ID.
	DeleteSession(ctx context.Context, sessionID string) error
	// DeleteUserSessions deletes all sessions for a user, returning the number of sessions deleted.
	DeleteUserSessions(ctx context.Context, userID Identifier) (int, error)
}

// Session represents an active user session.
type Session interface {
	// ID returns the session's unique identifier.
	ID() Identifier
	// UserID returns the ID of the user associated with this session.
	UserID() Identifier
	// IdleDeadline returns the time at which the session expires from inactivity.
	IdleDeadline() time.Time
	// AbsoluteDeadline returns the time at which the session expires regardless of activity.
	AbsoluteDeadline() time.Time
	// LastActivityAt returns the timestamp of the most recent session activity.
	// This is updated when the session is created, extended, or when activity is recorded.
	LastActivityAt() time.Time
}

// ActivityRecorder is an optional interface that stores can implement to support
// batched activity tracking. Stores that don't implement this interface can still
// use gosesh, but cannot enable activity tracking via WithActivityTracking().
type ActivityRecorder interface {
	// BatchRecordActivity updates the LastActivityAt timestamp for multiple sessions.
	// Returns the number of sessions successfully updated.
	// Non-existent session IDs are silently ignored.
	// This method must be safe to call concurrently with other store operations.
	BatchRecordActivity(ctx context.Context, updates map[string]time.Time) (int, error)
}

// SessionConfig configures session timeouts for a credential source.
// It defines how long sessions from this source can remain active.
type SessionConfig struct {
	// IdleDuration is the time before idle expiry (0 = no idle timeout).
	// When non-zero, the session expires if there is no activity within this duration.
	IdleDuration time.Duration
	// AbsoluteDuration is the maximum session lifetime (required, must be > 0).
	// The session expires after this duration regardless of activity.
	AbsoluteDuration time.Duration
	// RefreshThreshold controls when AuthenticateAndRefresh extends the idle deadline.
	// - nil: refresh disabled (session never extended)
	// - 0: refresh on every request
	// - >0: refresh when idle deadline is within this threshold
	RefreshThreshold *time.Duration
}

// CredentialSource abstracts how session IDs are read from requests
// and written to responses. This enables support for multiple authentication
// methods (cookies, headers, etc.) with different session configurations.
type CredentialSource interface {
	// Name returns an identifier for this source (used for logging/debugging).
	Name() string

	// ReadSessionID extracts the session ID from a request.
	// Returns empty string if no credential is present.
	ReadSessionID(r *http.Request) string

	// WriteSession writes the session credential to the response.
	// For sources that cannot write (e.g., header-based auth where client stores token),
	// this should be a no-op and return nil.
	WriteSession(w http.ResponseWriter, session Session) error

	// ClearSession removes the credential from the response.
	// For sources that cannot write, this should be a no-op and return nil.
	ClearSession(w http.ResponseWriter) error

	// CanWrite returns whether this source can write credentials to responses.
	// Returns true for cookies, false for headers (where client stores the token).
	CanWrite() bool

	// SessionConfig returns the timeout configuration for sessions from this source.
	// Different sources can have different timeout policies (e.g., short-lived browser
	// sessions vs. long-lived CLI tokens).
	SessionConfig() SessionConfig
}

// DefaultBrowserSessionConfig returns the default session configuration for
// cookie-based browser sessions. These sessions have:
// - 30 minute idle timeout (session expires after 30 minutes of inactivity)
// - 24 hour absolute timeout (session expires after 24 hours regardless of activity)
// - 10 minute refresh threshold (activity extends idle timeout when within 10 min of expiry)
func DefaultBrowserSessionConfig() SessionConfig {
	threshold := 10 * time.Minute
	return SessionConfig{
		IdleDuration:     30 * time.Minute,
		AbsoluteDuration: 24 * time.Hour,
		RefreshThreshold: &threshold,
	}
}

// DefaultNativeAppSessionConfig returns the default session configuration for
// native application sessions (desktop apps, CLI tools, mobile apps). These sessions have:
// - No idle timeout (0 duration means no idle expiry)
// - 30 day absolute timeout (long-lived for native app convenience)
// - Refresh disabled (tokens are long-lived and not refreshed)
func DefaultNativeAppSessionConfig() SessionConfig {
	return SessionConfig{
		IdleDuration:     0, // No idle timeout
		AbsoluteDuration: 30 * 24 * time.Hour,
		RefreshThreshold: nil, // Refresh disabled
	}
}

// NewOpts is a function type for configuring a new Gosesh instance.
type NewOpts func(*Gosesh)

// Do not use: this is exported for testing-purposes only.
func WithNow(fn func() time.Time) func(*Gosesh) {
	return func(c *Gosesh) {
		c.now = fn
	}
}

type StringIdentifier string

func (s StringIdentifier) String() string {
	return string(s)
}
