package gosesh

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

// Gosesh is the main type that provides OAuth2 authentication and session management.
// It handles the OAuth2 flow, session creation and validation, and provides middleware
// for protecting routes.
type Gosesh struct {
	store                   Storer
	logger                  *slog.Logger
	origin                  *url.URL
	allowedHosts            []string
	sessionCookieName       string
	oAuth2StateCookieName   string
	redirectCookieName      string
	redirectParamName       string
	sessionIdleTimeout      time.Duration
	sessionMaxLifetime      time.Duration
	sessionRefreshThreshold time.Duration
	now                     func() time.Time
	cookieDomain            func() string
	credentialSource        CredentialSource
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
		store:                   store,
		sessionCookieName:       "session",
		oAuth2StateCookieName:   "oauthstate",
		redirectCookieName:      "redirect",
		redirectParamName:       "next",
		sessionIdleTimeout:      1 * time.Hour,
		sessionMaxLifetime:      24 * time.Hour,
		sessionRefreshThreshold: 10 * time.Minute,
		origin:                  url,
		allowedHosts:            []string{url.Hostname()},
		now:                     time.Now,
	}
	gs.cookieDomain = func() string { return gs.origin.Hostname() }
	for _, opt := range opts {
		opt(gs)
	}

	// Backward compatibility: if no credential source specified, create a cookie source
	// with the existing configuration options
	if gs.credentialSource == nil {
		gs.credentialSource = NewCookieCredentialSource(
			WithCookieSourceName(gs.sessionCookieName),
			WithCookieSourceDomain(gs.cookieDomain()),
			WithCookieSourceSecure(gs.Scheme() == "https"),
			WithCookieSourceSessionConfig(SessionConfig{
				IdleDuration:     gs.sessionIdleTimeout,
				AbsoluteDuration: gs.sessionMaxLifetime,
				RefreshEnabled:   true,
			}),
		)
	}

	return gs
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

// WithRedirectParamName sets the name of the redirect URL parameter.
func WithRedirectParamName(name string) func(*Gosesh) {
	return func(c *Gosesh) {
		c.redirectParamName = name
	}
}

// WithSessionIdleTimeout sets the duration of inactivity after which a session expires.
// This represents the idle expiry window - the session will expire if there is no activity
// within this duration.
func WithSessionIdleTimeout(d time.Duration) func(*Gosesh) {
	return func(c *Gosesh) {
		c.sessionIdleTimeout = d
	}
}

// WithSessionMaxLifetime sets the absolute maximum lifetime of a session.
// The session will expire after this duration regardless of activity.
func WithSessionMaxLifetime(d time.Duration) func(*Gosesh) {
	return func(c *Gosesh) {
		c.sessionMaxLifetime = d
	}
}

// WithSessionRefreshThreshold sets the time window before idle expiry that triggers a refresh.
// When a session is accessed and its idle deadline is within this threshold, the session
// will be extended to prevent expiry.
func WithSessionRefreshThreshold(d time.Duration) func(*Gosesh) {
	return func(c *Gosesh) {
		c.sessionRefreshThreshold = d
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
// (e.g., cookies for browsers and headers for CLI/API clients).
func WithCredentialSources(sources ...CredentialSource) func(*Gosesh) {
	return func(gs *Gosesh) {
		gs.credentialSource = NewCompositeCredentialSource(sources...)
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
	// RefreshEnabled indicates whether AuthenticateAndRefresh extends the idle deadline.
	// When true, session activity will extend the idle timeout up to the absolute deadline.
	RefreshEnabled bool
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
// - Refresh enabled (activity extends the idle timeout)
func DefaultBrowserSessionConfig() SessionConfig {
	return SessionConfig{
		IdleDuration:     30 * time.Minute,
		AbsoluteDuration: 24 * time.Hour,
		RefreshEnabled:   true,
	}
}

// DefaultCLISessionConfig returns the default session configuration for
// header-based CLI/API sessions. These sessions have:
// - No idle timeout (0 duration means no idle expiry)
// - 30 day absolute timeout (long-lived for CLI convenience)
// - Refresh disabled (tokens are long-lived and not refreshed)
func DefaultCLISessionConfig() SessionConfig {
	return SessionConfig{
		IdleDuration:     0, // No idle timeout
		AbsoluteDuration: 30 * 24 * time.Hour,
		RefreshEnabled:   false,
	}
}

// NewOpts is a function type for configuring a new Gosesh instance.
type NewOpts func(*Gosesh)

func (gs *Gosesh) logError(msg string, err error, args ...any) {
	if gs.logger == nil {
		return
	}
	args = append([]any{"error", err}, args...)
	gs.logger.Error(msg, args...)
}

func (gs *Gosesh) logWarn(msg string, args ...any) {
	if gs.logger == nil {
		return
	}
	gs.logger.Warn(msg, args...)
}

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
