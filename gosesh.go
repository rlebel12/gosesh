package gosesh

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"time"
)

// Gosesh is the main type that provides OAuth2 authentication and session management.
// It handles the OAuth2 flow, session creation and validation, and provides middleware
// for protecting routes.
type Gosesh struct {
	store                 Storer
	logger                *slog.Logger
	origin                *url.URL
	allowedHosts          []string
	sessionCookieName     string
	oAuth2StateCookieName string
	redirectCookieName    string
	redirectParamName     string
	sessionIdleTimeout      time.Duration
	sessionMaxLifetime      time.Duration
	sessionRefreshThreshold time.Duration
	now                   func() time.Time
	cookieDomain          func() string
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
		sessionCookieName:     "session",
		oAuth2StateCookieName: "oauthstate",
		redirectCookieName:    "redirect",
		redirectParamName:     "next",
		sessionIdleTimeout:      1 * time.Hour,
		sessionMaxLifetime:      24 * time.Hour,
		sessionRefreshThreshold: 10 * time.Minute,
		origin:                url,
		allowedHosts:          []string{url.Hostname()},
		now:                   time.Now,
	}
	gs.cookieDomain = func() string { return gs.origin.Hostname() }
	for _, opt := range opts {
		opt(gs)
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
