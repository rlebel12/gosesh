package gosesh

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

// RawSessionID is the unprocessed session identifier generated with crypto/rand.
// This is the value stored in cookies or returned to clients.
// It should never be stored directly in the backing store.
type RawSessionID string

// String returns the string representation of the raw session ID.
func (r RawSessionID) String() string {
	return string(r)
}

// IsZero returns true if the raw session ID is empty.
func (r RawSessionID) IsZero() bool {
	return r == ""
}

// HashedSessionID is the cryptographically hashed session identifier.
// This is the value stored in the backing store and used for lookups.
// It is derived from RawSessionID using SHA-256 or HMAC-SHA256.
type HashedSessionID string

// String returns the string representation of the hashed session ID.
func (h HashedSessionID) String() string {
	return string(h)
}

// IsZero returns true if the hashed session ID is empty.
func (h HashedSessionID) IsZero() bool {
	return h == ""
}

// SessionIDGenerator generates a new raw session ID.
// The default implementation uses crypto/rand with 256 bits of entropy.
type SessionIDGenerator func() (RawSessionID, error)

// SessionIDHasher hashes a raw session ID to produce a hashed session ID for storage.
// The default implementation uses SHA-256. HMAC-SHA256 can be configured via options.
type SessionIDHasher func(RawSessionID) HashedSessionID

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
	idGenerator            SessionIDGenerator
	idHasher               SessionIDHasher
}

// AuthProviderID is an opaque identifier returned by the OAuth provider's UnmarshalFunc.
// It is passed into Storer.UpsertUser and never interpreted by gosesh.
type AuthProviderID = any

// UserID is the consumer's internal user identifier, returned by Storer.UpsertUser.
// It is used in CreateSession, Session.UserID(), and DeleteUserSessions.
type UserID = any

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

// defaultSessionIDGenerator generates a new session ID using crypto/rand.
// It produces 32 bytes (256 bits) of entropy, base64url-encoded without padding.
func defaultSessionIDGenerator() (RawSessionID, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("generate session ID: %w", err)
	}
	return RawSessionID(base64.RawURLEncoding.EncodeToString(b)), nil
}

// defaultSessionIDHasher hashes a raw session ID using SHA-256.
// The output is hex-encoded for consistent string representation.
func defaultSessionIDHasher(raw RawSessionID) HashedSessionID {
	hash := sha256.Sum256([]byte(raw))
	return HashedSessionID(hex.EncodeToString(hash[:]))
}

// newHMACSessionIDHasher creates an HMAC-SHA256 hasher with the given secret.
// The returned hasher can be used to hash session IDs with a secret key.
func newHMACSessionIDHasher(secret []byte) SessionIDHasher {
	return func(raw RawSessionID) HashedSessionID {
		h := hmac.New(sha256.New, secret)
		h.Write([]byte(raw))
		return HashedSessionID(hex.EncodeToString(h.Sum(nil)))
	}
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
		idGenerator:           defaultSessionIDGenerator,
		idHasher:              defaultSessionIDHasher,
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

// WithSessionIDGenerator sets a custom session ID generator.
// If not specified, the default generator uses crypto/rand with 256 bits of entropy.
func WithSessionIDGenerator(gen SessionIDGenerator) NewOpts {
	return func(gs *Gosesh) {
		gs.idGenerator = gen
	}
}

// WithHMACSessionIDHasher sets an HMAC-SHA256 session ID hasher with the given secret.
// This provides an additional layer of security over the default SHA-256 hasher.
// The secret should be kept secure and rotated periodically.
func WithHMACSessionIDHasher(secret []byte) NewOpts {
	return func(gs *Gosesh) {
		gs.idHasher = newHMACSessionIDHasher(secret)
	}
}

// Storer is the interface that must be implemented by storage backends.
// It defines the methods required for managing users and sessions.
type Storer interface {
	// UpsertUser creates or updates a user based on their OAuth2 provider ID.
	UpsertUser(ctx context.Context, authProviderID AuthProviderID) (userID UserID, err error)
	// CreateSession creates a new session for a user with the specified deadlines.
	// hashedID is the pre-hashed session identifier to store.
	// idleDeadline is when the session expires from inactivity.
	// absoluteDeadline is when the session expires regardless of activity.
	CreateSession(ctx context.Context, hashedID HashedSessionID, userID UserID, idleDeadline, absoluteDeadline time.Time) (Session, error)
	// ExtendSession extends the idle deadline of an existing session.
	// This is used to refresh a session's TTL without creating a new session.
	ExtendSession(ctx context.Context, hashedID HashedSessionID, newIdleDeadline time.Time) error
	// GetSession retrieves a session by its hashed ID.
	GetSession(ctx context.Context, hashedID HashedSessionID) (Session, error)
	// DeleteSession deletes a session by its hashed ID.
	DeleteSession(ctx context.Context, hashedID HashedSessionID) error
	// DeleteUserSessions deletes all sessions for a user, returning the number of sessions deleted.
	DeleteUserSessions(ctx context.Context, userID UserID) (int, error)
}

// Session represents an active user session.
type Session interface {
	// ID returns the hashed session identifier as stored in the backing store.
	ID() HashedSessionID
	// UserID returns the ID of the user associated with this session.
	UserID() UserID
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
	BatchRecordActivity(ctx context.Context, updates map[HashedSessionID]time.Time) (int, error)
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

	// ReadSessionID extracts the raw (unhashed) session ID from a request.
	// Returns empty RawSessionID if no credential is present.
	ReadSessionID(r *http.Request) RawSessionID

	// WriteSession writes the session credential to the response using the raw session ID.
	// For sources that cannot write (e.g., header-based auth where client stores token),
	// this should be a no-op and return nil.
	WriteSession(w http.ResponseWriter, rawID RawSessionID, session Session) error

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

// rawSessionIDContextKey is the context key for storing raw session IDs.
type rawSessionIDContextKey struct{}

// rawSessionIDKey is the singleton context key instance.
var rawSessionIDKey = rawSessionIDContextKey{}

// RawSessionIDFromContext retrieves the raw session ID from the context.
// Returns the session ID and true if present, or an empty ID and false if not.
func RawSessionIDFromContext(ctx context.Context) (RawSessionID, bool) {
	id, ok := ctx.Value(rawSessionIDKey).(RawSessionID)
	return id, ok
}
