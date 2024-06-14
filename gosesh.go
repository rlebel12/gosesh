package gosesh

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

func New(parser IDParser, store Storer, opts ...NewOpts) *Gosesh {
	url, _ := url.Parse("http://localhost")
	gs := &Gosesh{
		store:                 store,
		identifierFromBytes:   parser,
		sessionCookieName:     "session",
		oAuth2StateCookieName: "oauthstate",
		sessionIdleDuration:   24 * time.Hour,
		sessionActiveDuration: 1 * time.Hour,
		origin:                url,
		now:                   time.Now,
	}
	for _, opt := range opts {
		opt(gs)
	}

	return gs
}

func WithLogger(logger *slog.Logger) func(*Gosesh) {
	return func(gs *Gosesh) {
		gs.logger = logger
	}
}

func WithSessionCookieName(name string) func(*Gosesh) {
	return func(c *Gosesh) {
		c.sessionCookieName = name
	}
}

func WithOAuth2StateCookieName(name string) func(*Gosesh) {
	return func(c *Gosesh) {
		c.oAuth2StateCookieName = name
	}
}

func WithSessionIdleDuration(d time.Duration) func(*Gosesh) {
	return func(c *Gosesh) {
		c.sessionIdleDuration = d
	}
}

func WithSessionActiveDuration(d time.Duration) func(*Gosesh) {
	return func(c *Gosesh) {
		c.sessionActiveDuration = d
	}
}

func WithOrigin(origin *url.URL) func(*Gosesh) {
	return func(c *Gosesh) {
		c.origin = origin
	}
}

func (gs *Gosesh) Host() string {
	return gs.origin.Host
}

func (gs *Gosesh) Scheme() string {
	return gs.origin.Scheme
}

type (
	Gosesh struct {
		store                 Storer
		identifierFromBytes   IDParser
		logger                *slog.Logger
		origin                *url.URL
		sessionCookieName     string
		oAuth2StateCookieName string
		sessionIdleDuration   time.Duration
		sessionActiveDuration time.Duration
		now                   func() time.Time
	}

	IDParser func([]byte) (Identifier, error)

	Identifier interface {
		fmt.Stringer
	}

	Storer interface {
		UpsertUser(ctx context.Context, user OAuth2User) (Identifier, error)
		CreateSession(ctx context.Context, req CreateSessionRequest) (*Session, error)
		GetSession(ctx context.Context, sessionID Identifier) (*Session, error)
		UpdateSession(ctx context.Context, sessionID Identifier, req UpdateSessionValues) (*Session, error)
		DeleteSession(ctx context.Context, sessionID Identifier) error
		DeleteUserSessions(ctx context.Context, userID Identifier) (int, error)
	}

	Session struct {
		ID       Identifier
		UserID   Identifier
		IdleAt   time.Time
		ExpireAt time.Time
	}

	CreateSessionRequest struct {
		UserID   Identifier
		IdleAt   time.Time
		ExpireAt time.Time
	}

	UpdateSessionValues struct {
		IdleAt   time.Time
		ExpireAt time.Time
	}

	// Represents a user presented by an OAuth2 provider.
	// Note that this is separate from a user as persisted in your system.
	OAuth2User interface {
		Identifier // Uniquely identifies the user within the OAuth2 provider's system.
		Request(ctx context.Context, accessToken string) (*http.Response, error)
		Unmarshal(b []byte) error
	}

	NewOpts func(*Gosesh)

	OAuth2Credentials struct {
		ClientID     string
		ClientSecret string
	}
)

func (gs *Gosesh) logError(msg string, args ...any) {
	if gs.logger == nil {
		return
	}
	gs.logger.Error(msg, args...)
}

// Do not use: this is exported for testing-purposes only.
func WithNow(fn func() time.Time) func(*Gosesh) {
	return func(c *Gosesh) {
		c.now = fn
	}
}
