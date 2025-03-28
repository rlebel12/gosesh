package gosesh

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

type (
	Gosesh struct {
		store                 Storer
		identifierFromBytes   IDParser
		logger                *slog.Logger
		origin                *url.URL
		allowedHosts          []string
		sessionCookieName     string
		oAuth2StateCookieName string
		redirectCookieName    string
		redirectParamName     string
		sessionActiveDuration time.Duration
		sessionIdleDuration   time.Duration
		now                   func() time.Time
		cookieDomain          func() string
	}

	IDParser func([]byte) (Identifier, error)

	Identifier interface {
		fmt.Stringer
	}
)

func (gs *Gosesh) Host() string {
	return gs.origin.Host
}

func (gs *Gosesh) Scheme() string {
	return gs.origin.Scheme
}

func (gs *Gosesh) CookieDomain() string {
	return gs.cookieDomain()
}

func New(parser IDParser, store Storer, opts ...NewOpts) *Gosesh {
	url, _ := url.Parse("http://localhost")
	gs := &Gosesh{
		store:                 store,
		identifierFromBytes:   parser,
		sessionCookieName:     "session",
		oAuth2StateCookieName: "oauthstate",
		redirectCookieName:    "redirect",
		redirectParamName:     "next",
		sessionActiveDuration: 1 * time.Hour,
		sessionIdleDuration:   24 * time.Hour,
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

func WithRedirectCookieName(name string) func(*Gosesh) {
	return func(c *Gosesh) {
		c.redirectCookieName = name
	}
}

func WithRedirectParamName(name string) func(*Gosesh) {
	return func(c *Gosesh) {
		c.redirectParamName = name
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

func WithAllowedHosts(hosts ...string) func(*Gosesh) {
	return func(c *Gosesh) {
		c.allowedHosts = append(c.allowedHosts, hosts...)
	}
}

func WithCookieDomain(fn func(*Gosesh) func() string) func(*Gosesh) {
	return func(c *Gosesh) {
		c.cookieDomain = fn(c)
	}
}

type (
	Storer interface {
		UpsertUser(ctx context.Context, user OAuth2User) (Identifier, error)
		CreateSession(ctx context.Context, req CreateSessionRequest) (Session, error)
		GetSession(ctx context.Context, sessionID Identifier) (Session, error)
		DeleteSession(ctx context.Context, sessionID Identifier) error
		DeleteUserSessions(ctx context.Context, userID Identifier) (int, error)
	}

	Session interface {
		ID() Identifier
		UserID() Identifier
		IdleAt() time.Time
		ExpireAt() time.Time
	}

	CreateSessionRequest struct {
		UserID   Identifier
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

	OAuth2Credentials interface {
		ClientID() string
		ClientSecret() string
	}
)

func (gs *Gosesh) logError(msg string, err error, args ...any) {
	if gs.logger == nil {
		return
	}
	args = append([]any{"error", err.Error()}, args...)
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
