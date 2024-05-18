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
	config := &Config{
		SessionCookieName:     "session",
		OAuth2StateCookieName: "oauthstate",
		SessionIdleDuration:   24 * time.Hour,
		SessionActiveDuration: 1 * time.Hour,
		Origin:                *url,
		Now:                   time.Now,
	}
	for _, opt := range opts {
		opt(config)
	}

	gs := &Gosesh{
		config:   config,
		store:    store,
		idParser: parser,
	}

	return gs
}

func WithLogger(logger *slog.Logger) func(*Config) {
	return func(cfg *Config) {
		cfg.Logger = logger
	}
}

type (
	Gosesh struct {
		config   *Config
		store    Storer
		idParser IDParser
	}

	IDParser interface {
		Parse([]byte) (Identifier, error)
	}

	Identifier interface {
		fmt.Stringer
	}

	Storer interface {
		UpsertUser(ctx context.Context, udr OAuth2User) (Identifier, error)
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

	OAuth2User interface {
		Identifier
		Request(ctx context.Context, accessToken string) (*http.Response, error)
		Unmarshal(b []byte) error
	}

	NewOpts func(*Config)
)

func (gs *Gosesh) Config() Config {
	return *gs.config
}

func (gs *Gosesh) Storer() Storer {
	return gs.store
}

func (gs *Gosesh) IDParser() IDParser {
	return gs.idParser
}

func (gs *Gosesh) Logger() *slog.Logger {
	return gs.Config().Logger
}

func (gs *Gosesh) logError(msg string, args ...any) {
	if gs.Logger() == nil {
		return
	}
	gs.Logger().Error(msg, args...)
}

type (
	Config struct {
		Origin url.URL

		SessionCookieName     string
		OAuth2StateCookieName string

		SessionIdleDuration   time.Duration
		SessionActiveDuration time.Duration

		Logger *slog.Logger
		Now    func() time.Time
	}

	OAuth2Credentials struct {
		ClientID     string
		ClientSecret string
	}
)

func WithSessionCookieName(name string) func(*Config) {
	return func(c *Config) {
		c.SessionCookieName = name
	}
}

func WithOAuth2StateCookieName(name string) func(*Config) {
	return func(c *Config) {
		c.OAuth2StateCookieName = name
	}
}

func WithSessionIdleDuration(d time.Duration) func(*Config) {
	return func(c *Config) {
		c.SessionIdleDuration = d
	}
}

func WithSessionActiveDuration(d time.Duration) func(*Config) {
	return func(c *Config) {
		c.SessionActiveDuration = d
	}
}

func WithOrigin(origin url.URL) func(*Config) {
	return func(c *Config) {
		c.Origin = origin
	}
}

func WithNow(fn func() time.Time) func(*Config) {
	return func(c *Config) {
		c.Now = fn
	}
}
