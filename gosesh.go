package gosesh

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

func New[T Identifier](deps GoseshDependencies[T], opts ...NewOpts[T]) (*Gosesh[T], error) {
	if deps.IDParser == nil {
		return nil, fmt.Errorf("IDParser is required")
	} else if deps.Store == nil {
		return nil, fmt.Errorf("store is required")
	}

	gs := &Gosesh[T]{
		Store:    deps.Store,
		IDParser: deps.IDParser,
	}

	for _, opt := range opts {
		opt(gs)
	}

	if gs.Config == nil {
		gs.Config = NewConfig()
	}

	return gs, nil
}

type Gosesh[T Identifier] struct {
	Config   *Config
	Store    Storer
	IDParser IDParser[T]
}

type GoseshDependencies[T Identifier] struct {
	IDParser[T]
	Store Storer
}

type NewOpts[T Identifier] func(*Gosesh[T])

func WithConfig(opts ...ConfigOpts) func(*Gosesh[Identifier]) {
	return func(g *Gosesh[Identifier]) {
		g.Config = NewConfig(opts...)
	}
}

type IDParser[T Identifier] func([]byte) (T, error)

type OAuthProviderConfig struct {
	ClientID     string
	ClientSecret string
}

func NewConfig(opts ...ConfigOpts) *Config {
	config := &Config{
		Providers:             map[string]OAuthProviderConfig{},
		SessionCookieName:     defaultAuthSessionCookieName,
		OAuth2StateCookieName: defaultOAuthStateCookieName,
		SessionIdleDuration:   defaultSessionIdleDuration,
		SessionActiveDuration: defaultSessionActiveDuration,
	}
	for _, opt := range opts {
		opt(config)
	}
	return config
}

type Config struct {
	Origin *url.URL

	SessionCookieName     string
	OAuth2StateCookieName string

	SessionIdleDuration   time.Duration
	SessionActiveDuration time.Duration

	Providers map[string]OAuthProviderConfig
}

type ConfigOpts func(*Config)

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

func WithOrigin(origin *url.URL) func(*Config) {
	return func(c *Config) {
		c.Origin = origin
	}
}

type Identifier interface {
	fmt.Stringer
}

type Session struct {
	ID       Identifier
	UserID   Identifier
	IdleAt   time.Time
	ExpireAt time.Time
}

type CreateSessionRequest struct {
	UserID   Identifier
	IdleAt   time.Time
	ExpireAt time.Time
}

type UpdateSessionValues struct {
	IdleAt   time.Time
	ExpireAt time.Time
}

type OAuth2User interface {
	Identifier
	Request(ctx context.Context, accessToken string) (*http.Response, error)
	Unmarshal(b []byte) error
}

type Storer interface {
	UpsertUser(ctx context.Context, udr OAuth2User) (Identifier, error)
	CreateSession(ctx context.Context, req CreateSessionRequest) (*Session, error)
	GetSession(ctx context.Context, sessionID Identifier) (*Session, error)
	UpdateSession(ctx context.Context, sessionID Identifier, req UpdateSessionValues) (*Session, error)
	DeleteSession(ctx context.Context, sessionID Identifier) error
	DeleteUserSessions(ctx context.Context, userID Identifier) (int, error)
}
