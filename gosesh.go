package gosesh

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

func New(deps GoseshDependencies, opts ...NewOpts) (*Gosesh, error) {
	if deps.IDParser == nil {
		return nil, fmt.Errorf("IDParser is required")
	} else if deps.Store == nil {
		return nil, fmt.Errorf("store is required")
	}

	gs := &Gosesh{
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

type (
	Gosesh struct {
		Config   *Config
		Store    Storer
		IDParser IDParser
	}

	GoseshDependencies struct {
		IDParser
		Store Storer
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

	NewOpts func(*Gosesh)
)

func WithConfig(opts ...ConfigOpts) func(*Gosesh) {
	return func(g *Gosesh) {
		g.Config = NewConfig(opts...)
	}
}

type (
	ConfigOpts func(*Config)

	Config struct {
		Origin *url.URL

		SessionCookieName     string
		OAuth2StateCookieName string

		SessionIdleDuration   time.Duration
		SessionActiveDuration time.Duration

		Providers map[string]OAuthProviderConfig
	}

	OAuthProviderConfig struct {
		ClientID     string
		ClientSecret string
	}
)

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
