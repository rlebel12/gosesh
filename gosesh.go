package gosesh

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

func New[T Identifier](deps GoseshDependencies[T]) (*Gosesh[T], error) {
	if deps.IDParser == nil {
		return nil, fmt.Errorf("IDParser is required")
	} else if deps.Store == nil {
		return nil, fmt.Errorf("store is required")
	}

	config := &Config{
		Providers:             map[string]OAuthProviderConfig{},
		SessionCookieName:     defaultAuthSessionCookieName,
		OAuth2StateCookieName: defaultOAuthStateCookieName,
		SessionIdleDuration:   defaultSessionIdleDuration,
		SessionActiveDuration: defaultSessionActiveDuration,
	}

	gs := &Gosesh[T]{
		Config:   config,
		Store:    deps.Store,
		IDParser: deps.IDParser,
	}
	return gs, nil
}

type GoseshDependencies[T Identifier] struct {
	IDParser[T]
	Store Storer
}

type Gosesh[T Identifier] struct {
	Config   *Config
	Store    Storer
	IDParser IDParser[T]
}

type IDParser[T Identifier] func([]byte) (T, error)

type OAuthProviderConfig struct {
	ClientID     string
	ClientSecret string
}

type Config struct {
	Origin *url.URL

	SessionCookieName     string
	OAuth2StateCookieName string

	SessionIdleDuration   time.Duration
	SessionActiveDuration time.Duration

	Providers map[string]OAuthProviderConfig
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
