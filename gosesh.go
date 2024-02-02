package gosesh

import (
	"context"
	"net/url"
	"time"

	"github.com/google/uuid"
)

func New(store Storer) *Gosesh {
	config := &Config{
		Providers:             map[string]OAuthProviderConfig{},
		AuthSessionCookieName: defaultAuthSessionCookieName,
		OAuthStateCookieName:  defaultOAuthStateCookieName,
		SessionIdleDuration:   defaultSessionIdleDuration,
		SessionActiveDuration: defaultSessionActiveDuration,
	}

	gs := &Gosesh{
		Config: config,
		Store:  store,
	}

	return gs
}

type Gosesh struct {
	Config *Config
	Store  Storer
	CallbackRedirecter
}

type OAuthProviderConfig struct {
	ClientID     string
	ClientSecret string
}

type Config struct {
	Origin *url.URL

	AuthSessionCookieName string
	OAuthStateCookieName  string

	SessionIdleDuration   time.Duration
	SessionActiveDuration time.Duration

	AllowedRedirectDomains []string

	Providers map[string]OAuthProviderConfig
}

type User struct {
	ID    uuid.UUID
	Email string
}

type Session struct {
	ID       uuid.UUID
	UserID   uuid.UUID
	IdleAt   time.Time
	ExpireAt time.Time
}

type UpsertUserRequest struct {
	Email string
}

type CreateSessionRequest struct {
	User     *User
	IdleAt   time.Time
	ExpireAt time.Time
}

type UpdateSessionValues struct {
	IdleAt   time.Time
	ExpireAt time.Time
}

type Storer interface {
	UpsertUser(ctx context.Context, req UpsertUserRequest) (*User, error)
	GetUser(ctx context.Context, userID uuid.UUID) (*User, error)
	CreateSession(ctx context.Context, req CreateSessionRequest) (*Session, error)
	GetSession(ctx context.Context, sessionID uuid.UUID) (*Session, error)
	UpdateSession(ctx context.Context, sessionID uuid.UUID, req UpdateSessionValues) (*Session, error)
	DeleteSession(ctx context.Context, sessionID uuid.UUID) error
	DeleteUserSessions(ctx context.Context, userID uuid.UUID) (int, error)
}

type CallbackRedirecter interface {
	SetURL(ctx context.Context, oAuthState string, redirectURL *url.URL) error
	GetURL(ctx context.Context, oAuthState string) (*url.URL, error)
}
