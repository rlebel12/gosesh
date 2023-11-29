package identity

import (
	"context"
	"net/url"
	"time"

	"github.com/google/uuid"
)

func New() *Identity {
	i := &Identity{
		Config: &Config{
			Providers: map[string]OAuthProviderConfig{},
		},
	}

	i.Config.AuthSessionCookieName = defaultAuthSessionCookieName
	i.Config.OAuthStateCookieName = defaultOAuthStateCookieName
	i.Config.SessionIdleDuration = defaultSessionIdleDuration
	i.Config.SessionActiveDuration = defaultSessionActiveDuration

	return i
}

type Identity struct {
	Config *Config
	Storer
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
	ID        uuid.UUID
	Email     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Session struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	CreatedAt time.Time
	UpdatedAt time.Time
	IdleAt    time.Time
	ExpireAt  time.Time
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
