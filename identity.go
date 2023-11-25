package identity

import (
	"context"
	"net/url"
	"time"

	"github.com/google/uuid"
)

type Identity struct {
	Storer
	Config
}

type ProviderConfig struct {
	ClientID     string
	ClientSecret string
}

type Config struct {
	Origin url.URL

	Providers struct {
		Google  ProviderConfig
		Discord ProviderConfig
		Twitch  ProviderConfig
	}
}

type User struct {
	ID        uuid.UUID
	Email     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Session struct {
	ID        uuid.UUID
	CreatedAt time.Time
	UpdatedAt time.Time
	IdleAt    time.Time
	ExpireAt  time.Time
	User      *User
}

type UpsertUserRequest struct {
	Email string
}

type CreateSessionRequest struct {
	User     User
	IdleAt   time.Time
	ExpireAt time.Time
}

type UpdateSessionValues struct {
	IdleAt   time.Time
	ExpireAt time.Time
}

type Storer interface {
	UpsertUser(ctx context.Context, req UpsertUserRequest) (User, error)
	GetUser(ctx context.Context, userID uuid.UUID) (User, error)
	CreateSession(ctx context.Context, req CreateSessionRequest) (Session, error)
	GetSession(ctx context.Context, sessionID uuid.UUID) (Session, error)
	UpdateSession(ctx context.Context, sessionID uuid.UUID, req UpdateSessionValues) (Session, error)
	DeleteSession(ctx context.Context, sessionID uuid.UUID) error
	DeleteUserSessions(ctx context.Context, userID uuid.UUID) error
}

func New(c Config, s Storer) Identity {
	return Identity{
		Config: c,
		Storer: s,
	}
}
