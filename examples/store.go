package examples

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/rlebel12/gosesh"
	"github.com/rlebel12/gosesh/providers"
)

var sequenceID int

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		Users:    map[gosesh.Identifier]*CustomIdentifier{},
		Sessions: map[gosesh.Identifier]*Session{},
	}
}

type (
	MemoryStore struct {
		Users    map[gosesh.Identifier]*CustomIdentifier
		Sessions map[gosesh.Identifier]*Session
	}

	CustomIdentifier struct {
		id    int
		email string
	}

	Session struct {
		id       uuid.UUID
		userID   CustomIdentifier
		idleAt   time.Time
		expireAt time.Time
	}
)

func (ci CustomIdentifier) String() string {
	return fmt.Sprintf("%d (%s)", ci.id, ci.email)
}

func (ms *MemoryStore) UpsertUser(ctx context.Context, user gosesh.OAuth2User) (gosesh.Identifier, error) {
	switch d := user.(type) {
	case *providers.DiscordUser:
		slog.Info("Discord user", "id", d.ID, "username", d.Username, "email", d.Email, "verified", d.Verified)
	// case providers.GoogleUser:
	// 	slog.Info("Google user", "id", d.ID, "email", d.Email)
	default:
		slog.Info("Unknown user", "id", user.String())
	}
	for _, user := range ms.Users {
		if user.email == user.String() {
			return user, nil
		}
	}
	u := &CustomIdentifier{
		id: sequenceID,
	}
	sequenceID++
	ms.Users[u] = u
	return u, nil
}

func (ms *MemoryStore) CreateSession(ctx context.Context, req gosesh.CreateSessionRequest) (gosesh.Session, error) {
	userID, ok := req.UserID.(CustomIdentifier)
	if !ok {
		return nil, errors.New("invalid user id")
	}
	s := &Session{
		id:       uuid.New(),
		userID:   userID,
		idleAt:   req.IdleAt,
		expireAt: req.ExpireAt,
	}
	ms.Sessions[s.ID()] = s
	return s, nil
}

func (ms *MemoryStore) GetSession(ctx context.Context, sessionID gosesh.Identifier) (gosesh.Session, error) {
	s, ok := ms.Sessions[sessionID]
	if !ok {
		return nil, errors.New("session not found")
	}
	return s, nil
}

func (ms *MemoryStore) DeleteSession(ctx context.Context, sessionID gosesh.Identifier) error {
	delete(ms.Sessions, sessionID)
	return nil
}

func (ms *MemoryStore) DeleteUserSessions(ctx context.Context, userID gosesh.Identifier) (int, error) {
	var count int
	for _, s := range ms.Sessions {
		if s.UserID() == userID {
			delete(ms.Sessions, s.ID())
			count++
		}
	}
	return count, nil
}

func (s Session) ID() gosesh.Identifier {
	return s.id
}

func (s Session) UserID() gosesh.Identifier {
	return s.userID
}

func (s Session) IdleAt() time.Time {
	return s.idleAt
}

func (s Session) ExpireAt() time.Time {
	return s.expireAt
}
