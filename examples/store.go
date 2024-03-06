package examples

import (
	"context"
	"errors"
	"log/slog"

	"github.com/google/uuid"
	"github.com/rlebel12/gosesh"
	"github.com/rlebel12/gosesh/providers"
)

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		Users:    map[uuid.UUID]gosesh.User{},
		Sessions: map[uuid.UUID]*gosesh.Session{},
	}
}

type (
	User struct {
		id    uuid.UUID
		email string
	}
)

func (u User) GUID() string {
	return u.email
}

func (u User) ID() uuid.UUID {
	return u.id
}

type MemoryStore struct {
	Users    map[uuid.UUID]gosesh.User
	Sessions map[uuid.UUID]*gosesh.Session
}

func (ms *MemoryStore) UpsertUser(ctx context.Context, e gosesh.Emailer) (uuid.UUID, error) {
	switch d := e.(type) {
	case providers.DiscordUser:
		slog.Info("Discord user", "id", d.ID, "username", d.Username, "email", d.Email, "verified", d.Verified)
	case providers.GoogleUser:
		slog.Info("Google user", "id", d.ID, "email", d.Email)
	default:
		slog.Info("Unknown user", "email", e.GetEmail())
	}
	for _, user := range ms.Users {
		if user.GUID() == e.GetEmail() {
			return user.ID(), nil
		}
	}
	u := User{
		id:    uuid.New(),
		email: e.GetEmail(),
	}
	ms.Users[u.ID()] = u
	return u.ID(), nil
}

func (ms *MemoryStore) CreateSession(ctx context.Context, req gosesh.CreateSessionRequest) (*gosesh.Session, error) {
	s := &gosesh.Session{
		ID:       uuid.New(),
		UserID:   req.UserID,
		IdleAt:   req.IdleAt,
		ExpireAt: req.ExpireAt,
	}
	ms.Sessions[s.ID] = s
	return s, nil
}

func (ms *MemoryStore) GetSession(ctx context.Context, sessionID uuid.UUID) (*gosesh.Session, error) {
	s, ok := ms.Sessions[sessionID]
	if !ok {
		return nil, errors.New("session not found")
	}
	return s, nil
}

func (ms *MemoryStore) UpdateSession(ctx context.Context, sessionID uuid.UUID, req gosesh.UpdateSessionValues) (*gosesh.Session, error) {
	s, ok := ms.Sessions[sessionID]
	if !ok {
		return nil, errors.New("session not found")
	}
	s.IdleAt = req.IdleAt
	s.ExpireAt = req.ExpireAt
	ms.Sessions[s.ID] = s
	return s, nil
}

func (ms *MemoryStore) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	delete(ms.Sessions, sessionID)
	return nil
}

func (ms *MemoryStore) DeleteUserSessions(ctx context.Context, userID uuid.UUID) (int, error) {
	var count int
	for _, s := range ms.Sessions {
		if s.UserID == userID {
			delete(ms.Sessions, s.ID)
			count++
		}
	}
	return count, nil
}
