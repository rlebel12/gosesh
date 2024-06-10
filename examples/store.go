package examples

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/rlebel12/gosesh"
	"github.com/rlebel12/gosesh/providers"
)

var sequenceID int

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		Users:    map[gosesh.Identifier]*CustomIdentifier{},
		Sessions: map[gosesh.Identifier]*gosesh.Session{},
	}
}

type (
	CustomIdentifier struct {
		id    int
		email string
	}
)

func (ci *CustomIdentifier) ID() string {
	return fmt.Sprintf("%d (%s)", ci.id, ci.email)
}

type MemoryStore struct {
	Users    map[gosesh.Identifier]*CustomIdentifier
	Sessions map[gosesh.Identifier]*gosesh.Session
}

func (ms *MemoryStore) UpsertUser(ctx context.Context, user gosesh.OAuth2User) (gosesh.Identifier, error) {
	switch d := user.(type) {
	case *providers.DiscordUser:
		slog.Info("Discord user", "id", d.Id, "username", d.Username, "email", d.Email, "verified", d.Verified)
	// case providers.GoogleUser:
	// 	slog.Info("Google user", "id", d.ID, "email", d.Email)
	default:
		slog.Info("Unknown user", "id", user.ID())
	}
	for _, user := range ms.Users {
		if user.email == user.ID() {
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

func (ms *MemoryStore) CreateSession(ctx context.Context, req gosesh.CreateSessionRequest) (*gosesh.Session, error) {
	s := &gosesh.Session{
		Identifier: &CustomIdentifier{
			id:    sequenceID,
			email: "foo",
		},
		User:     req.User,
		IdleAt:   req.IdleAt,
		ExpireAt: req.ExpireAt,
	}
	ms.Sessions[s.Identifier] = s
	return s, nil
}

func (ms *MemoryStore) GetSession(ctx context.Context, sessionID gosesh.Identifier) (*gosesh.Session, error) {
	s, ok := ms.Sessions[sessionID]
	if !ok {
		return nil, errors.New("session not found")
	}
	return s, nil
}

func (ms *MemoryStore) UpdateSession(ctx context.Context, sessionID gosesh.Identifier, req gosesh.UpdateSessionValues) (*gosesh.Session, error) {
	s, ok := ms.Sessions[sessionID]
	if !ok {
		return nil, errors.New("session not found")
	}
	s.IdleAt = req.IdleAt
	s.ExpireAt = req.ExpireAt
	ms.Sessions[s.Identifier] = s
	return s, nil
}

func (ms *MemoryStore) DeleteSession(ctx context.Context, sessionID gosesh.Identifier) error {
	delete(ms.Sessions, sessionID)
	return nil
}

func (ms *MemoryStore) DeleteUserSessions(ctx context.Context, userID gosesh.Identifier) (int, error) {
	var count int
	for _, s := range ms.Sessions {
		if s.User == userID {
			delete(ms.Sessions, s.Identifier)
			count++
		}
	}
	return count, nil
}
