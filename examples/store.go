package examples

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/rlebel12/identity"
)

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		Users:    map[uuid.UUID]*identity.User{},
		Sessions: map[uuid.UUID]*identity.Session{},
	}
}

type MemoryStore struct {
	Users    map[uuid.UUID]*identity.User
	Sessions map[uuid.UUID]*identity.Session
}

func (ms *MemoryStore) UpsertUser(ctx context.Context, req identity.UpsertUserRequest) (*identity.User, error) {
	for _, user := range ms.Users {
		if user.Email == req.Email {
			user.UpdatedAt = time.Now().UTC()
			return user, nil
		}
	}

	u := &identity.User{
		ID:        uuid.New(),
		Email:     req.Email,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	ms.Users[u.ID] = u
	return u, nil
}

func (ms *MemoryStore) GetUser(ctx context.Context, userID uuid.UUID) (*identity.User, error) {
	u, ok := ms.Users[userID]
	if !ok {
		return nil, errors.New("user not found")
	}
	return u, nil
}

func (ms *MemoryStore) CreateSession(ctx context.Context, req identity.CreateSessionRequest) (*identity.Session, error) {
	s := &identity.Session{
		ID:        uuid.New(),
		UserID:    req.User.ID,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
		IdleAt:    req.IdleAt,
		ExpireAt:  req.ExpireAt,
	}
	ms.Sessions[s.ID] = s
	return s, nil
}

func (ms *MemoryStore) GetSession(ctx context.Context, sessionID uuid.UUID) (*identity.Session, error) {
	s, ok := ms.Sessions[sessionID]
	if !ok {
		return nil, errors.New("session not found")
	}
	return s, nil
}

func (ms *MemoryStore) UpdateSession(ctx context.Context, sessionID uuid.UUID, req identity.UpdateSessionValues) (*identity.Session, error) {
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
