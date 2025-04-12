// An in-memory store that can be provided to Gosesh for testing purposes.

package gosesh

import (
	"context"
	"errors"
	"strconv"
	"time"
)

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sessions: map[Identifier]*MemoryStoreSession{},
	}
}

type (
	MemoryStore struct {
		sessions   map[Identifier]*MemoryStoreSession
		sequenceID MemoryStoreIdentifier
	}

	MemoryStoreIdentifier int

	MemoryStoreSession struct {
		id       MemoryStoreIdentifier
		userID   Identifier
		idleAt   time.Time
		expireAt time.Time
	}
)

func (id MemoryStoreIdentifier) String() string {
	return strconv.Itoa(int(id))
}

func (ms *MemoryStore) UpsertUser(ctx context.Context, user OAuth2User) (Identifier, error) {
	return user, nil
}

func (ms *MemoryStore) CreateSession(ctx context.Context, req CreateSessionRequest) (Session, error) {
	ms.sequenceID++
	s := &MemoryStoreSession{
		id:       ms.sequenceID,
		userID:   req.UserID,
		idleAt:   req.IdleAt,
		expireAt: req.ExpireAt,
	}
	ms.sessions[s.ID()] = s
	return s, nil
}

func (ms *MemoryStore) GetSession(ctx context.Context, sessionID Identifier) (Session, error) {
	s, ok := ms.sessions[sessionID]
	if !ok {
		return nil, errors.New("session not found")
	}
	return s, nil
}

func (ms *MemoryStore) DeleteSession(ctx context.Context, sessionID Identifier) error {
	_, ok := ms.sessions[sessionID]
	if !ok {
		return errors.New("session not found")
	}
	delete(ms.sessions, sessionID)
	return nil
}

func (ms *MemoryStore) DeleteUserSessions(ctx context.Context, userID Identifier) (int, error) {
	var count int
	for _, s := range ms.sessions {
		if s.UserID() == userID {
			delete(ms.sessions, s.ID())
			count++
		}
	}
	return count, nil
}

func (s MemoryStoreSession) ID() Identifier {
	return s.id
}

func (s MemoryStoreSession) UserID() Identifier {
	return s.userID
}

func (s MemoryStoreSession) IdleAt() time.Time {
	return s.idleAt
}

func (s MemoryStoreSession) ExpireAt() time.Time {
	return s.expireAt
}

// Ensure interfaces are implemented
var _ Storer = (*MemoryStore)(nil)
var _ Identifier = (*MemoryStoreIdentifier)(nil)
var _ Session = (*MemoryStoreSession)(nil)
