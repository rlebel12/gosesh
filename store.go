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
		sessions: map[string]*MemoryStoreSession{},
	}
}

type (
	MemoryStore struct {
		sessions   map[string]*MemoryStoreSession
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

func (ms *MemoryStore) UpsertUser(ctx context.Context, userID Identifier) (Identifier, error) {
	return userID, nil
}

func (ms *MemoryStore) CreateSession(ctx context.Context, userID Identifier, idleAt, expireAt time.Time) (Session, error) {
	ms.sequenceID++
	s := &MemoryStoreSession{
		id:       ms.sequenceID,
		userID:   userID,
		idleAt:   idleAt,
		expireAt: expireAt,
	}
	ms.sessions[s.ID().String()] = s
	return s, nil
}

func (ms *MemoryStore) GetSession(ctx context.Context, sessionID string) (Session, error) {
	s, ok := ms.sessions[sessionID]
	if !ok {
		return nil, errors.New("session not found")
	}
	return s, nil
}

func (ms *MemoryStore) DeleteSession(ctx context.Context, sessionID string) error {
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
			delete(ms.sessions, s.ID().String())
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
