// An in-memory store that can be provided to Gosesh for testing purposes.

package gosesh

import (
	"context"
	"errors"
	"sync"
	"time"
)

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sessions: map[HashedSessionID]*MemoryStoreSession{},
	}
}

type (
	MemoryStore struct {
		mu       sync.RWMutex
		sessions map[HashedSessionID]*MemoryStoreSession
	}

	MemoryStoreSession struct {
		id               HashedSessionID
		userID           UserID
		idleDeadline     time.Time
		absoluteDeadline time.Time
		lastActivityAt   time.Time
	}
)

func (ms *MemoryStore) UpsertUser(ctx context.Context, authProviderID AuthProviderID) (UserID, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	return authProviderID, nil
}

func (ms *MemoryStore) CreateSession(ctx context.Context, hashedID HashedSessionID, userID UserID, idleDeadline, absoluteDeadline time.Time) (Session, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	now := time.Now().UTC()
	s := &MemoryStoreSession{
		id:               hashedID,
		userID:           userID,
		idleDeadline:     idleDeadline,
		absoluteDeadline: absoluteDeadline,
		lastActivityAt:   now,
	}
	ms.sessions[hashedID] = s
	return s, nil
}

func (ms *MemoryStore) GetSession(ctx context.Context, hashedID HashedSessionID) (Session, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	s, ok := ms.sessions[hashedID]
	if !ok {
		return nil, errors.New("session not found")
	}
	return s, nil
}

func (ms *MemoryStore) DeleteSession(ctx context.Context, hashedID HashedSessionID) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	_, ok := ms.sessions[hashedID]
	if !ok {
		return errors.New("session not found")
	}
	delete(ms.sessions, hashedID)
	return nil
}

func (ms *MemoryStore) DeleteUserSessions(ctx context.Context, userID UserID) (int, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	var count int
	for hashedID, s := range ms.sessions {
		if s.UserID() == userID {
			delete(ms.sessions, hashedID)
			count++
		}
	}
	return count, nil
}

func (ms *MemoryStore) ExtendSession(ctx context.Context, hashedID HashedSessionID, newIdleDeadline time.Time) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	s, ok := ms.sessions[hashedID]
	if !ok {
		return errors.New("session not found")
	}
	s.idleDeadline = newIdleDeadline
	s.lastActivityAt = time.Now().UTC() // Update activity timestamp
	return nil
}

func (ms *MemoryStore) BatchRecordActivity(ctx context.Context, updates map[HashedSessionID]time.Time) (int, error) {
	if len(updates) == 0 {
		return 0, nil
	}

	ms.mu.Lock()
	defer ms.mu.Unlock()

	count := 0
	for hashedID, timestamp := range updates {
		s, ok := ms.sessions[hashedID]
		if ok {
			s.lastActivityAt = timestamp
			count++
		}
	}
	return count, nil
}

// Reset clears all sessions.
// This is useful for testing to isolate state between test cases.
func (ms *MemoryStore) Reset() {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	ms.sessions = make(map[HashedSessionID]*MemoryStoreSession)
}

func (s MemoryStoreSession) ID() HashedSessionID {
	return s.id
}

func (s MemoryStoreSession) UserID() UserID {
	return s.userID
}

func (s MemoryStoreSession) IdleDeadline() time.Time {
	return s.idleDeadline
}

func (s MemoryStoreSession) AbsoluteDeadline() time.Time {
	return s.absoluteDeadline
}

func (s MemoryStoreSession) LastActivityAt() time.Time {
	return s.lastActivityAt
}

// SetIdleDeadline updates the idle deadline for testing purposes.
// This should only be used in tests to simulate expired sessions.
func (s *MemoryStoreSession) SetIdleDeadline(deadline time.Time) {
	s.idleDeadline = deadline
}

// SetLastActivityAt updates the last activity timestamp for testing purposes.
// This should only be used in tests to simulate session activity.
func (s *MemoryStoreSession) SetLastActivityAt(timestamp time.Time) {
	s.lastActivityAt = timestamp
}

// SetAbsoluteDeadline updates the absolute deadline for testing purposes.
// This should only be used in tests to simulate expired sessions.
func (s *MemoryStoreSession) SetAbsoluteDeadline(deadline time.Time) {
	s.absoluteDeadline = deadline
}

// Ensure interfaces are implemented
var _ Storer = (*MemoryStore)(nil)
var _ ActivityRecorder = (*MemoryStore)(nil)
var _ Session = (*MemoryStoreSession)(nil)
