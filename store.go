// An in-memory store that can be provided to Gosesh for testing purposes.

package gosesh

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"time"
)

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sessions: map[string]*MemoryStoreSession{},
	}
}

type (
	MemoryStore struct {
		mu       sync.RWMutex
		sessions map[string]*MemoryStoreSession
	}

	MemoryStoreIdentifier string

	MemoryStoreSession struct {
		id               MemoryStoreIdentifier
		userID           Identifier
		idleDeadline     time.Time
		absoluteDeadline time.Time
		lastActivityAt   time.Time
	}
)

func (id MemoryStoreIdentifier) String() string {
	return string(id)
}

// generateSessionID creates a random alphanumeric session ID using crypto/rand.
func generateSessionID() (MemoryStoreIdentifier, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const length = 32

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	for i := range bytes {
		bytes[i] = alphabet[int(bytes[i])%len(alphabet)]
	}

	return MemoryStoreIdentifier(bytes), nil
}

func (ms *MemoryStore) UpsertUser(ctx context.Context, userID Identifier) (Identifier, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	return userID, nil
}

func (ms *MemoryStore) CreateSession(ctx context.Context, userID Identifier, idleDeadline, absoluteDeadline time.Time) (Session, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	id, err := generateSessionID()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	s := &MemoryStoreSession{
		id:               id,
		userID:           userID,
		idleDeadline:     idleDeadline,
		absoluteDeadline: absoluteDeadline,
		lastActivityAt:   now, // Set to creation time
	}
	ms.sessions[s.ID().String()] = s
	return s, nil
}

func (ms *MemoryStore) GetSession(ctx context.Context, sessionID string) (Session, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	s, ok := ms.sessions[sessionID]
	if !ok {
		return nil, errors.New("session not found")
	}
	return s, nil
}

func (ms *MemoryStore) DeleteSession(ctx context.Context, sessionID string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	_, ok := ms.sessions[sessionID]
	if !ok {
		return errors.New("session not found")
	}
	delete(ms.sessions, sessionID)
	return nil
}

func (ms *MemoryStore) DeleteUserSessions(ctx context.Context, userID Identifier) (int, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	var count int
	for _, s := range ms.sessions {
		if s.UserID() == userID {
			delete(ms.sessions, s.ID().String())
			count++
		}
	}
	return count, nil
}

func (ms *MemoryStore) ExtendSession(ctx context.Context, sessionID string, newIdleDeadline time.Time) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	s, ok := ms.sessions[sessionID]
	if !ok {
		return errors.New("session not found")
	}
	s.idleDeadline = newIdleDeadline
	s.lastActivityAt = time.Now().UTC() // Update activity timestamp
	return nil
}

func (ms *MemoryStore) BatchRecordActivity(ctx context.Context, updates map[string]time.Time) (int, error) {
	if len(updates) == 0 {
		return 0, nil
	}

	ms.mu.Lock()
	defer ms.mu.Unlock()

	count := 0
	for sessionID, timestamp := range updates {
		s, ok := ms.sessions[sessionID]
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

	ms.sessions = make(map[string]*MemoryStoreSession)
}

func (s MemoryStoreSession) ID() Identifier {
	return s.id
}

func (s MemoryStoreSession) UserID() Identifier {
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
var _ Identifier = (*MemoryStoreIdentifier)(nil)
var _ Session = (*MemoryStoreSession)(nil)
