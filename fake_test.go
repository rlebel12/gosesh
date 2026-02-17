package gosesh

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type FakeSession struct {
	IDValue               HashedSessionID
	UserIDValue           UserID
	IdleDeadlineValue     time.Time
	AbsoluteDeadlineValue time.Time
	LastActivityAtValue   time.Time
}

func (f *FakeSession) ID() HashedSessionID {
	return f.IDValue
}

func (f *FakeSession) UserID() UserID {
	return f.UserIDValue
}

func (f *FakeSession) IdleDeadline() time.Time {
	return f.IdleDeadlineValue
}

func (f *FakeSession) AbsoluteDeadline() time.Time {
	return f.AbsoluteDeadlineValue
}

func (f *FakeSession) LastActivityAt() time.Time {
	return f.LastActivityAtValue
}

func NewFakeSession(id HashedSessionID, userID UserID, idleDeadline, absoluteDeadline, lastActivityAt time.Time) *FakeSession {
	return &FakeSession{
		IDValue:               id,
		UserIDValue:           userID,
		IdleDeadlineValue:     idleDeadline,
		AbsoluteDeadlineValue: absoluteDeadline,
		LastActivityAtValue:   lastActivityAt,
	}
}

func TestFakeSessionContract(t *testing.T) {
	SessionContract{
		NewSession: func(id HashedSessionID, userID UserID, idleDeadline, absoluteDeadline, lastActivityAt time.Time) Session {
			return NewFakeSession(id, userID, idleDeadline, absoluteDeadline, lastActivityAt)
		},
	}.Test(t)
}

type erroringStore struct {
	Storer
	createSessionError       bool
	deleteSessionError       bool
	deleteUserSessionsError  bool
	upsertUserError          bool
	getSessionError          bool
	extendSessionError       bool
	BatchRecordActivityErr   error
}

func (s *erroringStore) CreateSession(ctx context.Context, hashedID HashedSessionID, userID UserID, idleDeadline, absoluteDeadline time.Time) (Session, error) {
	if s.createSessionError {
		return nil, errors.New("mock failure")
	}
	return s.Storer.CreateSession(ctx, hashedID, userID, idleDeadline, absoluteDeadline)
}

func (s *erroringStore) DeleteSession(ctx context.Context, hashedID HashedSessionID) error {
	if s.deleteSessionError {
		return errors.New("mock failure")
	}
	return s.Storer.DeleteSession(ctx, hashedID)
}

func (s *erroringStore) DeleteUserSessions(ctx context.Context, userID UserID) (int, error) {
	if s.deleteUserSessionsError {
		return 0, errors.New("mock failure")
	}
	return s.Storer.DeleteUserSessions(ctx, userID)
}

func (s *erroringStore) UpsertUser(ctx context.Context, authProviderID AuthProviderID) (UserID, error) {
	if s.upsertUserError {
		return nil, errors.New("mock failure")
	}
	return s.Storer.UpsertUser(ctx, authProviderID)
}

func (s *erroringStore) GetSession(ctx context.Context, hashedID HashedSessionID) (Session, error) {
	if s.getSessionError {
		return nil, errors.New("mock failure")
	}
	return s.Storer.GetSession(ctx, hashedID)
}

func (s *erroringStore) ExtendSession(ctx context.Context, hashedID HashedSessionID, newIdleDeadline time.Time) error {
	if s.extendSessionError {
		return errors.New("mock failure")
	}
	return s.Storer.ExtendSession(ctx, hashedID, newIdleDeadline)
}

func (s *erroringStore) BatchRecordActivity(ctx context.Context, updates map[HashedSessionID]time.Time) (int, error) {
	if s.BatchRecordActivityErr != nil {
		return 0, s.BatchRecordActivityErr
	}
	// If the underlying Storer implements ActivityRecorder, use it
	if recorder, ok := s.Storer.(ActivityRecorder); ok {
		return recorder.BatchRecordActivity(ctx, updates)
	}
	return 0, errors.New("BatchRecordActivity not implemented")
}

// erroringDeviceCodeStore wraps a DeviceCodeStore and injects errors for testing.
type erroringDeviceCodeStore struct {
	DeviceCodeStore
	completeDeviceCodeError bool
}

func (s *erroringDeviceCodeStore) CompleteDeviceCode(ctx context.Context, deviceCode string, rawSessionID RawSessionID) error {
	if s.completeDeviceCodeError {
		return errors.New("mock failure")
	}
	return s.DeviceCodeStore.CompleteDeviceCode(ctx, deviceCode, rawSessionID)
}

// contextAwareStore wraps a MemoryStore and adds context cancellation checking
// to BatchRecordActivity, simulating a real database that respects context.
type contextAwareStore struct {
	*MemoryStore
}

func newContextAwareStore() *contextAwareStore {
	return &contextAwareStore{MemoryStore: NewMemoryStore()}
}

func (s *contextAwareStore) BatchRecordActivity(ctx context.Context, updates map[HashedSessionID]time.Time) (int, error) {
	// Check context before processing - this is what real database drivers do
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return s.MemoryStore.BatchRecordActivity(ctx, updates)
}

type testLogger struct {
	logs []string
	mu   sync.Mutex
}

func (l *testLogger) Error(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logs = append(l.logs, msg)
}

func (l *testLogger) Info(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logs = append(l.logs, msg)
}

func (l *testLogger) Debug(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logs = append(l.logs, msg)
}

func (l *testLogger) Write(p []byte) (n int, err error) {
	l.logs = append(l.logs, string(p))
	return len(p), nil
}

func (l *testLogger) assertExpectedLogs(t *testing.T, expectedLogs []string) {
	require.Equal(t, len(expectedLogs), len(l.logs), "Expected %d logs but got %d", len(expectedLogs), len(l.logs))
	for i, actualLog := range l.logs {
		assert.Contains(t, actualLog, expectedLogs[i], "Log message %d does not contain expected content", i)
	}
}

func withTestLogger() (func(*Gosesh), *testLogger) {
	logger := &testLogger{}
	handler := slog.NewTextHandler(logger, &slog.HandlerOptions{Level: slog.LevelDebug})
	return func(g *Gosesh) {
		g.logger = slog.New(handler)
	}, logger
}
