package gosesh

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type FakeSession struct {
	IDValue               Identifier
	UserIDValue           Identifier
	IdleDeadlineValue     time.Time
	AbsoluteDeadlineValue time.Time
}

func (f *FakeSession) ID() Identifier {
	return f.IDValue
}

func (f *FakeSession) UserID() Identifier {
	return f.UserIDValue
}

func (f *FakeSession) IdleDeadline() time.Time {
	return f.IdleDeadlineValue
}

func (f *FakeSession) AbsoluteDeadline() time.Time {
	return f.AbsoluteDeadlineValue
}

func NewFakeSession(id, userID Identifier, idleDeadline, absoluteDeadline time.Time) *FakeSession {
	return &FakeSession{
		IDValue:               id,
		UserIDValue:           userID,
		IdleDeadlineValue:     idleDeadline,
		AbsoluteDeadlineValue: absoluteDeadline,
	}
}

func TestStringIdentifierContract(t *testing.T) {
	IdentifierContract{
		NewIdentifier: func(id string) Identifier {
			return StringIdentifier(id)
		},
	}.Test(t)
}

func TestFakeSessionContract(t *testing.T) {
	SessionContract{
		NewSession: func(id, userID Identifier, idleDeadline, absoluteDeadline time.Time) Session {
			return NewFakeSession(id, userID, idleDeadline, absoluteDeadline)
		},
		NewIdentifier: func(id string) Identifier {
			return StringIdentifier(id)
		},
	}.Test(t)
}

type erroringStore struct {
	Storer
	createSessionError      bool
	deleteSessionError      bool
	deleteUserSessionsError bool
	upsertUserError         bool
	getSessionError         bool
}

func (s *erroringStore) CreateSession(ctx context.Context, userID Identifier, idleDeadline, absoluteDeadline time.Time) (Session, error) {
	if s.createSessionError {
		return nil, errors.New("mock failure")
	}
	return s.Storer.CreateSession(ctx, userID, idleDeadline, absoluteDeadline)
}

func (s *erroringStore) DeleteSession(ctx context.Context, sessionID string) error {
	if s.deleteSessionError {
		return errors.New("mock failure")
	}
	return s.Storer.DeleteSession(ctx, sessionID)
}

func (s *erroringStore) DeleteUserSessions(ctx context.Context, userID Identifier) (int, error) {
	if s.deleteUserSessionsError {
		return 0, errors.New("mock failure")
	}
	return s.Storer.DeleteUserSessions(ctx, userID)
}

func (s *erroringStore) UpsertUser(ctx context.Context, authProviderID Identifier) (Identifier, error) {
	if s.upsertUserError {
		return nil, errors.New("mock failure")
	}
	return s.Storer.UpsertUser(ctx, authProviderID)
}

func (s *erroringStore) GetSession(ctx context.Context, sessionID string) (Session, error) {
	if s.getSessionError {
		return nil, errors.New("mock failure")
	}
	return s.Storer.GetSession(ctx, sessionID)
}

type testLogger struct {
	logs []string
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
	handler := slog.NewTextHandler(logger, nil)
	return func(g *Gosesh) {
		g.logger = slog.New(handler)
	}, logger
}
