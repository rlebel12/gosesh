package gosesh

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/rlebel12/gosesh/internal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type FakeOAuth2Credentials struct {
	ClientIDValue     string
	ClientSecretValue string
}

func (f *FakeOAuth2Credentials) ClientID() string {
	return f.ClientIDValue
}

func (f *FakeOAuth2Credentials) ClientSecret() string {
	return f.ClientSecretValue
}

func NewFakeOAuth2Credentials(clientID, clientSecret string) *FakeOAuth2Credentials {
	return &FakeOAuth2Credentials{
		ClientIDValue:     clientID,
		ClientSecretValue: clientSecret,
	}
}

type FakeSession struct {
	IDValue       Identifier
	UserIDValue   Identifier
	IdleAtValue   time.Time
	ExpireAtValue time.Time
}

func (f *FakeSession) ID() Identifier {
	return f.IDValue
}

func (f *FakeSession) UserID() Identifier {
	return f.UserIDValue
}

func (f *FakeSession) IdleAt() time.Time {
	return f.IdleAtValue
}

func (f *FakeSession) ExpireAt() time.Time {
	return f.ExpireAtValue
}

func NewFakeSession(id, userID Identifier, idleAt, expireAt time.Time) *FakeSession {
	return &FakeSession{
		IDValue:       id,
		UserIDValue:   userID,
		IdleAtValue:   idleAt,
		ExpireAtValue: expireAt,
	}
}

func TestFakeIdentifierContract(t *testing.T) {
	IdentifierContract{
		NewIdentifier: func(id string) Identifier {
			return internal.NewFakeIdentifier(id)
		},
	}.Test(t)
}

func TestFakeOAuth2UserContract(t *testing.T) {
	OAuth2UserContract{
		NewOAuth2User: func(id string) OAuth2User {
			return internal.NewFakeOAuth2User(id)
		},
	}.Test(t)
}

func TestFakeOAuth2CredentialsContract(t *testing.T) {
	OAuth2CredentialsContract{
		NewOAuth2Credentials: func(clientID, clientSecret string) OAuth2Credentials {
			return NewFakeOAuth2Credentials(clientID, clientSecret)
		},
	}.Test(t)
}

func TestFakeSessionContract(t *testing.T) {
	SessionContract{
		NewSession: func(id, userID Identifier, idleAt, expireAt time.Time) Session {
			return NewFakeSession(id, userID, idleAt, expireAt)
		},
		NewIdentifier: func(id string) Identifier {
			return internal.NewFakeIdentifier(id)
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

func (s *erroringStore) CreateSession(ctx context.Context, req CreateSessionRequest) (Session, error) {
	if s.createSessionError {
		return nil, errors.New("mock failure")
	}
	return s.Storer.CreateSession(ctx, req)
}

func (s *erroringStore) DeleteSession(ctx context.Context, sessionID Identifier) error {
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

func (s *erroringStore) UpsertUser(ctx context.Context, user OAuth2User) (Identifier, error) {
	if s.upsertUserError {
		return nil, errors.New("mock failure")
	}
	return s.Storer.UpsertUser(ctx, user)
}

func (s *erroringStore) GetSession(ctx context.Context, sessionID Identifier) (Session, error) {
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
