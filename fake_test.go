package gosesh

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rlebel12/gosesh/internal"
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
	*MemoryStore
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
	return s.MemoryStore.CreateSession(ctx, req)
}

func (s *erroringStore) DeleteSession(ctx context.Context, sessionID Identifier) error {
	if s.deleteSessionError {
		return errors.New("mock failure")
	}
	return s.MemoryStore.DeleteSession(ctx, sessionID)
}

func (s *erroringStore) DeleteUserSessions(ctx context.Context, userID Identifier) (int, error) {
	if s.deleteUserSessionsError {
		return 0, errors.New("mock failure")
	}
	return s.MemoryStore.DeleteUserSessions(ctx, userID)
}

func (s *erroringStore) UpsertUser(ctx context.Context, user OAuth2User) (Identifier, error) {
	if s.upsertUserError {
		return nil, errors.New("mock failure")
	}
	return s.MemoryStore.UpsertUser(ctx, user)
}

func (s *erroringStore) GetSession(ctx context.Context, sessionID Identifier) (Session, error) {
	if s.getSessionError {
		return nil, errors.New("mock failure")
	}
	return s.MemoryStore.GetSession(ctx, sessionID)
}
