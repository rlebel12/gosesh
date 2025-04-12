package gosesh

import (
	"context"
	"net/http"
	"testing"
	"time"
)

type FakeIdentifier struct {
	ID string
}

func (f *FakeIdentifier) String() string {
	return f.ID
}

func NewFakeIdentifier(id string) *FakeIdentifier {
	return &FakeIdentifier{ID: id}
}

type FakeOAuth2User struct {
	*FakeIdentifier
	RequestFunc   func(ctx context.Context, accessToken string) (*http.Response, error)
	UnmarshalFunc func(b []byte) error
}

func (f *FakeOAuth2User) Request(ctx context.Context, accessToken string) (*http.Response, error) {
	if f.RequestFunc != nil {
		return f.RequestFunc(ctx, accessToken)
	}
	return &http.Response{}, nil
}

func (f *FakeOAuth2User) Unmarshal(b []byte) error {
	if f.UnmarshalFunc != nil {
		return f.UnmarshalFunc(b)
	}
	return nil
}

func NewFakeOAuth2User(id string) *FakeOAuth2User {
	return &FakeOAuth2User{
		FakeIdentifier: NewFakeIdentifier(id),
	}
}

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
			return NewFakeIdentifier(id)
		},
	}.Test(t)
}

func TestFakeOAuth2UserContract(t *testing.T) {
	OAuth2UserContract{
		NewOAuth2User: func(id string) OAuth2User {
			return NewFakeOAuth2User(id)
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
	}.Test(t)
}
