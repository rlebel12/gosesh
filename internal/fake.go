package internal

import (
	"context"
	"net/http"
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
