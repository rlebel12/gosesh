package providers

import (
	"errors"
	"net/http"
	"testing"

	"github.com/rlebel12/gosesh"
	"github.com/rlebel12/gosesh/internal"
	"golang.org/x/oauth2"
)

type FakeGosesher struct {
	OAuth2BeginFunc func(cfg *oauth2.Config) http.HandlerFunc
	SchemeValue     string
	HostValue       string
}

func NewFakeGosesher(
	giveScheme,
	giveHost string,
	giveOAuth2BeginFunc func(cfg *oauth2.Config) http.HandlerFunc,
) *FakeGosesher {
	return &FakeGosesher{
		SchemeValue:     giveScheme,
		HostValue:       giveHost,
		OAuth2BeginFunc: giveOAuth2BeginFunc,
	}
}

func (f *FakeGosesher) OAuth2Begin(cfg *oauth2.Config) http.HandlerFunc {
	if f.OAuth2BeginFunc != nil {
		return f.OAuth2BeginFunc(cfg)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}

func (f *FakeGosesher) OAuth2Callback(user gosesh.OAuth2User, cfg *oauth2.Config, handler gosesh.HandlerDone) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		handler(w, r, nil)
	}
}

func (f *FakeGosesher) Scheme() string {
	return f.SchemeValue
}

func (f *FakeGosesher) Host() string {
	return f.HostValue
}

// ErroringGosesher is a Gosesher that returns errors for testing
type ErroringGosesher struct {
	*FakeGosesher
	oauth2BeginError    bool
	oauth2CallbackError bool
}

// NewErroringGosesher creates a new erroring Gosesher instance
func NewErroringGosesher(scheme, host string) *ErroringGosesher {
	return &ErroringGosesher{
		FakeGosesher: NewFakeGosesher(scheme, host, nil),
	}
}

func (e *ErroringGosesher) OAuth2Begin(cfg *oauth2.Config) http.HandlerFunc {
	if e.oauth2BeginError {
		return func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
	return e.FakeGosesher.OAuth2Begin(cfg)
}

func (e *ErroringGosesher) OAuth2Callback(user gosesh.OAuth2User, cfg *oauth2.Config, handler gosesh.HandlerDone) http.HandlerFunc {
	if e.oauth2CallbackError {
		return func(w http.ResponseWriter, r *http.Request) {
			handler(w, r, errors.New("mock failure"))
		}
	}
	return e.FakeGosesher.OAuth2Callback(user, cfg, handler)
}

func TestGosesherContract(t *testing.T) {
	GosesherContract{
		NewGosesher: func(
			giveScheme,
			giveHost string,
			giveOAuth2BeginFunc func(cfg *oauth2.Config) http.HandlerFunc,
		) Gosesher {
			return NewFakeGosesher(giveScheme, giveHost, giveOAuth2BeginFunc)
		},
		NewOAuth2User: func(giveID string) gosesh.OAuth2User {
			return internal.NewFakeOAuth2User(giveID)
		},
	}.Test(t)
}
