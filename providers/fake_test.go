package providers

import (
	"io"
	"net/http"
	"testing"

	"github.com/rlebel12/gosesh"
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

func (f *FakeGosesher) OAuth2Callback(
	config *oauth2.Config, request gosesh.RequestFunc, unmarshal gosesh.UnmarshalFunc, done gosesh.HandlerDoneFunc,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		content, err := request(r.Context(), "accessToken")
		if err != nil {
			done(w, r, err)
			return
		} else if content == nil {
			done(w, r, nil)
			return
		}
		defer content.Close()
		b, err := io.ReadAll(content)
		if err != nil {
			done(w, r, err)
			return
		}
		_, err = unmarshal(b)
		if err != nil {
			done(w, r, err)
			return
		}
		done(w, r, nil)
	}
}

func (f *FakeGosesher) Scheme() string {
	return f.SchemeValue
}

func (f *FakeGosesher) Host() string {
	return f.HostValue
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
	}.Test(t)
}
