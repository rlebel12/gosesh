package providers

import (
	"net/http"

	"github.com/rlebel12/gosesh"
	"golang.org/x/oauth2"
)

type Gosesher interface {
	OAuth2Begin(cfg *oauth2.Config) http.HandlerFunc
	OAuth2Callback(user gosesh.OAuth2User, cfg *oauth2.Config, handler gosesh.HandlerDone) http.HandlerFunc
	Scheme() string
	Host() string
}

type Provider interface {
	OAuth2Begin() http.HandlerFunc
	OAuth2Callback(handler gosesh.HandlerDone) http.HandlerFunc
}
