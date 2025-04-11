package providers

import (
	"net/http"

	"github.com/rlebel12/gosesh"
	"golang.org/x/oauth2"
)

//go:generate moq -with-resets -rm -out provider_mock.go . Gosesher

type Gosesher interface {
	OAuth2Begin(cfg *oauth2.Config) http.HandlerFunc
	OAuth2Callback(user gosesh.OAuth2User, cfg *oauth2.Config, handler gosesh.HandlerDone) http.HandlerFunc
	Scheme() string
	Host() string
}
