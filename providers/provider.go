package providers

import (
	"net/http"

	"github.com/rlebel12/gosesh"
	"golang.org/x/oauth2"
)

type gosesher interface {
	OAuth2Begin(cfg *oauth2.Config) http.Handler
	OAuth2Callback(w http.ResponseWriter, r *http.Request, id gosesh.Identifier, cfg *oauth2.Config) error
	Scheme() string
	Host() string
}
