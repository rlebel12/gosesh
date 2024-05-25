package providers

import (
	"net/http"
	"testing"

	"github.com/rlebel12/gosesh"
	mock_providers "github.com/rlebel12/gosesh/mocks/providers"
	"golang.org/x/oauth2"
)

type gosesher interface {
	OAuth2Begin(cfg *oauth2.Config) http.HandlerFunc
	OAuth2Callback(w http.ResponseWriter, r *http.Request, user gosesh.OAuth2User, cfg *oauth2.Config) error
	Scheme() string
	Host() string
}

func newGosesher(t *testing.T) *mock_providers.Gosesher {
	sesh := mock_providers.NewGosesher(t)
	sesh.EXPECT().Scheme().Return("http")
	sesh.EXPECT().Host().Return("localhost")
	return sesh
}
