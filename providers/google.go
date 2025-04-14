package providers

import (
	"context"
	"io"
	"net/http"

	"github.com/rlebel12/gosesh"
	"golang.org/x/oauth2/google"
)

type (
	Google struct {
		Provider
	}
)

func NewGoogle(sesh Gosesher, clientID, clientSecret, redirectPath string) *Google {
	google := &Google{
		Provider: newProvider(sesh, []string{
			"https://www.googleapis.com/auth/userinfo.email",
		}, google.Endpoint, clientID, clientSecret, redirectPath),
	}
	return google
}

func (p *Google) OAuth2Begin() http.HandlerFunc {
	return p.Gosesh.OAuth2Begin(p.Config)
}

func (p *Google) OAuth2Callback(handler gosesh.HandlerDoneFunc) http.HandlerFunc {
	return p.Gosesh.OAuth2Callback(p.Config, p.requestUser, unmarshalUser(p.NewUser), handler)
}

func (p *Google) requestUser(ctx context.Context, accessToken string) (io.ReadCloser, error) {
	const url = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="
	return p.doRequest("GET", url+accessToken, nil)
}

func (p *Google) NewUser() *GoogleUser {
	return &GoogleUser{}
}

type GoogleUser struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Picture       string `json:"picture"`
}

func (user *GoogleUser) String() string {
	return user.Email
}
