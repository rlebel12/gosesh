package providers

import (
	"context"
	"fmt"
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

func NewGoogle(sesh Gosesher, clientID, clientSecret, redirectPath string, opts ...Opt[Google]) *Google {
	google := &Google{
		Provider: newProvider(sesh, []string{
			"https://www.googleapis.com/auth/userinfo.email",
		}, google.Endpoint, clientID, clientSecret, redirectPath),
	}
	for _, opt := range opts {
		opt(google)
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
	const baseURL = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="
	url := fmt.Sprintf("%s%s", baseURL, accessToken)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating request: %s", err.Error())
	}
	return p.doRequest(req)
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
