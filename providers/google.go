package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/rlebel12/gosesh"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func NewGoogle(sesh Gosesher, credentials gosesh.OAuth2Credentials, redirectPath string) *Google {
	oauth2Config := &oauth2.Config{
		ClientID:     credentials.ClientID(),
		ClientSecret: credentials.ClientSecret(),
		RedirectURL: fmt.Sprintf(
			"%s://%s%s", sesh.Scheme(), sesh.Host(), redirectPath),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}
	return &Google{
		sesh: sesh,
		cfg:  oauth2Config,
	}
}

type Google struct {
	sesh Gosesher
	cfg  *oauth2.Config
}

func (p *Google) OAuth2Begin() http.HandlerFunc {
	return p.sesh.OAuth2Begin(p.cfg)
}

func (p *Google) OAuth2Callback(handler gosesh.HandlerDone) http.HandlerFunc {
	return p.sesh.OAuth2Callback(new(GoogleUser), p.cfg, handler)
}

type GoogleUser struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Picture       string `json:"picture"`
}

func (*GoogleUser) Request(ctx context.Context, accessToken string) (*http.Response, error) {
	const oauthGoogleUrlAPI = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="
	return http.Get(oauthGoogleUrlAPI + accessToken)
}

func (user *GoogleUser) Unmarshal(b []byte) error {
	return json.Unmarshal(b, user)
}

func (user *GoogleUser) String() string {
	return user.Email
}
