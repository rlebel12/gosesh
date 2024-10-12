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

type (
	Google struct {
		sesh       Gosesher
		cfg        *oauth2.Config
		googleHost string
	}

	GoogleOpt func(*Google)
)

func NewGoogle(sesh Gosesher, credentials gosesh.OAuth2Credentials, redirectPath string, opts ...GoogleOpt) *Google {
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
	google := &Google{
		sesh:       sesh,
		cfg:        oauth2Config,
		googleHost: "https://www.googleapis.com",
	}
	for _, opt := range opts {
		opt(google)
	}
	return google
}

// To help with testing, this function allows you to set the Discord host to a different value (i.e. httptest.Server.URL).
func WithGoogleHost(host string) GoogleOpt {
	return func(d *Google) {
		d.googleHost = host
	}
}

func (p *Google) OAuth2Begin() http.HandlerFunc {
	return p.sesh.OAuth2Begin(p.cfg)
}

func (p *Google) OAuth2Callback(handler gosesh.HandlerDone) http.HandlerFunc {
	return p.sesh.OAuth2Callback(p.NewUser(), p.cfg, handler)
}

func (p *Google) NewUser() gosesh.OAuth2User {
	return &GoogleUser{
		googleHost: p.googleHost,
	}
}

type GoogleUser struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Picture       string `json:"picture"`

	googleHost string `json:"-"`
}

func (user *GoogleUser) Request(ctx context.Context, accessToken string) (*http.Response, error) {
	url := fmt.Sprintf("%s/oauth2/v2/userinfo?access_token=%s", user.googleHost, accessToken)
	return http.Get(url)
}

func (user *GoogleUser) Unmarshal(b []byte) error {
	return json.Unmarshal(b, user)
}

func (user *GoogleUser) String() string {
	return user.Email
}
