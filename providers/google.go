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

func NewGoogleProvider[ID gosesh.Identifier](gs *gosesh.Gosesh[ID]) GoogleProvider[ID] {
	return GoogleProvider[ID]{
		gs:  gs,
		cfg: GoogleOauth2Config(*gs.Config),
	}
}

type GoogleProvider[ID gosesh.Identifier] struct {
	gs  *gosesh.Gosesh[ID]
	cfg *oauth2.Config
}

func (p *GoogleProvider[ID]) OAuth2Begin(w http.ResponseWriter, r *http.Request) {
	p.gs.OAuth2Begin(p.cfg)(w, r)
}

func (p *GoogleProvider[ID]) Callback(w http.ResponseWriter, r *http.Request) error {
	return p.gs.OAuth2Callback(gosesh.OAuth2CallbackParams{
		W:            w,
		R:            r,
		User:         new(GoogleUser),
		OAuth2Config: p.cfg,
	})
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
	return user.ID
}

const GoogleProviderKey = "google"

func GoogleOauth2Config(config gosesh.Config) *oauth2.Config {
	providerConf := config.Providers[GoogleProviderKey]
	return &oauth2.Config{
		ClientID:     providerConf.ClientID,
		ClientSecret: providerConf.ClientSecret,
		RedirectURL: fmt.Sprintf(
			"%s://%s/auth/google/callback", config.Origin.Scheme, config.Origin.Host),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}
}
