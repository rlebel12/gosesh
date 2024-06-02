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

func NewGoogle(gs *gosesh.Gosesh, providerConfig gosesh.OAuth2Credentials) GoogleProvider {
	oauth2Config := &oauth2.Config{
		ClientID:     providerConfig.ClientID,
		ClientSecret: providerConfig.ClientSecret,
		RedirectURL: fmt.Sprintf(
			"%s://%s/auth/google/callback", gs.Scheme(), gs.Host()),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}
	return GoogleProvider{
		gs:  gs,
		cfg: oauth2Config,
	}
}

type GoogleProvider struct {
	gs  *gosesh.Gosesh
	cfg *oauth2.Config
}

func (p *GoogleProvider) OAuth2Begin() http.HandlerFunc {
	return p.gs.OAuth2Begin(p.cfg)
}

func (p *GoogleProvider) OAuth2Callback(handler gosesh.CallbackHandler) http.HandlerFunc {
	return p.gs.OAuth2Callback(new(googleUser), p.cfg, handler)
}

type googleUser struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Picture       string `json:"picture"`
}

func (*googleUser) Request(ctx context.Context, accessToken string) (*http.Response, error) {
	const oauthGoogleUrlAPI = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="
	return http.Get(oauthGoogleUrlAPI + accessToken)
}

func (user *googleUser) Unmarshal(b []byte) error {
	return json.Unmarshal(b, user)
}

func (user *googleUser) String() string {
	return user.ID
}
