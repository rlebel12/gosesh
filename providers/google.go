package providers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/rlebel12/gosesh"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const GoogleProviderKey = "google"

func GoogleAuthLogin(gs *gosesh.Gosesh) http.HandlerFunc {
	return gosesh.OAuthBeginHandler(gs, GoogleOauthConfig(gs))
}

func GoogleAuthCallback(gs *gosesh.Gosesh) http.HandlerFunc {
	return gosesh.OAuthCallbackHandler[GoogleUser](gs, GoogleOauthConfig(gs))
}

type GoogleUser struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Picture       string `json:"picture"`
}

func (GoogleUser) Request(ctx context.Context, gs *gosesh.Gosesh, accessToken string) (*http.Response, error) {
	const oauthGoogleUrlAPI = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="
	return http.Get(oauthGoogleUrlAPI + accessToken)
}

func (user GoogleUser) GetEmail() string {
	return user.Email
}

func GoogleOauthConfig(gs *gosesh.Gosesh) *oauth2.Config {
	providerConf := gs.Config.Providers[GoogleProviderKey]
	return &oauth2.Config{
		ClientID:     providerConf.ClientID,
		ClientSecret: providerConf.ClientSecret,
		RedirectURL: fmt.Sprintf(
			"%s://%s/auth/google/callback", gs.Config.Origin.Scheme, gs.Config.Origin.Host),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}
}
