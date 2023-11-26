package providers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/rlebel12/identity"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const GoogleProviderKey = "google"

func GoogleAuthLogin(i *identity.Identity) http.HandlerFunc {
	return identity.OAuthBeginHandler(i, GoogleOauthConfig(i))
}

func GoogleAuthCallback(i *identity.Identity) http.HandlerFunc {
	return identity.OAuthCallbackHandler[GoogleUser](i, GoogleOauthConfig(i))
}

type GoogleUser struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Picture       string `json:"picture"`
}

func (GoogleUser) Request(ctx context.Context, i *identity.Identity, accessToken string) (*http.Response, error) {
	const oauthGoogleUrlAPI = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="
	return http.Get(oauthGoogleUrlAPI + accessToken)
}

func (user GoogleUser) GetEmail() string {
	return user.Email
}

func GoogleOauthConfig(i *identity.Identity) *oauth2.Config {
	providerConf := i.Config.Providers[GoogleProviderKey]
	return &oauth2.Config{
		ClientID:     providerConf.ClientID,
		ClientSecret: providerConf.ClientSecret,
		RedirectURL: fmt.Sprintf(
			"%s://%s/auth/google/callback", i.Config.Origin.Scheme, i.Config.Origin.Host),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}
}
