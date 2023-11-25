package identity

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type GoogleUser struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Picture       string `json:"picture"`
}

func (GoogleUser) Request(ctx context.Context, i *Identity, accessToken string) (*http.Response, error) {
	const oauthGoogleUrlAPI = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="
	return http.Get(oauthGoogleUrlAPI + accessToken)
}

func (user GoogleUser) GetEmail() string {
	return user.Email
}

func (i *Identity) GoogleOauthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     i.Config.GoogleOAuthConfig.ClientID,
		ClientSecret: i.Config.GoogleOAuthConfig.ClientSecret,
		RedirectURL: fmt.Sprintf(
			"%s://%s/auth/google/callback", i.Config.Origin.Scheme, i.Config.Origin.Host),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}
}
