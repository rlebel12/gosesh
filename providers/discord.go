package providers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/rlebel12/identity"
	"golang.org/x/oauth2"
)

func DiscordAuthLogin(i *identity.Identity, w http.ResponseWriter, r *http.Request) error {
	return identity.OAuthBegin(i, w, r, DiscordOauthConfig(i))
}

func DiscordAuthCallback(i *identity.Identity, w http.ResponseWriter, r *http.Request) error {
	return identity.OAuthCallback[DiscordUser](i, w, r, DiscordOauthConfig(i))
}

type DiscordUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
}

func (DiscordUser) Request(ctx context.Context, i *identity.Identity, accessToken string) (*http.Response, error) {
	const oauthDiscordUrlAPI = "https://discord.com/api/v9/users/@me"
	req, err := http.NewRequest("GET", oauthDiscordUrlAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating request: %s", err.Error())
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("User-Agent", "Vel (127.0.0.1, 0.0.1)")
	client := &http.Client{}
	return client.Do(req)
}

func (user DiscordUser) GetEmail() string {
	return user.Email
}

func DiscordOauthConfig(i *identity.Identity) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     i.Config.Providers.Discord.ClientID,
		ClientSecret: i.Config.Providers.Discord.ClientSecret,
		RedirectURL: fmt.Sprintf(
			"%s://%s/auth/discord/callback", i.Config.Origin.Scheme, i.Config.Origin.Host),
		Scopes: []string{
			"identify",
			"email",
		},
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://discord.com/oauth2/authorize",
			TokenURL:  "https://discord.com/api/oauth2/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
}
