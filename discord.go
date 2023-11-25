package identity

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

type DiscordUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
}

func (DiscordUser) Request(ctx context.Context, i *Identity, accessToken string) (*http.Response, error) {
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

func (i *Identity) DiscordOauthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     i.Config.DiscordOAuthConfig.ClientID,
		ClientSecret: i.Config.DiscordOAuthConfig.ClientSecret,
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
