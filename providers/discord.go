package providers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/rlebel12/gosesh"
	"golang.org/x/oauth2"
)

const DiscordProviderKey = "discord"

func DiscordAuthLogin(gs *gosesh.Gosesh) http.HandlerFunc {
	return gosesh.OAuthBeginHandler(gs, DiscordOauthConfig(gs))
}

func DiscordAuthCallback(gs *gosesh.Gosesh) http.HandlerFunc {
	return gosesh.OAuthCallbackHandler[DiscordUser](gs, DiscordOauthConfig(gs))
}

type DiscordUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
}

func (DiscordUser) Request(ctx context.Context, gs *gosesh.Gosesh, accessToken string) (*http.Response, error) {
	const oauthDiscordUrlAPI = "https://discord.com/api/v9/users/@me"
	req, err := http.NewRequest("GET", oauthDiscordUrlAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating request: %s", err.Error())
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	client := &http.Client{}
	return client.Do(req)
}

func (user DiscordUser) GetEmail() string {
	return user.Email
}

func DiscordOauthConfig(gs *gosesh.Gosesh) *oauth2.Config {
	providerConf := gs.Config.Providers[DiscordProviderKey]
	return &oauth2.Config{
		ClientID:     providerConf.ClientID,
		ClientSecret: providerConf.ClientSecret,
		RedirectURL: fmt.Sprintf(
			"%s://%s/auth/discord/callback", gs.Config.Origin.Scheme, gs.Config.Origin.Host),
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
