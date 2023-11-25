package providers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/rlebel12/identity"
	"golang.org/x/oauth2"
)

const TwitchProviderKey = "twitch"

func TwitchAuthLogin(i *identity.Identity) http.HandlerFunc {
	return identity.OAuthBegin(i, TwitchOauthConfig(i))
}

func TwitchAuthCallback(i *identity.Identity) http.HandlerFunc {
	return identity.OAuthCallback[TwitchUser](i, TwitchOauthConfig(i))
}

type TwitchUser struct {
	Data []struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"data"`
}

func (TwitchUser) Request(ctx context.Context, i *identity.Identity, accessToken string) (*http.Response, error) {
	const oauthTwitchUrlAPI = "https://api.twitch.tv/helix/users"
	providerConf := i.Config.Providers[TwitchProviderKey]
	req, err := http.NewRequest("GET", oauthTwitchUrlAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating request: %s", err.Error())
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Client-Id", providerConf.ClientID)
	req.Header.Set("User-Agent", "Vel (127.0.0.1, 0.0.1)")
	client := &http.Client{}
	return client.Do(req)
}

func (user TwitchUser) GetEmail() string {
	if len(user.Data) == 0 {
		return ""
	}
	return user.Data[0].Email
}

func TwitchOauthConfig(i *identity.Identity) *oauth2.Config {
	providerConf := i.Config.Providers[TwitchProviderKey]
	return &oauth2.Config{
		ClientID:     providerConf.ClientID,
		ClientSecret: providerConf.ClientSecret,
		RedirectURL: fmt.Sprintf(
			"%s://%s/auth/twitch/callback", i.Config.Origin.Scheme, i.Config.Origin.Host),
		Scopes: []string{
			"user:read:email",
		},
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://id.twitch.tv/oauth2/authorize",
			TokenURL:  "https://id.twitch.tv/oauth2/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
}
