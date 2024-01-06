package providers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/rlebel12/gosesh"
	"golang.org/x/oauth2"
)

const TwitchProviderKey = "twitch"

func TwitchAuthLogin(gs *gosesh.Gosesh) http.HandlerFunc {
	return gosesh.OAuthBeginHandler(gs, TwitchOauthConfig(gs))
}

func TwitchAuthCallback(gs *gosesh.Gosesh) http.HandlerFunc {
	return gosesh.OAuthCallbackHandler[TwitchUser](gs, TwitchOauthConfig(gs))
}

type TwitchUser struct {
	Data []struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"data"`
}

func (TwitchUser) Request(ctx context.Context, gs *gosesh.Gosesh, accessToken string) (*http.Response, error) {
	const oauthTwitchUrlAPI = "https://api.twitch.tv/helix/users"
	providerConf := gs.Config.Providers[TwitchProviderKey]
	req, err := http.NewRequest("GET", oauthTwitchUrlAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating request: %s", err.Error())
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Client-Id", providerConf.ClientID)
	client := &http.Client{}
	return client.Do(req)
}

func (user TwitchUser) GetEmail() string {
	if len(user.Data) == 0 {
		return ""
	}
	return user.Data[0].Email
}

func TwitchOauthConfig(gs *gosesh.Gosesh) *oauth2.Config {
	providerConf := gs.Config.Providers[TwitchProviderKey]
	return &oauth2.Config{
		ClientID:     providerConf.ClientID,
		ClientSecret: providerConf.ClientSecret,
		RedirectURL: fmt.Sprintf(
			"%s://%s/auth/twitch/callback", gs.Config.Origin.Scheme, gs.Config.Origin.Host),
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
