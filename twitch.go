package identity

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

type TwitchUser struct {
	Data []struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"data"`
}

func (TwitchUser) Request(ctx context.Context, i *Identity, accessToken string) (*http.Response, error) {
	const oauthTwitchUrlAPI = "https://api.twitch.tv/helix/users"
	req, err := http.NewRequest("GET", oauthTwitchUrlAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating request: %s", err.Error())
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Client-Id", i.Config.TwitchOAuthConfig.ClientID)
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

func (i *Identity) TwitchOauthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     i.Config.TwitchOAuthConfig.ClientID,
		ClientSecret: i.Config.TwitchOAuthConfig.ClientSecret,
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
