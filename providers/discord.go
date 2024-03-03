package providers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/rlebel12/gosesh"
	"golang.org/x/oauth2"
)

func NewDiscordProvider(gs *gosesh.Gosesh, scopes DiscordScopes) DiscordProvider {
	return DiscordProvider{
		gs:  gs,
		cfg: DiscordOauthConfig(gs, scopes),
	}
}

type DiscordProvider struct {
	gs  *gosesh.Gosesh
	cfg *oauth2.Config
}

func (p *DiscordProvider) DiscordAuthLogin() http.HandlerFunc {
	return gosesh.OAuthBeginHandler(p.gs, p.cfg)
}

func (p *DiscordProvider) DiscordAuthCallback() http.HandlerFunc {
	return gosesh.OAuthCallbackHandler[DiscordUser](p.gs, p.cfg)
}

type DiscordScopes struct {
	Email bool
}

func (s DiscordScopes) String() []string {
	scopes := []string{"identify"}
	if s.Email {
		scopes = append(scopes, "email")
	}
	return scopes
}

type DiscordUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email,omitempty"`
	Verified bool   `json:"verified,omitempty"`
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

const DiscordProviderKey = "discord"

func DiscordOauthConfig(gs *gosesh.Gosesh, scopes DiscordScopes) *oauth2.Config {
	providerConf := gs.Config.Providers[DiscordProviderKey]
	return &oauth2.Config{
		ClientID:     providerConf.ClientID,
		ClientSecret: providerConf.ClientSecret,
		RedirectURL: fmt.Sprintf(
			"%s://%s/auth/discord/callback", gs.Config.Origin.Scheme, gs.Config.Origin.Host),
		Scopes: scopes.String(),
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://discord.com/oauth2/authorize",
			TokenURL:  "https://discord.com/api/oauth2/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
}
