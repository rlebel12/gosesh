package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/rlebel12/gosesh"
	"golang.org/x/oauth2"
)

func NewDiscordProvider(gs *gosesh.Gosesh, scopes DiscordScopes) DiscordProvider {
	return DiscordProvider{
		gs:  gs,
		cfg: DiscordOauthConfig(*gs.Config, scopes),
	}
}

type DiscordProvider struct {
	gs  *gosesh.Gosesh
	cfg *oauth2.Config
}

func (p *DiscordProvider) OAuth2Begin(w http.ResponseWriter, r *http.Request) {
	p.gs.OAuth2Begin(p.cfg)(w, r)
}

func (p *DiscordProvider) OAuth2Callback(w http.ResponseWriter, r *http.Request) error {
	return p.gs.OAuth2Callback(w, r, new(DiscordUser), p.cfg)
}

type DiscordScopes struct {
	Email bool
}

func (s DiscordScopes) Strings() []string {
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

func (*DiscordUser) Request(ctx context.Context, accessToken string) (*http.Response, error) {
	const oauthDiscordUrlAPI = "https://discord.com/api/v9/users/@me"
	req, err := http.NewRequest("GET", oauthDiscordUrlAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating request: %s", err.Error())
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	client := &http.Client{}
	return client.Do(req)
}

func (user *DiscordUser) Unmarshal(b []byte) error {
	return json.Unmarshal(b, user)
}

func (user *DiscordUser) String() string {
	return user.ID
}

const DiscordProviderKey = "discord"

func DiscordOauthConfig(config gosesh.Config, scopes DiscordScopes) *oauth2.Config {
	providerConf := config.Providers[DiscordProviderKey]
	return &oauth2.Config{
		ClientID:     providerConf.ClientID,
		ClientSecret: providerConf.ClientSecret,
		RedirectURL: fmt.Sprintf(
			"%s://%s/auth/discord/callback", config.Origin.Scheme, config.Origin.Host),
		Scopes: scopes.Strings(),
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://discord.com/oauth2/authorize",
			TokenURL:  "https://discord.com/api/oauth2/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
}

func WithDiscordProvider(pConfig gosesh.OAuthProviderConfig) func(*gosesh.Config) {
	return func(config *gosesh.Config) {
		config.Providers[DiscordProviderKey] = gosesh.OAuthProviderConfig{
			ClientID:     pConfig.ClientID,
			ClientSecret: pConfig.ClientSecret,
		}
	}
}
