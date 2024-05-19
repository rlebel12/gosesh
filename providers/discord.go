package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/rlebel12/gosesh"
	"golang.org/x/oauth2"
)

func NewDiscord(gs *gosesh.Gosesh, scopes DiscordScopes, credentials gosesh.OAuth2Credentials) Discord {
	oauth2Config := &oauth2.Config{
		ClientID:     credentials.ClientID,
		ClientSecret: credentials.ClientSecret,
		RedirectURL: fmt.Sprintf(
			"%s://%s/auth/discord/callback", gs.Config().Origin.Scheme, gs.Config().Origin.Host),
		Scopes: scopes.Strings(),
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://discord.com/oauth2/authorize",
			TokenURL:  "https://discord.com/api/oauth2/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
	return Discord{
		gs:  gs,
		cfg: oauth2Config,
	}
}

type Discord struct {
	gs  *gosesh.Gosesh
	cfg *oauth2.Config
}

func (p *Discord) OAuth2Begin(w http.ResponseWriter, r *http.Request) {
	p.gs.OAuth2Begin(p.cfg).ServeHTTP(w, r)
}

func (p *Discord) OAuth2Callback(w http.ResponseWriter, r *http.Request) error {
	return p.gs.OAuth2Callback(w, r, new(discordUser), p.cfg)
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

type discordUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email,omitempty"`
	Verified bool   `json:"verified,omitempty"`
}

func (*discordUser) Request(ctx context.Context, accessToken string) (*http.Response, error) {
	const oauthDiscordUrlAPI = "https://discord.com/api/v9/users/@me"
	req, err := http.NewRequest("GET", oauthDiscordUrlAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating request: %s", err.Error())
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	client := &http.Client{}
	return client.Do(req)
}

func (user *discordUser) Unmarshal(b []byte) error {
	return json.Unmarshal(b, user)
}

func (user *discordUser) String() string {
	return user.ID
}
