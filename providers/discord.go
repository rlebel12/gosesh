package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/rlebel12/gosesh"
	"golang.org/x/oauth2"
)

func NewDiscord(sesh Gosesher, scopes DiscordScopes, credentials gosesh.OAuth2Credentials) Discord {
	oauth2Config := &oauth2.Config{
		ClientID:     credentials.ClientID,
		ClientSecret: credentials.ClientSecret,
		RedirectURL: fmt.Sprintf(
			"%s://%s/auth/discord/callback", sesh.Scheme(), sesh.Host()),
		Scopes: scopes.strings(),
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://discord.com/oauth2/authorize",
			TokenURL:  "https://discord.com/api/oauth2/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
	return Discord{
		gs:          sesh,
		cfg:         oauth2Config,
		discordHost: "https://discord.com",
	}
}

type Discord struct {
	gs          Gosesher
	cfg         *oauth2.Config
	discordHost string
}

func (p *Discord) OAuth2Begin(w http.ResponseWriter, r *http.Request) {
	p.gs.OAuth2Begin(p.cfg).ServeHTTP(w, r)
}

func (p *Discord) OAuth2Callback(w http.ResponseWriter, r *http.Request) error {
	return p.gs.OAuth2Callback(w, r, new(DiscordUser), p.cfg)
}

type DiscordScopes struct {
	Email bool
}

func (s DiscordScopes) strings() []string {
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
	testHost *string
}

func (user *DiscordUser) String() string {
	return user.ID
}

func (user *DiscordUser) Request(ctx context.Context, accessToken string) (*http.Response, error) {
	discordHost := "https://discord.com"
	if user.testHost != nil {
		discordHost = *user.testHost
	}
	url := fmt.Sprintf("%s/api/v9/users/@me", discordHost)
	req, err := http.NewRequest("GET", url, nil)
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
