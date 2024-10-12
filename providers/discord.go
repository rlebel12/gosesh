package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/rlebel12/gosesh"
	"golang.org/x/oauth2"
)

// Creates a new Discord OAuth2 provider. redirectPath should have a leading slash.
func NewDiscord(sesh Gosesher, scopes DiscordScopes, credentials gosesh.OAuth2Credentials, redirectPath string, opts ...DiscordOpt) *Discord {
	oauth2Config := &oauth2.Config{
		ClientID:     credentials.ClientID(),
		ClientSecret: credentials.ClientSecret(),
		RedirectURL: fmt.Sprintf(
			"%s://%s%s", sesh.Scheme(), sesh.Host(), redirectPath),
		Scopes: scopes.strings(),
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://discord.com/oauth2/authorize",
			TokenURL:  "https://discord.com/api/oauth2/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
	discord := &Discord{
		Gosesh:      sesh,
		Config:      oauth2Config,
		discordHost: "https://discord.com",
		keyMode:     DiscordKeyModeID,
	}
	for _, opt := range opts {
		opt(discord)
	}
	return discord
}

func WithDiscordKeyMode(mode discordKeyMode) DiscordOpt {
	return func(d *Discord) {
		d.keyMode = mode
	}
}

type (
	Discord struct {
		Gosesh      Gosesher
		Config      *oauth2.Config
		discordHost string
		keyMode     discordKeyMode
	}

	DiscordOpt func(*Discord)

	discordKeyMode int
)

const (
	DiscordKeyModeID discordKeyMode = iota
	DiscordKeyModeEmail
)

func (d *Discord) OAuth2Begin() http.HandlerFunc {
	return d.Gosesh.OAuth2Begin(d.Config)
}

func (d *Discord) OAuth2Callback(handler gosesh.HandlerDone) http.HandlerFunc {
	return d.Gosesh.OAuth2Callback(d.NewUser(), d.Config, handler)
}

func (d *Discord) NewUser() gosesh.OAuth2User {
	return &DiscordUser{Discord: d, DiscordHost: "https://discord.com"}
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

	Discord     *Discord `json:"-"`
	DiscordHost string   `json:"-"`
}

func (user *DiscordUser) String() string {
	switch user.Discord.keyMode {
	case DiscordKeyModeID:
		return user.ID
	case DiscordKeyModeEmail:
		return user.Email
	default:
		return user.ID
	}
}

func (user *DiscordUser) Request(ctx context.Context, accessToken string) (*http.Response, error) {
	url := fmt.Sprintf("%s/api/v9/users/@me", user.DiscordHost)
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
