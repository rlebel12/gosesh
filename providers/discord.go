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
		ClientID:     credentials.ClientID,
		ClientSecret: credentials.ClientSecret,
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
		gosesh:      sesh,
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
		Config      *oauth2.Config
		gosesh      Gosesher
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
	return d.gosesh.OAuth2Begin(d.Config)
}

func (d *Discord) OAuth2Callback(handler gosesh.CallbackHandler) http.HandlerFunc {
	user := &DiscordUser{Discord: d}
	return d.gosesh.OAuth2Callback(user, d.Config, handler)
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
	Id       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email,omitempty"`
	Verified bool   `json:"verified,omitempty"`

	Discord *Discord `json:"-"`
	Host    *string  `json:"-"` // Exposed for testing only
}

func (user *DiscordUser) ID() string {
	switch user.Discord.keyMode {
	case DiscordKeyModeID:
		return user.Id
	case DiscordKeyModeEmail:
		return user.Email
	default:
		return user.Id
	}
}

func (user *DiscordUser) Request(ctx context.Context, accessToken string) (*http.Response, error) {
	discordHost := "https://discord.com"
	if user.Host != nil {
		discordHost = *user.Host
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
