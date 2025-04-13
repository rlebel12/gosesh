package providers

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/rlebel12/gosesh"
	"golang.org/x/oauth2"
)

type (
	Discord struct {
		Provider
		keyMode discordKeyMode
	}
)

// Creates a new Discord OAuth2 provider. redirectPath should have a leading slash.
func NewDiscord(sesh Gosesher, scopes DiscordScopes, clientID, clientSecret, redirectPath string, opts ...Opt[Discord]) *Discord {
	discord := &Discord{
		Provider: newProvider(sesh, scopes.strings(), oauth2.Endpoint{
			AuthURL:   "https://discord.com/oauth2/authorize",
			TokenURL:  "https://discord.com/api/oauth2/token",
			AuthStyle: oauth2.AuthStyleInParams,
		}, clientID, clientSecret, redirectPath),
		keyMode: DiscordKeyModeID,
	}
	for _, opt := range opts {
		opt(discord)
	}
	return discord
}

func WithDiscordKeyMode(mode discordKeyMode) Opt[Discord] {
	return func(d *Discord) {
		d.keyMode = mode
	}
}

type discordKeyMode int

const (
	DiscordKeyModeID discordKeyMode = iota
	DiscordKeyModeEmail
)

func (d *Discord) OAuth2Begin() http.HandlerFunc {
	return d.Gosesh.OAuth2Begin(d.Config)
}

func (d *Discord) OAuth2Callback(handler gosesh.HandlerDoneFunc) http.HandlerFunc {
	return d.Gosesh.OAuth2Callback(d.Config, d.requestUser, unmarshalUser(d.NewUser), handler)
}

func (d *Discord) requestUser(ctx context.Context, accessToken string) (io.ReadCloser, error) {
	const url = "https://discord.com/api/v9/users/@me"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating request: %s", err.Error())
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	return d.doRequest(req)
}

func (d *Discord) NewUser() DiscordUser {
	return DiscordUser{keyMode: d.keyMode}
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

	keyMode discordKeyMode `json:"-"`
}

func (user DiscordUser) String() string {
	switch user.keyMode {
	case DiscordKeyModeEmail:
		return user.Email
	case DiscordKeyModeID:
		fallthrough
	default:
		return user.ID
	}
}
