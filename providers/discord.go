package providers

import (
	"context"
	"io"
	"net/http"

	"github.com/rlebel12/gosesh"
	"golang.org/x/oauth2"
)

// Discord provides OAuth2 authentication using Discord's OAuth2 service.
// It implements the basic OAuth2 flow for Discord authentication with configurable key modes.
type Discord struct {
	Provider
	keyMode discordKeyMode
}

// NewDiscord creates a new Discord OAuth2 provider with the given configuration.
// The redirectPath parameter should have a leading slash.
// Additional options can be provided to customize the provider's behavior.
func NewDiscord(sesh Gosesher, clientID, clientSecret, redirectPath string, opts ...Opt[Discord]) *Discord {
	discord := &Discord{
		Provider: newProvider(sesh, []string{"identify"}, oauth2.Endpoint{
			AuthURL:   "https://discord.com/oauth2/authorize",
			TokenURL:  "https://discord.com/api/oauth2/token",
			AuthStyle: oauth2.AuthStyleInParams,
		}, clientID, clientSecret, redirectPath),
	}
	for _, opt := range opts {
		opt(discord)
	}
	return discord
}

// WithDiscordKeyMode sets the key mode for the Discord provider.
// The key mode determines whether to use the user's ID or email as their unique identifier.
func WithDiscordKeyMode(mode discordKeyMode) Opt[Discord] {
	return func(d *Discord) {
		d.keyMode = mode
	}
}

// discordKeyMode determines how to identify a Discord user.
type discordKeyMode int

const (
	// DiscordKeyModeID uses the user's Discord ID as their unique identifier.
	DiscordKeyModeID discordKeyMode = iota
	// DiscordKeyModeEmail uses the user's email address as their unique identifier.
	DiscordKeyModeEmail
)

// WithDiscordEmailScope adds the email scope to the Discord provider's OAuth2 configuration.
// This is required to access the user's email address.
func WithDiscordEmailScope() Opt[Discord] {
	return func(d *Discord) {
		d.Config.Scopes = append(d.Config.Scopes, "email")
	}
}

// OAuth2Begin returns a handler that initiates the Discord OAuth2 flow.
func (d *Discord) OAuth2Begin() http.HandlerFunc {
	return d.Gosesh.OAuth2Begin(d.Config)
}

// OAuth2Callback returns a handler that completes the Discord OAuth2 flow.
// The handler parameter is called when the flow completes, with any error that occurred.
func (d *Discord) OAuth2Callback(handler gosesh.HandlerDoneFunc) http.HandlerFunc {
	return d.Gosesh.OAuth2Callback(d.Config, d.requestUser, unmarshalUser(d.NewUser), handler)
}

// requestUser makes a request to Discord's users endpoint to get the user's data.
func (d *Discord) requestUser(ctx context.Context, accessToken string) (io.ReadCloser, error) {
	return d.doRequest("GET", "https://discord.com/api/v9/users/@me", http.Header{"Authorization": {"Bearer " + accessToken}})
}

// NewUser creates a new DiscordUser instance with the current key mode.
func (d *Discord) NewUser() *DiscordUser {
	return &DiscordUser{keyMode: d.keyMode}
}

// DiscordUser represents a user authenticated through Discord's OAuth2 service.
// It contains the user's Discord account information.
type DiscordUser struct {
	ID       string `json:"id"`                 // The user's unique Discord ID
	Username string `json:"username"`           // The user's Discord username
	Email    string `json:"email,omitempty"`    // The user's email address (requires email scope)
	Verified bool   `json:"verified,omitempty"` // Whether the email is verified

	keyMode discordKeyMode `json:"-"` // Determines which field to use as the unique identifier
}

// String returns either the user's ID or email as their unique identifier,
// depending on the configured key mode.
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
