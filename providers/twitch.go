package providers

import (
	"context"
	"io"
	"net/http"

	"github.com/rlebel12/gosesh"
	"golang.org/x/oauth2"
)

// Twitch provides OAuth2 authentication using Twitch's OAuth2 service.
// It implements the basic OAuth2 flow for Twitch authentication with configurable key modes.
type Twitch struct {
	Provider
	keyMode twitchKeyMode
}

// NewTwitch creates a new Twitch OAuth2 provider with the given configuration.
// The redirectPath parameter should have a leading slash.
// Additional options can be provided to customize the provider's behavior.
func NewTwitch(sesh Gosesher, clientID, clientSecret, redirectPath string, opts ...Opt[Twitch]) *Twitch {
	twitch := &Twitch{
		Provider: newProvider(sesh, []string{}, oauth2.Endpoint{
			AuthURL:   "https://id.twitch.tv/oauth2/authorize",
			TokenURL:  "https://id.twitch.tv/oauth2/token",
			AuthStyle: oauth2.AuthStyleInParams,
		}, clientID, clientSecret, redirectPath),
		keyMode: TwitchKeyModeID,
	}
	for _, opt := range opts {
		opt(twitch)
	}
	return twitch
}

// WithTwitchKeyMode sets the key mode for the Twitch provider.
// The key mode determines whether to use the user's ID or email as their unique identifier.
func WithTwitchKeyMode(mode twitchKeyMode) Opt[Twitch] {
	return func(t *Twitch) {
		t.keyMode = mode
	}
}

// WithEmailScope adds the email scope to the Twitch provider's OAuth2 configuration.
// This is required to access the user's email address.
func WithEmailScope() Opt[Twitch] {
	return func(t *Twitch) {
		t.Config.Scopes = append(t.Config.Scopes, "user:read:email")
	}
}

// twitchKeyMode determines how to identify a Twitch user.
type twitchKeyMode int

const (
	// TwitchKeyModeID uses the user's Twitch ID as their unique identifier.
	TwitchKeyModeID twitchKeyMode = iota
	// TwitchKeyModeEmail uses the user's email address as their unique identifier.
	TwitchKeyModeEmail
)

// OAuth2Begin returns a handler that initiates the Twitch OAuth2 flow.
func (t *Twitch) OAuth2Begin() http.HandlerFunc {
	return t.Gosesh.OAuth2Begin(t.Config)
}

// OAuth2Callback returns a handler that completes the Twitch OAuth2 flow.
// The handler parameter is called when the flow completes, with any error that occurred.
func (t *Twitch) OAuth2Callback(handler gosesh.HandlerDoneFunc) http.HandlerFunc {
	return t.Gosesh.OAuth2Callback(t.Config, t.requestUser, unmarshalUser(t.NewUser), handler)
}

// requestUser makes a request to Twitch's users endpoint to get the user's data.
func (t *Twitch) requestUser(ctx context.Context, accessToken string) (io.ReadCloser, error) {
	return t.doRequest("GET", "https://api.twitch.tv/helix/users", http.Header{
		"Authorization": {"Bearer " + accessToken},
		"Client-Id":     {t.Config.ClientID},
	})
}

// NewUser creates a new TwitchUser instance with the current key mode.
func (t *Twitch) NewUser() *TwitchUser {
	return &TwitchUser{keyMode: t.keyMode}
}

// TwitchUser represents a user authenticated through Twitch's OAuth2 service.
// It contains the user's Twitch account information.
type TwitchUser struct {
	Data []struct {
		ID    string `json:"id"`    // The user's unique Twitch ID
		Login string `json:"login"` // The user's Twitch login name
		Email string `json:"email"` // The user's email address (requires email scope)
	} `json:"data"`

	keyMode twitchKeyMode `json:"-"` // Determines which field to use as the unique identifier
}

// String returns either the user's ID or email as their unique identifier,
// depending on the configured key mode.
func (user *TwitchUser) String() string {
	if len(user.Data) == 0 {
		return ""
	}

	switch user.keyMode {
	case TwitchKeyModeEmail:
		return user.Data[0].Email
	case TwitchKeyModeID:
		fallthrough
	default:
		return user.Data[0].ID
	}
}
