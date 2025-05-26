package providers

import (
	"net/http"

	"github.com/rlebel12/gosesh"
	"golang.org/x/oauth2"
)

// TickTick provides OAuth2 authentication using TickTick's OAuth2 service.
// It implements the basic OAuth2 flow for TickTick authentication with configurable scopes.
type TickTick struct {
	Provider
}

// NewTickTick creates a new TickTick OAuth2 provider with the given configuration.
// The redirectPath parameter should have a leading slash.
// Additional options can be provided to customize the provider's behavior.
func NewTickTick(sesh Gosesher, clientID, clientSecret, redirectPath string, opts ...Opt[TickTick]) *TickTick {
	ticktick := &TickTick{
		Provider: newProvider(sesh, []string{"tasks:read"}, oauth2.Endpoint{
			AuthURL:   "https://ticktick.com/oauth/authorize",
			TokenURL:  "https://ticktick.com/oauth/token",
			AuthStyle: oauth2.AuthStyleInParams,
		}, clientID, clientSecret, redirectPath),
	}
	for _, opt := range opts {
		opt(ticktick)
	}
	return ticktick
}

// WithTickTickWriteScope adds the tasks:write scope to the TickTick provider's OAuth2 configuration.
// This is required to create, update, and delete tasks.
func WithTickTickWriteScope() Opt[TickTick] {
	return func(t *TickTick) {
		t.Config.Scopes = append(t.Config.Scopes, "tasks:write")
	}
}

// OAuth2Begin returns a handler that initiates the TickTick OAuth2 flow.
func (t *TickTick) OAuth2Begin() http.HandlerFunc {
	return t.Gosesh.OAuth2Begin(t.Config)
}

// OAuth2Callback returns a handler that completes the TickTick OAuth2 flow.
// The handler parameter is called when the flow completes, with any error that occurred.
func (t *TickTick) OAuth2Callback(handler gosesh.HandlerDoneFunc) http.HandlerFunc {
	return t.Gosesh.OAuth2Callback(t.Config, t.requestUser, unmarshalUser(t.NewUser), handler)
}
