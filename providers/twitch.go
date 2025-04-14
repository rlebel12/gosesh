package providers

import (
	"context"
	"io"
	"net/http"

	"github.com/rlebel12/gosesh"
	"golang.org/x/oauth2"
)

type (
	Twitch struct {
		Provider
		keyMode twitchKeyMode
	}
)

// Creates a new Twitch OAuth2 provider. redirectPath should have a leading slash.
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

func WithTwitchKeyMode(mode twitchKeyMode) Opt[Twitch] {
	return func(t *Twitch) {
		t.keyMode = mode
	}
}

func WithEmailScope() Opt[Twitch] {
	return func(t *Twitch) {
		t.Config.Scopes = append(t.Config.Scopes, "user:read:email")
	}
}

type twitchKeyMode int

const (
	TwitchKeyModeID twitchKeyMode = iota
	TwitchKeyModeEmail
)

func (t *Twitch) OAuth2Begin() http.HandlerFunc {
	return t.Gosesh.OAuth2Begin(t.Config)
}

func (t *Twitch) OAuth2Callback(handler gosesh.HandlerDoneFunc) http.HandlerFunc {
	return t.Gosesh.OAuth2Callback(t.Config, t.requestUser, unmarshalUser(t.NewUser), handler)
}

func (t *Twitch) requestUser(ctx context.Context, accessToken string) (io.ReadCloser, error) {
	return t.doRequest("GET", "https://api.twitch.tv/helix/users", http.Header{
		"Authorization": {"Bearer " + accessToken},
		"Client-Id":     {t.Config.ClientID},
	})
}

func (t *Twitch) NewUser() *TwitchUser {
	return &TwitchUser{keyMode: t.keyMode}
}

type TwitchUser struct {
	Data []struct {
		ID    string `json:"id"`
		Login string `json:"login"`
		Email string `json:"email"`
	} `json:"data"`

	keyMode twitchKeyMode `json:"-"`
}

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
