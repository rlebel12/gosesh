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
	Twitch struct {
		Provider
		keyMode twitchKeyMode
	}
)

// Creates a new Twitch OAuth2 provider. redirectPath should have a leading slash.
func NewTwitch(sesh Gosesher, scopes TwitchScopes, clientID, clientSecret, redirectPath string, opts ...Opt[Twitch]) *Twitch {
	twitch := &Twitch{
		Provider: newProvider(sesh, scopes.strings(), oauth2.Endpoint{
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
	const url = "https://api.twitch.tv/helix/users"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating request: %s", err.Error())
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Client-Id", t.Config.ClientID)
	return t.doRequest(req)
}

func (t *Twitch) NewUser() *TwitchUser {
	return &TwitchUser{keyMode: t.keyMode}
}

type TwitchScopes struct {
	Email bool
}

func (s TwitchScopes) strings() []string {
	scopes := []string{}
	if s.Email {
		scopes = append(scopes, "user:read:email")
	}
	return scopes
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
