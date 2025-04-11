package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/rlebel12/gosesh"
	"golang.org/x/oauth2"
)

type (
	Twitch struct {
		sesh       Gosesher
		cfg        *oauth2.Config
		twitchHost string
		keyMode    twitchKeyMode
	}

	TwitchOpt func(*Twitch)
)

// Creates a new Twitch OAuth2 provider. redirectPath should have a leading slash.
func NewTwitch(sesh Gosesher, scopes TwitchScopes, credentials gosesh.OAuth2Credentials, redirectPath string, opts ...TwitchOpt) *Twitch {
	oauth2Config := &oauth2.Config{
		ClientID:     credentials.ClientID(),
		ClientSecret: credentials.ClientSecret(),
		RedirectURL: fmt.Sprintf(
			"%s://%s%s", sesh.Scheme(), sesh.Host(), redirectPath),
		Scopes: scopes.strings(),
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://id.twitch.tv/oauth2/authorize",
			TokenURL:  "https://id.twitch.tv/oauth2/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
	twitch := &Twitch{
		sesh:       sesh,
		cfg:        oauth2Config,
		twitchHost: "https://api.twitch.tv",
		keyMode:    TwitchKeyModeID,
	}
	for _, opt := range opts {
		opt(twitch)
	}
	return twitch
}

func WithTwitchKeyMode(mode twitchKeyMode) TwitchOpt {
	return func(t *Twitch) {
		t.keyMode = mode
	}
}

// To help with testing, this function allows you to set the Twitch host to a different value (i.e. httptest.Server.URL).
func WithTwitchHost(host string) TwitchOpt {
	return func(t *Twitch) {
		t.twitchHost = host
	}
}

type twitchKeyMode int

const (
	TwitchKeyModeID twitchKeyMode = iota
	TwitchKeyModeEmail
)

func (t *Twitch) OAuth2Begin() http.HandlerFunc {
	return t.sesh.OAuth2Begin(t.cfg)
}

func (t *Twitch) OAuth2Callback(handler gosesh.HandlerDone) http.HandlerFunc {
	return t.sesh.OAuth2Callback(t.NewUser(), t.cfg, handler)
}

func (t *Twitch) NewUser() gosesh.OAuth2User {
	return &TwitchUser{twitch: t}
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

	twitch *Twitch `json:"-"`
}

func (user *TwitchUser) String() string {
	if len(user.Data) == 0 {
		return ""
	}

	switch user.twitch.keyMode {
	case TwitchKeyModeID:
		return user.Data[0].ID
	case TwitchKeyModeEmail:
		return user.Data[0].Email
	default:
		return user.Data[0].ID
	}
}

func (user *TwitchUser) Request(ctx context.Context, accessToken string) (*http.Response, error) {
	url := fmt.Sprintf("%s/helix/users", user.twitch.twitchHost)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating request: %s", err.Error())
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Client-Id", user.twitch.cfg.ClientID)
	client := &http.Client{}
	return client.Do(req)
}

func (user *TwitchUser) Unmarshal(b []byte) error {
	return json.Unmarshal(b, user)
}
