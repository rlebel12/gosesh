package providers

// import (
// 	"context"
// 	"fmt"
// 	"net/http"

// 	"github.com/rlebel12/gosesh"
// 	"golang.org/x/oauth2"
// )

// func NewTwitchProvider[ID gosesh.Identifier](gs *gosesh.Gosesh[ID], scopes TwitchScopes) TwitchProvider[ID] {
// 	return TwitchProvider[ID]{
// 		gs:  gs,
// 		cfg: TwitchOauthConfig(*gs.Config, scopes),
// 	}
// }

// type TwitchProvider[ID gosesh.Identifier] struct {
// 	gs  *gosesh.Gosesh[ID]
// 	cfg *oauth2.Config
// }

// func (p *TwitchProvider[ID]) LoginHandler() http.HandlerFunc {
// 	return p.gs.OAuth2Begin(p.cfg)
// }

// func (p *TwitchProvider[ID]) Callback(w http.ResponseWriter, r *http.Request) error {
// 	return p.gs.OAuth2Callback(gosesh.OAuth2CallbackParams{
// 		W:            w,
// 		R:            r,
// 		User:         new(TwitchUser),
// 		OAuth2Config: p.cfg,
// 	})
// }

// type TwitchScopes struct {
// 	Email bool
// }

// func (s TwitchScopes) Strings() []string {
// 	scopes := []string{"identify"}
// 	if s.Email {
// 		scopes = append(scopes, "email")
// 	}
// 	return scopes
// }

// type TwitchUser struct {
// 	ID       string `json:"id"`
// 	Username string `json:"username"`
// 	Email    string `json:"email,omitempty"`
// 	Verified bool   `json:"verified,omitempty"`
// }

// func (*TwitchUser) Request(ctx context.Context, accessToken string) (*http.Response, error) {
// 	const oauthTwitchUrlAPI = "https://api.twitch.tv/helix/users"
// 	providerConf := gs.Config.Providers[TwitchProviderKey]
// 	req, err := http.NewRequest("GET", oauthTwitchUrlAPI, nil)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed creating request: %s", err.Error())
// 	}
// 	req.Header.Set("Authorization", "Bearer "+accessToken)
// 	req.Header.Set("Client-Id", providerConf.ClientID)
// 	client := &http.Client{}
// 	return client.Do(req)
// }

// func (user *TwitchUser) Unmarshal(b []byte) error {
// 	return json.Unmarshal(b, user)
// }

// func (user *TwitchUser) String() string {
// 	return user.ID
// }

// const TwitchProviderKey = "twitch"

// func TwitchOauthConfig(config gosesh.Config, scopes TwitchScopes) *oauth2.Config {
// 	providerConf := config.Providers[TwitchProviderKey]
// 	return &oauth2.Config{
// 		ClientID:     providerConf.ClientID,
// 		ClientSecret: providerConf.ClientSecret,
// 		RedirectURL: fmt.Sprintf(
// 			"%s://%s/auth/twitch/callback", config.Origin.Scheme, config.Origin.Host),
// 		Scopes: scopes.Strings(),
// 		Endpoint: oauth2.Endpoint{
// 			AuthURL:   "https://twitch.com/oauth2/authorize",
// 			TokenURL:  "https://twitch.com/api/oauth2/token",
// 			AuthStyle: oauth2.AuthStyleInParams,
// 		},
// 	}
// }

// const TwitchProviderKey = "twitch"

// func TwitchAuthLogin(gs *gosesh.Gosesh) http.HandlerFunc {
// 	return gosesh.OAuthBeginHandler(gs, TwitchOauthConfig(gs))
// }

// func TwitchAuthCallback(gs *gosesh.Gosesh, completeHandler http.HandlerFunc) http.HandlerFunc {
// 	return gosesh.OAuthCallbackHandler[TwitchUser](gs, TwitchOauthConfig(gs))
// }

// type TwitchUser struct {
// 	Data []struct {
// 		ID    string `json:"id"`
// 		Email string `json:"email"`
// 	} `json:"data"`
// }

// func (TwitchUser) Request(ctx context.Context, gs *gosesh.Gosesh, accessToken string) (*http.Response, error) {
// 	const oauthTwitchUrlAPI = "https://api.twitch.tv/helix/users"
// 	providerConf := gs.Config.Providers[TwitchProviderKey]
// 	req, err := http.NewRequest("GET", oauthTwitchUrlAPI, nil)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed creating request: %s", err.Error())
// 	}
// 	req.Header.Set("Authorization", "Bearer "+accessToken)
// 	req.Header.Set("Client-Id", providerConf.ClientID)
// 	client := &http.Client{}
// 	return client.Do(req)
// }

// func (user TwitchUser) GetEmail() string {
// 	if len(user.Data) == 0 {
// 		return ""
// 	}
// 	return user.Data[0].Email
// }

// func TwitchOauthConfig(gs *gosesh.Gosesh) *oauth2.Config {
// 	providerConf := gs.Config.Providers[TwitchProviderKey]
// 	return &oauth2.Config{
// 		ClientID:     providerConf.ClientID,
// 		ClientSecret: providerConf.ClientSecret,
// 		RedirectURL: fmt.Sprintf(
// 			"%s://%s/auth/twitch/callback", gs.Config.Origin.Scheme, gs.Config.Origin.Host),
// 		Scopes: []string{
// 			"user:read:email",
// 		},
// 		Endpoint: oauth2.Endpoint{
// 			AuthURL:   "https://id.twitch.tv/oauth2/authorize",
// 			TokenURL:  "https://id.twitch.tv/oauth2/token",
// 			AuthStyle: oauth2.AuthStyleInParams,
// 		},
// 	}
// }
