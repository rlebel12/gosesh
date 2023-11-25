package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

const (
	callbackRedirectKeyBase = "callback_redirect"
)

const (
	SessionActiveDuration = 1 * time.Hour
	SessionIdleDuration   = 24 * time.Hour
)

type UserDataRequester interface {
	Request(ctx context.Context, i *Identity, accessToken string) (*http.Response, error)
	GetEmail() string
}

func GetUserData[DataType UserDataRequester](ctx context.Context, i *Identity, accessToken string) (DataType, error) {
	var userData DataType
	response, err := userData.Request(ctx, i, accessToken)
	if err != nil {
		return userData, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer response.Body.Close()
	contents, err := io.ReadAll(response.Body)
	if err != nil {
		return userData, fmt.Errorf("failed read response: %s", err.Error())
	}

	if err := json.Unmarshal(contents, &userData); err != nil {
		return userData, fmt.Errorf("failed unmarshalling response: %s", err.Error())
	}
	return userData, nil
}

func (i *Identity) GoogleAuthLogin(w http.ResponseWriter, r *http.Request) error {
	return i.login(w, r, i.GoogleOauthConfig())
}

func (i *Identity) DiscordAuthLogin(w http.ResponseWriter, r *http.Request) error {
	return i.login(w, r, i.DiscordOauthConfig())
}

func (i *Identity) TwitchAuthLogin(w http.ResponseWriter, r *http.Request) error {
	return i.login(w, r, i.TwitchOauthConfig())
}

func (i *Identity) login(w http.ResponseWriter, r *http.Request, oauthCfg *oauth2.Config) error {
	// ctx := r.Context()
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)

	expiration := time.Now().UTC().Add(5 * time.Minute)
	cookie := i.OauthStateCookie(state, expiration)
	http.SetCookie(w, &cookie)

	// err = setCallbackRedirectURL(rctx, state, params.RedirectURL)
	// if err != nil {
	// 	return err
	// }

	url := oauthCfg.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	return nil
	// return rctx.Redirect(http.StatusTemporaryRedirect, url)
}

// func setCallbackRedirectURL(rctx contexts.RequestContext, state string, redirectURL string) error {
// 	if rctx.AppContext.Cache == nil || redirectURL == "" {
// 		return nil
// 	}
// 	key := callbackRedirectURLKey(state)
// 	return rctx.AppContext.Cache.SetCallbackRedirectURL(
// 		rctx.Request().Context(), key, redirectURL, 5*time.Minute,
// 	)
// }

func (i *Identity) GoogleAuthCallback(w http.ResponseWriter, r *http.Request) error {
	return callback[GoogleUser](i, w, r, i.GoogleOauthConfig())
}

func (i *Identity) DiscordAuthCallback(w http.ResponseWriter, r *http.Request) error {
	return callback[DiscordUser](i, w, r, i.DiscordOauthConfig())
}

func (i *Identity) TwitchAuthCallback(w http.ResponseWriter, r *http.Request) error {
	return callback[TwitchUser](i, w, r, i.TwitchOauthConfig())
}

func callback[UserDataType UserDataRequester](
	i *Identity, w http.ResponseWriter, r *http.Request, oauthCfg *oauth2.Config,
) error {
	ctx := r.Context()
	oauthState, err := r.Cookie(OauthStateCookieName)
	if err != nil {
		return err
	}

	stateCookie := i.OauthStateCookie("", time.Now().UTC())
	http.SetCookie(w, &stateCookie)

	stateFromForm := r.FormValue("state")
	if stateFromForm != oauthState.Value {
		// rctx.Logger().Error("invalid oauth state")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}

	code := r.FormValue("code")
	token, err := oauthCfg.Exchange(ctx, code)
	if err != nil {
		return fmt.Errorf("code exchange wrong: %s", err.Error())
	}

	userData, err := GetUserData[UserDataType](ctx, i, token.AccessToken)
	if err != nil {
		// rctx.Logger().Error(err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}

	user, err := i.Identifier.UpsertUser(ctx, UpsertUserRequest{
		Email: userData.GetEmail(),
	})
	if err != nil {
		// rctx.Logger().Error(err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}

	now := time.Now().UTC()
	session, err := i.Identifier.CreateSession(ctx, CreateSessionRequest{
		User:     user,
		IdleAt:   now.Add(SessionIdleDuration),
		ExpireAt: now.Add(SessionActiveDuration),
	})
	if err != nil {
		// rctx.Logger().Error(err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}

	sessionCookie := i.SessionCookie(session.ID, session.ExpireAt)
	http.SetCookie(w, &sessionCookie)

	// redirectURL, err := getCallbackRedirectURL(rctx, oauthState.Value)
	// if err != nil {
	// 	rctx.Logger().Error(err)
	// 	return rctx.Redirect(http.StatusTemporaryRedirect, "/")
	// }
	// if redirectURL != "" {
	// 	return rctx.Redirect(http.StatusPermanentRedirect, redirectURL)
	// }

	return nil
}

// func getCallbackRedirectURL(rctx contexts.RequestContext, state string) (string, error) {
// 	if rctx.AppContext.Cache == nil {
// 		return "", nil
// 	}
// 	key := callbackRedirectURLKey(state)
// 	return rctx.AppContext.Cache.GetCallbackRedirectURL(rctx.Request().Context(), key)
// }

// type logoutIn struct {
// 	AllSessions bool `query:"all"`
// }

// func (i *Identity) Logout(w http.ResponseWriter, r *http.Request) error {
// 	sessionID, err := r.Cookie(AuthSessionCookieName)

// 	sessionCookie := i.SessionCookie(uuid.UUID{}, time.Now().UTC())
// 	http.SetCookie(w, &sessionCookie)

// 	i.Identifier.DeleteSession(r.Context(), i.Session(r).ID)

// 	return rctx.Redirect(http.StatusTemporaryRedirect, "/")
// }

// func callbackRedirectURLKey(state string) string {
// 	return fmt.Sprintf("%s:%s", callbackRedirectKeyBase, state)
// }
