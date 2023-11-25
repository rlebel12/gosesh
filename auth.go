package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

func OAuthBeginHandler(i *Identity, oauthCfg *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		b := make([]byte, 16)
		rand.Read(b)
		state := base64.URLEncoding.EncodeToString(b)

		expiration := time.Now().UTC().Add(5 * time.Minute)
		cookie := i.OauthStateCookie(state, expiration)
		http.SetCookie(w, &cookie)

		err := i.setCallbackRedirectURL(ctx, r, state)
		if err != nil {
			panic(err)
		}

		url := oauthCfg.AuthCodeURL(state)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)

	}
}

func (i *Identity) setCallbackRedirectURL(ctx context.Context, r *http.Request, state string) error {
	if i.Redirecter == nil {
		return nil
	}

	redirectURLRaw := r.URL.Query().Get("redirect_url")
	if redirectURLRaw == "" {
		return nil
	}

	redirectURL, err := url.Parse(redirectURLRaw)
	if err != nil {
		return err
	}

	i.Redirecter.SetCallbackRedirectURL(ctx, state, redirectURL)
	return nil
}

type UserDataRequester interface {
	Request(ctx context.Context, i *Identity, accessToken string) (*http.Response, error)
	GetEmail() string
}

func OAuthCallbackHandler[userDataRequester UserDataRequester](i *Identity, oauthCfg *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		oauthState, err := r.Cookie(i.Config.OAuthStateCookieName)
		if err != nil {
			return
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
			_ = fmt.Errorf("code exchange wrong: %s", err.Error())
			return
		}

		userData, err := getUserData[userDataRequester](ctx, i, token.AccessToken)
		if err != nil {
			// rctx.Logger().Error(err)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		}

		user, err := i.Storer.UpsertUser(ctx, UpsertUserRequest{
			Email: userData.GetEmail(),
		})
		if err != nil {
			// rctx.Logger().Error(err)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		}

		now := time.Now().UTC()
		session, err := i.Storer.CreateSession(ctx, CreateSessionRequest{
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

		redirectURL, err := i.getCallbackRedirectURL(ctx, oauthState.Value)
		if err != nil {
			// rctx.Logger().Error(err)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		}
		if *redirectURL != (url.URL{}) {
			http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
		}
	}
}

func getUserData[DataType UserDataRequester](ctx context.Context, i *Identity, accessToken string) (DataType, error) {
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

func (i *Identity) getCallbackRedirectURL(ctx context.Context, state string) (*url.URL, error) {
	if i.Redirecter == nil {
		return &url.URL{}, nil
	}

	return i.Redirecter.GetCallbackRedirectURL(ctx, state)
}

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
