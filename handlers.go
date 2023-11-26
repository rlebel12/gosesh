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

	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

const (
	defaultSessionActiveDuration = 1 * time.Hour
	defaultSessionIdleDuration   = 24 * time.Hour
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
	if i.CallbackRedirecter == nil {
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

	i.CallbackRedirecter.SetURL(ctx, state, redirectURL)
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

		if r.FormValue("state") != oauthState.Value {
			// rctx.Logger().Error("invalid oauth state")
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		}

		token, err := oauthCfg.Exchange(ctx, r.FormValue("code"))
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
			IdleAt:   now.Add(i.Config.SessionActiveDuration),
			ExpireAt: now.Add(i.Config.SessionIdleDuration),
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
	if i.CallbackRedirecter == nil {
		return &url.URL{}, nil
	}

	return i.CallbackRedirecter.GetURL(ctx, state)
}

func (i *Identity) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r = i.authenticate(w, r)
		session, ok := CurrentSession(r)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		var err error
		switch {
		case r.URL.Query().Get("all") != "":
			err = i.Storer.DeleteSession(r.Context(), session.ID)
		default:
			err = i.Storer.DeleteUserSessions(r.Context(), session.User.ID)
		}
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		sessionCookie := i.SessionCookie(uuid.UUID{}, time.Now().UTC())
		http.SetCookie(w, &sessionCookie)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}
}
