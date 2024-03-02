package gosesh

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"
)

const (
	defaultSessionActiveDuration = 1 * time.Hour
	defaultSessionIdleDuration   = 24 * time.Hour
)

func OAuthBeginHandler(gs *Gosesh, oauthCfg *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		b := make([]byte, 16)
		rand.Read(b)
		state := base64.URLEncoding.EncodeToString(b)

		expiration := time.Now().UTC().Add(5 * time.Minute)
		cookie := gs.OauthStateCookie(state, expiration)
		http.SetCookie(w, &cookie)

		err := gs.setCallbackRedirectURL(ctx, r, state)
		if err != nil {
			slog.Error("Failed to set callback redirect URL: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		url := oauthCfg.AuthCodeURL(state)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)

	}
}

func (gs *Gosesh) setCallbackRedirectURL(ctx context.Context, r *http.Request, state string) error {
	if gs.CallbackRedirecter == nil {
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

	gs.CallbackRedirecter.SetURL(ctx, state, redirectURL)
	return nil
}

type Emailer interface {
	GetEmail() string
}

type UserDataRequester interface {
	Request(ctx context.Context, gs *Gosesh, accessToken string) (*http.Response, error)
	Emailer
}

func OAuthCallbackHandler[T UserDataRequester](gs *Gosesh, oauthCfg *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		oauthState, err := r.Cookie(gs.Config.OAuthStateCookieName)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		stateCookie := gs.OauthStateCookie("", time.Now().UTC())
		http.SetCookie(w, &stateCookie)

		if r.FormValue("state") != oauthState.Value {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		token, err := oauthCfg.Exchange(ctx, r.FormValue("code"))
		if err != nil {
			slog.Error("failed to exchange token", "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		data, err := getUserData[T](ctx, gs, token.AccessToken)
		if err != nil {
			slog.Error("failed to get user data", "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		id, err := gs.Store.UpsertUser(ctx, data)
		if err != nil {
			slog.Error("failed to upsert user", "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		now := time.Now().UTC()
		session, err := gs.Store.CreateSession(ctx, CreateSessionRequest{
			UserID:   id,
			IdleAt:   now.Add(gs.Config.SessionActiveDuration),
			ExpireAt: now.Add(gs.Config.SessionIdleDuration),
		})
		if err != nil {
			slog.Error("failed to create session", "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		sessionCookie := gs.SessionCookie(session.ID, session.ExpireAt)
		http.SetCookie(w, &sessionCookie)

		redirectURL, err := gs.getCallbackRedirectURL(ctx, oauthState.Value)
		if err != nil {
			slog.Error("failed to get callback redirect URL", "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if *redirectURL != (url.URL{}) {
			http.Redirect(w, r, redirectURL.String(), http.StatusPermanentRedirect)
			return
		}
		redirectURL, ok := ctx.Value(CallbackRedirectKey).(*url.URL)
		if ok && *redirectURL != (url.URL{}) {
			http.Redirect(w, r, redirectURL.String(), http.StatusPermanentRedirect)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func getUserData[T UserDataRequester](ctx context.Context, gs *Gosesh, accessToken string) (T, error) {
	var data T
	response, err := data.Request(ctx, gs, accessToken)
	if err != nil {
		return data, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer response.Body.Close()
	contents, err := io.ReadAll(response.Body)
	if err != nil {
		return data, fmt.Errorf("failed read response: %s", err.Error())
	}

	if err := json.Unmarshal(contents, &data); err != nil {
		return data, fmt.Errorf("failed unmarshalling response: %s", err.Error())
	}
	return data, nil
}

func (gs *Gosesh) getCallbackRedirectURL(ctx context.Context, state string) (*url.URL, error) {
	if gs.CallbackRedirecter == nil {
		return &url.URL{}, nil
	}

	return gs.CallbackRedirecter.GetURL(ctx, state)
}

func (gs *Gosesh) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r, err := gs.Logout(w, r)
		if err != nil {
			if errors.Is(err, ErrUnauthorized) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		redirectURL, ok := r.Context().Value(LogoutRedirectKey).(*url.URL)
		if ok && *redirectURL != (url.URL{}) {
			http.Redirect(w, r, redirectURL.String(), http.StatusPermanentRedirect)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

var ErrUnauthorized = errors.New("unauthorized")

func (gs *Gosesh) Logout(w http.ResponseWriter, r *http.Request) (*http.Request, error) {
	r = gs.authenticate(w, r)
	session, ok := CurrentSession(r)
	if !ok {
		return r, ErrUnauthorized
	}

	var err error
	switch {
	case r.URL.Query().Get("all") != "":
		err = gs.Store.DeleteSession(r.Context(), session.ID)
	default:
		_, err = gs.Store.DeleteUserSessions(r.Context(), session.UserID)
	}
	if err != nil {
		slog.Error("failed to delete session(s)", "err", err, "all", r.URL.Query().Get("all") != "")
		return r, err
	}

	sessionCookie := gs.ExpireSessionCookie()
	http.SetCookie(w, &sessionCookie)

	ctx := context.WithValue(r.Context(), SessionContextKey, nil)
	return r.WithContext(ctx), nil
}
