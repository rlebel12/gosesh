package gosesh

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

func (gs *Gosesh) OAuth2Begin(oauthCfg *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			gs.logError("failed to create OAuth2 state", "err", err)
			http.Error(w, "failed to create OAuth2 state", http.StatusInternalServerError)
			return
		}
		state := base64.URLEncoding.EncodeToString(b)

		expiration := gs.Now().UTC().Add(5 * time.Minute)
		cookie := gs.OauthStateCookie(state, expiration)
		http.SetCookie(w, &cookie)

		url := oauthCfg.AuthCodeURL(state)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

var (
	ErrFailedGettingStateCookie = errors.New("failed getting state cookie")
	ErrInvalidStateCookie       = errors.New("invalid state cookie")
	ErrFailedExchangingToken    = errors.New("failed exchanging token")
	ErrFailedUnmarshallingData  = errors.New("failed unmarshalling data")
	ErrFailedUpsertingUser      = errors.New("failed upserting user")
	ErrFailedCreatingSession    = errors.New("failed creating session")
)

func (gs *Gosesh) OAuth2Callback(w http.ResponseWriter, r *http.Request, user OAuth2User, config *oauth2.Config) error {
	ctx := r.Context()
	oauthState, err := r.Cookie(gs.oAuth2StateCookieName)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFailedGettingStateCookie, err)
	}

	stateCookie := gs.OauthStateCookie("", gs.Now().UTC())
	http.SetCookie(w, &stateCookie)

	if r.FormValue("state") != oauthState.Value {
		return ErrInvalidStateCookie
	}

	token, err := config.Exchange(ctx, r.FormValue("code"))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFailedExchangingToken, err)
	}

	err = gs.unmarshalUserData(ctx, user, token.AccessToken)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFailedUnmarshallingData, err)
	}

	id, err := gs.store.UpsertUser(ctx, user)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFailedUpsertingUser, err)
	}

	now := gs.Now().UTC()
	session, err := gs.store.CreateSession(ctx, CreateSessionRequest{
		UserID:   id,
		IdleAt:   now.Add(gs.sessionActiveDuration),
		ExpireAt: now.Add(gs.sessionIdleDuration),
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFailedCreatingSession, err)
	}

	sessionCookie := gs.SessionCookie(session.ID, session.ExpireAt)
	http.SetCookie(w, &sessionCookie)
	return nil
}

func (gs *Gosesh) unmarshalUserData(ctx context.Context, data OAuth2User, accessToken string) error {
	response, err := data.Request(ctx, accessToken)
	if err != nil {
		return fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer response.Body.Close()
	contents, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("failed read response: %s", err.Error())
	}

	return data.Unmarshal(contents)
}

func (gs *Gosesh) LogoutHandler(completeHandler http.HandlerFunc) http.HandlerFunc {
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

		if completeHandler == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		completeHandler(w, r)
	}
}

var ErrUnauthorized = errors.New("unauthorized")

func (gs *Gosesh) Logout(w http.ResponseWriter, r *http.Request) (*http.Request, error) {
	r = gs.authenticate(r)
	session, ok := CurrentSession(r)
	if !ok {
		return r, ErrUnauthorized
	}

	var err error
	switch {
	case r.URL.Query().Get("all") != "":
		_, err = gs.store.DeleteUserSessions(r.Context(), session.UserID)
	default:
		err = gs.store.DeleteSession(r.Context(), session.ID)
	}
	if err != nil {
		gs.logError("failed to delete session(s)", "err", err, "all", r.URL.Query().Get("all") != "")
		return r, err
	}

	sessionCookie := gs.ExpireSessionCookie()
	http.SetCookie(w, &sessionCookie)

	ctx := context.WithValue(r.Context(), SessionContextKey, nil)
	return r.WithContext(ctx), nil
}
