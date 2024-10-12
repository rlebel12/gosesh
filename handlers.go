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

		expiration := gs.now().UTC().Add(5 * time.Minute)
		cookie := gs.oauthStateCookie(state, expiration)
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

type HandlerDone func(http.ResponseWriter, *http.Request, error)

// Create a handler for the OAuth2 callback. This handler performs the token exchange and retrieves
// user data from the provider. When the OAuth2 flow has completed, the input `done` will be invoked, with
// the error value set to nil if the flow was successful, or an error if it was not.
func (gs *Gosesh) OAuth2Callback(user OAuth2User, config *oauth2.Config, done HandlerDone) http.HandlerFunc {
	if done == nil {
		gs.logWarn("no done handler provided for OAuth2Callback, using default")
		done = defaultDoneHandler(gs, "OAuth2Callback")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		oauthState, err := r.Cookie(gs.oAuth2StateCookieName)
		if err != nil {
			done(w, r, fmt.Errorf("%w: %w", ErrFailedGettingStateCookie, err))
			return
		}

		now := gs.now().UTC()
		stateCookie := gs.oauthStateCookie("", now)
		http.SetCookie(w, &stateCookie)

		if r.FormValue("state") != oauthState.Value {
			done(w, r, ErrInvalidStateCookie)
			return
		}

		token, err := config.Exchange(ctx, r.FormValue("code"))
		if err != nil {
			done(w, r, fmt.Errorf("%w: %w", ErrFailedExchangingToken, err))
			return
		}

		err = gs.unmarshalUserData(ctx, user, token.AccessToken)
		if err != nil {
			done(w, r, fmt.Errorf("%w: %w", ErrFailedUnmarshallingData, err))
			return
		}

		id, err := gs.store.UpsertUser(ctx, user)
		if err != nil {
			done(w, r, fmt.Errorf("%w: %w", ErrFailedUpsertingUser, err))
			return
		}

		session, err := gs.store.CreateSession(ctx, CreateSessionRequest{
			UserID:   id,
			IdleAt:   now.Add(gs.sessionActiveDuration),
			ExpireAt: now.Add(gs.sessionIdleDuration),
		})
		if err != nil {
			done(w, r, fmt.Errorf("%w: %w", ErrFailedCreatingSession, err))
			return
		}

		sessionCookie := gs.sessionCookie(session.ID(), session.ExpireAt())
		http.SetCookie(w, &sessionCookie)
		done(w, r, nil)
	}
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

var (
	ErrUnauthorized          = errors.New("unauthorized")
	ErrFailedDeletingSession = errors.New("failed deleting session(s)")
)

func (gs *Gosesh) Logout(done HandlerDone) http.HandlerFunc {
	if done == nil {
		gs.logWarn("no done handler provided for Logout, using default")
		done = defaultDoneHandler(gs, "Logout")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		r = gs.authenticate(w, r)
		session, ok := CurrentSession(r)
		if !ok {
			done(w, r, ErrUnauthorized)
			return
		}

		var err error
		switch {
		case r.URL.Query().Get("all") != "":
			_, err = gs.store.DeleteUserSessions(r.Context(), session.UserID())
		default:
			err = gs.store.DeleteSession(r.Context(), session.ID())
		}
		if err != nil {
			gs.logError("failed to delete session(s)", "err", err, "all", r.URL.Query().Get("all") != "")
			done(w, r, fmt.Errorf("%w: %w", ErrFailedDeletingSession, err))
			return
		}

		http.SetCookie(w, gs.expireSessionCookie())

		ctx := context.WithValue(r.Context(), SessionContextKey, nil)
		done(w, r.WithContext(ctx), nil)
	}
}

func defaultDoneHandler(sesh *Gosesh, handlerName string) HandlerDone {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		if err != nil {
			sesh.logError("failed in handler", "name", handlerName, "err", err.Error())
		}
	}
}
