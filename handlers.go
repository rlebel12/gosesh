package gosesh

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

const (
	defaultSessionActiveDuration = 1 * time.Hour
	defaultSessionIdleDuration   = 24 * time.Hour
)

func (gs *Gosesh[T]) OAuth2Begin(oauthCfg *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 16)
		rand.Read(b)
		state := base64.URLEncoding.EncodeToString(b)

		expiration := time.Now().UTC().Add(5 * time.Minute)
		cookie := gs.OauthStateCookie(state, expiration)
		http.SetCookie(w, &cookie)

		url := oauthCfg.AuthCodeURL(state)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

var (
	ErrMissingArguments         = errors.New("missing arguments")
	ErrFailedGettingStateCookie = errors.New("failed getting state cookie")
	ErrInvalidStateCookie       = errors.New("invalid state cookie")
	ErrFailedExchangingToken    = errors.New("failed exchanging token")
	ErrFailedUnmarshallingData  = errors.New("failed unmarshalling data")
	ErrFailedUpsertingUser      = errors.New("failed upserting user")
	ErrFailedCreatingSession    = errors.New("failed creating session")
)

type OAuth2CallbackParams struct {
	W            http.ResponseWriter
	R            *http.Request
	User         OAuth2User
	OAuth2Config *oauth2.Config
}

func (gs *Gosesh[T]) OAuth2Callback(args OAuth2CallbackParams) error {
	if args.R == nil {
		return errors.New("missing request")
	} else if args.W == nil {
		return errors.New("missing response writer")
	} else if args.User == nil {
		return errors.New("missing requester")
	} else if args.OAuth2Config == nil {
		return errors.New("missing oauth config")
	}

	r := args.R
	w := args.W
	ctx := r.Context()
	oauthState, err := r.Cookie(gs.Config.OAuth2StateCookieName)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFailedGettingStateCookie, err)
	}

	stateCookie := gs.OauthStateCookie("", time.Now().UTC())
	http.SetCookie(w, &stateCookie)

	if r.FormValue("state") != oauthState.Value {
		return fmt.Errorf("%w: %w", ErrInvalidStateCookie, err)
	}

	token, err := args.OAuth2Config.Exchange(ctx, r.FormValue("code"))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFailedExchangingToken, err)
	}

	err = gs.unmarshalUserData(ctx, args.User, token.AccessToken)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFailedUnmarshallingData, err)
	}

	id, err := gs.Store.UpsertUser(ctx, args.User)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFailedUpsertingUser, err)
	}

	now := time.Now().UTC()
	session, err := gs.Store.CreateSession(ctx, CreateSessionRequest{
		UserID:   id,
		IdleAt:   now.Add(gs.Config.SessionActiveDuration),
		ExpireAt: now.Add(gs.Config.SessionIdleDuration),
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFailedCreatingSession, err)
	}

	sessionCookie := gs.SessionCookie(session.ID, session.ExpireAt)
	http.SetCookie(w, &sessionCookie)
	return nil
}

func (gs *Gosesh[T]) unmarshalUserData(ctx context.Context, data OAuth2User, accessToken string) error {
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

func (gs *Gosesh[T]) LogoutHandler(completeHandler http.HandlerFunc) http.HandlerFunc {
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

func (gs *Gosesh[T]) Logout(w http.ResponseWriter, r *http.Request) (*http.Request, error) {
	r = gs.authenticate(w, r)
	session, ok := CurrentSession(r)
	if !ok {
		return r, ErrUnauthorized
	}

	var err error
	switch {
	case r.URL.Query().Get("all") != "":
		_, err = gs.Store.DeleteUserSessions(r.Context(), session.UserID)
	default:
		err = gs.Store.DeleteSession(r.Context(), session.ID)
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
