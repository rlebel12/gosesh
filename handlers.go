package gosesh

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"time"

	"golang.org/x/oauth2"
)

// OAuth2Begin creates a handler that initiates the OAuth2 flow.
// It generates a secure state parameter, sets it in a cookie, and redirects to the OAuth2 provider.
func (gs *Gosesh) OAuth2Begin(oauthCfg *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setSecureCookieHeaders(w)

		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			gs.logError("failed to create OAuth2 state", err)
			http.Error(w, "failed to create OAuth2 state", http.StatusInternalServerError)
			return
		}
		state := base64.URLEncoding.EncodeToString(b)

		expiration := gs.now().UTC().Add(5 * time.Minute)
		cookie := gs.oauthStateCookie(state, expiration)
		http.SetCookie(w, cookie)

		next := r.URL.Query().Get(gs.redirectParamName)
		if next != "" {
			gs.setRedirectCookie(next, w)
		}

		url := oauthCfg.AuthCodeURL(state)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

type (
	// HandlerDoneFunc is a function type that handles the completion of an OAuth2 flow.
	// It is called with the response writer, request, and any error that occurred.
	HandlerDoneFunc func(http.ResponseWriter, *http.Request, error)

	// RequestFunc is a function type that retrieves user data from an OAuth2 provider.
	// It takes a context and access token, and returns a reader with the user data.
	RequestFunc func(ctx context.Context, accessToken string) (io.ReadCloser, error)

	// UnmarshalFunc is a function type that unmarshals user data into an Identifier.
	// It takes the raw user data and returns an Identifier and any error that occurred.
	UnmarshalFunc func(b []byte) (Identifier, error)
)

// OAuth2Callback creates a handler that completes the OAuth2 flow.
// It validates the state parameter, exchanges the code for a token, retrieves user data,
// and creates a session. When complete, it calls the provided done handler.
func (gs *Gosesh) OAuth2Callback(config *oauth2.Config, request RequestFunc, unmarshal UnmarshalFunc, done HandlerDoneFunc) http.HandlerFunc {
	if done == nil {
		gs.logWarn("no done handler provided for OAuth2Callback, using default")
		done = defaultDoneHandler(gs, "OAuth2Callback")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		setSecureCookieHeaders(w)

		ctx := r.Context()
		oauthState, err := r.Cookie(gs.oAuth2StateCookieName)
		if err != nil {
			done(w, r, fmt.Errorf("%w: %w", ErrFailedGettingStateCookie, err))
			return
		}

		now := gs.now().UTC()
		stateCookie := gs.oauthStateCookie("", now)
		http.SetCookie(w, stateCookie)

		if r.FormValue("state") != oauthState.Value {
			done(w, r, ErrInvalidStateCookie)
			return
		}

		token, err := config.Exchange(ctx, r.FormValue("code"))
		if err != nil {
			done(w, r, fmt.Errorf("%w: %w", ErrFailedExchangingToken, err))
			return
		}

		user, err := unmarshalUserData(ctx, request, unmarshal, token.AccessToken)
		if err != nil {
			done(w, r, fmt.Errorf("%w: %w", ErrFailedUnmarshallingData, err))
			return
		}

		id, err := gs.store.UpsertUser(ctx, user)
		if err != nil {
			done(w, r, fmt.Errorf("%w: %w", ErrFailedUpsertingUser, err))
			return
		}

		session, err := gs.store.CreateSession(
			ctx, id, now.Add(gs.sessionActiveDuration), now.Add(gs.sessionIdleDuration))
		if err != nil {
			done(w, r, fmt.Errorf("%w: %w", ErrFailedCreatingSession, err))
			return
		}

		sessionCookie := gs.sessionCookie(session.ID(), session.ExpireAt())
		http.SetCookie(w, sessionCookie)
		done(w, r, nil)
	}
}

// unmarshalUserData retrieves and unmarshals user data from an OAuth2 provider.
func unmarshalUserData(
	ctx context.Context,
	request RequestFunc,
	unmarshal UnmarshalFunc,
	accessToken string,
) (Identifier, error) {
	response, err := request(ctx, accessToken)
	if err != nil {
		return nil, fmt.Errorf("get user info: %w", err)
	}
	defer response.Close()
	contents, err := io.ReadAll(response)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	user, err := unmarshal(contents)
	if err != nil {
		return nil, fmt.Errorf("unmarshal user data: %w", err)
	}
	return user, nil
}

var (
	ErrUnauthorized          = errors.New("unauthorized")
	ErrFailedDeletingSession = errors.New("failed deleting session(s)")
)

// Logout creates a handler that terminates a user's session.
// If the "all" query parameter is present, it terminates all sessions for the user.
func (gs *Gosesh) Logout(done HandlerDoneFunc) http.HandlerFunc {
	if done == nil {
		gs.logWarn("no done handler provided for Logout, using default")
		done = defaultDoneHandler(gs, "Logout")
	}
	return gs.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			err = gs.store.DeleteSession(r.Context(), session.ID().String())
		}
		if err != nil {
			done(w, r, fmt.Errorf("%w: %w", ErrFailedDeletingSession, err))
			return
		}

		http.SetCookie(w, gs.expireSessionCookie())
		ctx := context.WithValue(r.Context(), sessionKey, nil)
		done(w, r.WithContext(ctx), nil)
	})).ServeHTTP
}

// CallbackRedirect creates a handler that redirects after an OAuth2 flow completes.
// It uses the redirect cookie to determine where to redirect, falling back to the default target.
func (gs *Gosesh) CallbackRedirect(defaultTarget string) http.HandlerFunc {
	if defaultTarget == "" {
		defaultTarget = "/"
	}
	return func(w http.ResponseWriter, r *http.Request) {
		redirectCookie, err := r.Cookie(gs.redirectCookieName)
		if err != nil {
			http.Redirect(w, r, defaultTarget, http.StatusTemporaryRedirect)
			return
		}

		path, err := base64.URLEncoding.DecodeString(redirectCookie.Value)
		redirectCookie = gs.redirectCookie("", gs.now())
		http.SetCookie(w, redirectCookie)
		if err != nil {
			gs.logError("failed to decode redirect path", err)
			http.Redirect(w, r, defaultTarget, http.StatusTemporaryRedirect)
			return
		}

		url, err := url.Parse(string(path))
		if err != nil {
			gs.logError("failed to parse redirect path", err)
			http.Redirect(w, r, defaultTarget, http.StatusTemporaryRedirect)
			return
		} else if url.Hostname() != "" && !slices.Contains(gs.allowedHosts, url.Hostname()) {
			gs.logWarn("disallowed host in redirect path", "host", url.Host)
			http.Redirect(w, r, defaultTarget, http.StatusTemporaryRedirect)
			return
		}

		http.Redirect(w, r, url.String(), http.StatusTemporaryRedirect)
	}
}

// defaultDoneHandler creates a default handler for OAuth2 flow completion.
// It handles errors by setting appropriate HTTP status codes and redirects on success.
func defaultDoneHandler(gs *Gosesh, handlerName string) HandlerDoneFunc {
	redirect := gs.CallbackRedirect("/")
	return func(w http.ResponseWriter, r *http.Request, err error) {
		if err != nil {
			code := http.StatusInternalServerError
			switch {
			case errors.Is(err, ErrUnauthorized):
				code = http.StatusUnauthorized
			case errors.Is(err, ErrSessionExpired):
				code = http.StatusUnauthorized
			default:
				gs.logError("callback", err, "name", handlerName)
			}
			http.Error(w, http.StatusText(code), code)
			return
		}
		redirect(w, r)
	}
}
