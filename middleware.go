package gosesh

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
)

// sessionContextKey is the type used for the session context key.
type sessionContextKey struct{}

// sessionKey is the context key used to store the current session.
var sessionKey = sessionContextKey{}

func (gs *Gosesh) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = gs.authenticate(w, r)
		next.ServeHTTP(w, r)
	})
}

func (gs *Gosesh) AuthenticateAndRefresh(next http.Handler) http.Handler {
	return gs.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := CurrentSession(r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		now := gs.now().UTC()
		timeUntilIdle := session.IdleDeadline().Sub(now)

		// Only extend if within refresh threshold
		if timeUntilIdle > gs.sessionRefreshThreshold {
			next.ServeHTTP(w, r)
			return
		}

		// Calculate new idle deadline, capped at absolute deadline
		newIdleDeadline := now.Add(gs.sessionIdleTimeout)
		if newIdleDeadline.After(session.AbsoluteDeadline()) {
			newIdleDeadline = session.AbsoluteDeadline()
		}

		if err := gs.store.ExtendSession(r.Context(), session.ID().String(), newIdleDeadline); err != nil {
			gs.logError("extend session", err)
			next.ServeHTTP(w, r)
			return
		}

		// Update cookie expiration
		sessionCookie := gs.sessionCookie(session.ID(), session.AbsoluteDeadline())
		http.SetCookie(w, sessionCookie)

		next.ServeHTTP(w, r)
	}))
}

// RequireAuth creates middleware that requires a valid session.
// If no valid session exists, it returns a 401 Unauthorized response.
func (gs *Gosesh) RequireAuthentication(next http.Handler) http.Handler {
	return gs.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := CurrentSession(r); !ok {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	}))
}

func (gs *Gosesh) RedirectUnauthenticated(loginURL url.URL, isRedirectableOpt ...func(r *http.Request) bool) func(next http.Handler) http.Handler {
	isRedirectable := func(r *http.Request) bool {
		return strings.Contains(r.Header.Get("Accept"), "text/html")
	}
	if len(isRedirectableOpt) > 0 {
		isRedirectable = isRedirectableOpt[0]
	}

	return func(next http.Handler) http.Handler {
		return gs.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, ok := CurrentSession(r)
			if ok {
				next.ServeHTTP(w, r)
				return
			}
			if !isRedirectable(r) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			gs.setRedirectCookie(r.URL.Path, w)
			http.Redirect(w, r, loginURL.String(), http.StatusTemporaryRedirect)
		}))
	}
}

// CurrentSession retrieves the current session from the request context.
// Returns the session and true if a session exists, nil and false otherwise.
func CurrentSession(r *http.Request) (Session, bool) {
	session, ok := r.Context().Value(sessionKey).(Session)
	return session, ok
}

func (gs *Gosesh) authenticate(w http.ResponseWriter, r *http.Request) *http.Request {
	_, ok := CurrentSession(r)
	if ok {
		return r
	}

	setSecureCookieHeaders(w)
	ctx := r.Context()

	sessionCookie, err := r.Cookie(gs.sessionCookieName)
	if err != nil {
		return r
	}

	sessionID, err := base64.URLEncoding.DecodeString(sessionCookie.Value)
	if err != nil {
		gs.logError("failed to decode session cookie", err)
		http.SetCookie(w, gs.expireSessionCookie())
		return r
	}

	session, err := gs.store.GetSession(ctx, string(sessionID))
	if err != nil {
		gs.logError("get session", err)
		http.SetCookie(w, gs.expireSessionCookie())
		return r
	}

	now := gs.now().UTC()

	// Check idle deadline (sliding window)
	if session.IdleDeadline().Before(now) {
		gs.logError("session idle expired", ErrSessionExpired)
		http.SetCookie(w, gs.expireSessionCookie())
		return r
	}

	// Check absolute deadline (hard limit)
	if session.AbsoluteDeadline().Before(now) {
		gs.logError("session absolute expired", ErrSessionExpired)
		http.SetCookie(w, gs.expireSessionCookie())
		return r
	}

	return gs.newRequestWithSession(r, session)
}

func (gs *Gosesh) newRequestWithSession(r *http.Request, session Session) *http.Request {
	ctx := r.Context()
	ctx = context.WithValue(ctx, sessionKey, session)
	return r.WithContext(ctx)
}
