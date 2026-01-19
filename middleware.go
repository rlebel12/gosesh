package gosesh

import (
	"context"
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

		sessionCfg := gs.credentialSource.SessionConfig()

		// Check if refresh is enabled for this credential source
		if sessionCfg.RefreshThreshold == nil {
			next.ServeHTTP(w, r)
			return
		}

		now := gs.now().UTC()
		timeUntilIdle := session.IdleDeadline().Sub(now)

		// Only extend if within refresh threshold (0 = always refresh)
		if *sessionCfg.RefreshThreshold > 0 && timeUntilIdle > *sessionCfg.RefreshThreshold {
			next.ServeHTTP(w, r)
			return
		}

		// Calculate new idle deadline, capped at absolute deadline
		newIdleDeadline := now.Add(sessionCfg.IdleDuration)
		if newIdleDeadline.After(session.AbsoluteDeadline()) {
			newIdleDeadline = session.AbsoluteDeadline()
		}

		if err := gs.store.ExtendSession(r.Context(), session.ID().String(), newIdleDeadline); err != nil {
			gs.logger.Error("extend session", "error", err)
			next.ServeHTTP(w, r)
			return
		}

		// Write session to credential source
		if err := gs.credentialSource.WriteSession(w, session); err != nil {
			gs.logger.Error("write session", "error", err)
		}

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

	// Read session ID from credential source
	sessionID := gs.credentialSource.ReadSessionID(r)
	if sessionID == "" {
		return r
	}

	session, err := gs.store.GetSession(ctx, sessionID)
	if err != nil {
		gs.logger.Error("get session", "error", err)
		gs.credentialSource.ClearSession(w)
		return r
	}

	now := gs.now().UTC()

	// Record activity if tracker is enabled (record after session validated, before expiry checks)
	if gs.activityTracker != nil {
		gs.activityTracker.RecordActivity(sessionID, now)
	}

	// Check idle deadline (sliding window)
	if session.IdleDeadline().Before(now) {
		gs.logger.Debug("session idle expired")
		gs.credentialSource.ClearSession(w)
		return r
	}

	// Check absolute deadline (hard limit)
	if session.AbsoluteDeadline().Before(now) {
		gs.logger.Warn("session absolute expired")
		gs.credentialSource.ClearSession(w)
		return r
	}

	return gs.newRequestWithSession(r, session)
}

func (gs *Gosesh) newRequestWithSession(r *http.Request, session Session) *http.Request {
	ctx := r.Context()
	ctx = context.WithValue(ctx, sessionKey, session)
	return r.WithContext(ctx)
}
