package gosesh

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
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
		if session.IdleAt().After(now) {
			next.ServeHTTP(w, r)
			return
		}

		session, err := gs.replaceSession(r.Context(), session, now)
		if err != nil {
			gs.logError("replace session", err)
			next.ServeHTTP(w, r)
			return
		}

		if err := gs.monitor.AuditSessionRefreshed(r.Context(), session.ID(), session.ID(), session.UserID(), nil); err != nil {
			gs.logError("monitor audit session refreshed", err)
		}

		sessionCookie := gs.sessionCookie(session.ID(), session.ExpireAt())
		http.SetCookie(w, sessionCookie)

		r = gs.newRequestWithSession(r, session)
		next.ServeHTTP(w, r)
	}))
}

func (gs *Gosesh) replaceSession(ctx context.Context, old_session Session, now time.Time) (Session, error) {
	new_session, err := gs.store.CreateSession(
		ctx,
		old_session.UserID(),
		now.Add(gs.sessionActiveDuration),
		now.Add(gs.sessionIdleDuration),
	)
	if err != nil {
		return old_session, fmt.Errorf("create session: %w", err)
	}

	if err := gs.store.DeleteSession(ctx, old_session.ID().String()); err != nil {
		return new_session, fmt.Errorf("delete session: %w", err)
	}
	return new_session, nil
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
		if err := gs.monitor.AuditAuthenticationFailure(ctx, nil, "no session cookie", nil); err != nil {
			gs.logError("monitor audit authentication failure", err)
		}
		return r
	}

	sessionID, err := base64.URLEncoding.DecodeString(sessionCookie.Value)
	if err != nil {
		gs.logError("failed to decode session cookie", err)
		if err := gs.monitor.AuditAuthenticationFailure(ctx, nil, "invalid session cookie", nil); err != nil {
			gs.logError("monitor audit authentication failure", err)
		}
		http.SetCookie(w, gs.expireSessionCookie())
		return r
	}

	session, err := gs.store.GetSession(ctx, string(sessionID))
	if err != nil {
		gs.logError("get session", err)
		if err := gs.monitor.AuditAuthenticationFailure(ctx, nil, "failed to get session", map[string]string{"error": err.Error()}); err != nil {
			gs.logError("monitor audit authentication failure", err)
		}
		http.SetCookie(w, gs.expireSessionCookie())
		return r
	}

	if session.ExpireAt().Before(gs.now().UTC()) {
		gs.logError("session expired", ErrSessionExpired)
		if err := gs.monitor.AuditAuthenticationFailure(ctx, session.UserID(), "session expired", nil); err != nil {
			gs.logError("monitor audit authentication failure", err)
		}
		http.SetCookie(w, gs.expireSessionCookie())
		return r
	}

	if err := gs.monitor.AuditAuthenticationSuccess(ctx, session.UserID(), nil); err != nil {
		gs.logError("monitor audit authentication success", err)
	}
	return gs.newRequestWithSession(r, session)
}

func (gs *Gosesh) newRequestWithSession(r *http.Request, session Session) *http.Request {
	ctx := r.Context()
	ctx = context.WithValue(ctx, sessionKey, session)
	return r.WithContext(ctx)
}
