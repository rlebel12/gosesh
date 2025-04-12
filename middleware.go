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

type contextKey string

const (
	SessionContextKey contextKey = "session"
)

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

		sessionCookie := gs.sessionCookie(session.ID(), session.ExpireAt())
		http.SetCookie(w, sessionCookie)

		r = gs.newRequestWithSession(r, session)
		next.ServeHTTP(w, r)
	}))
}

func (gs *Gosesh) replaceSession(ctx context.Context, old_session Session, now time.Time) (Session, error) {
	new_session, err := gs.store.CreateSession(ctx, CreateSessionRequest{
		UserID:   old_session.UserID(),
		IdleAt:   now.Add(gs.sessionActiveDuration),
		ExpireAt: now.Add(gs.sessionIdleDuration),
	})
	if err != nil {
		return old_session, fmt.Errorf("create session: %w", err)
	}

	if err := gs.store.DeleteSession(ctx, old_session.ID()); err != nil {
		return new_session, fmt.Errorf("delete session: %w", err)
	}
	return new_session, nil
}

func (gs *Gosesh) RequireAuthentication(next http.Handler) http.Handler {
	return gs.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := CurrentSession(r)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
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

func CurrentSession(r *http.Request) (Session, bool) {
	session, ok := r.Context().Value(SessionContextKey).(Session)
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

	sessionIDRaw, err := base64.URLEncoding.DecodeString(sessionCookie.Value)
	if err != nil {
		gs.logError("decode session cookie", err)
		http.SetCookie(w, gs.expireSessionCookie())
		return r
	}

	id, err := gs.identifierFromBytes(sessionIDRaw)
	if err != nil {
		gs.logError("parse session ID", err)
		http.SetCookie(w, gs.expireSessionCookie())
		return r
	}

	session, err := gs.store.GetSession(ctx, id)
	if err != nil {
		gs.logError("get session", err)
		http.SetCookie(w, gs.expireSessionCookie())
		return r
	}

	if session.ExpireAt().Before(gs.now().UTC()) {
		gs.logError("session expired", ErrSessionExpired)
		http.SetCookie(w, gs.expireSessionCookie())
		return r
	}

	return gs.newRequestWithSession(r, session)
}

func (gs *Gosesh) newRequestWithSession(r *http.Request, session Session) *http.Request {
	ctx := r.Context()
	ctx = context.WithValue(ctx, SessionContextKey, session)
	return r.WithContext(ctx)
}
