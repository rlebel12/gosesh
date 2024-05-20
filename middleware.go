package gosesh

import (
	"context"
	"net/http"
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
		if session.IdleAt.After(now) {
			next.ServeHTTP(w, r)
			return
		}

		ctx := r.Context()
		session, err := gs.store.UpdateSession(ctx, session.ID, UpdateSessionValues{
			IdleAt:   now.Add(gs.sessionActiveDuration),
			ExpireAt: now.Add(gs.sessionIdleDuration),
		})
		if err != nil {
			gs.logError("failed updating session: %s", err.Error())
			next.ServeHTTP(w, r)
			return
		}

		sessionCookie := gs.SessionCookie(session.ID, session.ExpireAt)
		http.SetCookie(w, &sessionCookie)

		ctx = context.WithValue(ctx, SessionContextKey, session)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	}))
}

func (gs *Gosesh) RequireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := CurrentSession(r)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func CurrentSession(r *http.Request) (*Session, bool) {
	session, ok := r.Context().Value(SessionContextKey).(*Session)
	return session, ok
}

func (gs *Gosesh) authenticate(w http.ResponseWriter, r *http.Request) *http.Request {
	_, ok := CurrentSession(r)
	if ok {
		return r
	}

	ctx := r.Context()

	id, err := gs.parseIdentifierFromCookie(r)
	if err != nil {
		http.SetCookie(w, gs.ExpireSessionCookie())
		return r
	}

	session, err := gs.store.GetSession(ctx, id)
	if err != nil {
		http.SetCookie(w, gs.ExpireSessionCookie())
		return r
	}

	if session.ExpireAt.Before(gs.now().UTC()) {
		http.SetCookie(w, gs.ExpireSessionCookie())
		return r
	}

	ctx = context.WithValue(ctx, SessionContextKey, session)
	return r.WithContext(ctx)
}
