package gosesh

import (
	"context"
	"net/http"
	"time"
)

type contextKey string

const (
	SessionContextKey contextKey = "session"
)

func (gs *Gosesh) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = gs.authenticate(r)
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

		now := time.Now().UTC()
		if session.IdleAt.After(now) {
			next.ServeHTTP(w, r)
			return
		}

		ctx := r.Context()
		session, err := gs.Store.UpdateSession(ctx, session.ID, UpdateSessionValues{
			IdleAt:   now.Add(gs.Config.SessionActiveDuration),
			ExpireAt: now.Add(gs.Config.SessionIdleDuration),
		})
		if err != nil {
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

func (gs *Gosesh) authenticate(r *http.Request) *http.Request {
	_, ok := CurrentSession(r)
	if ok {
		return r
	}

	ctx := r.Context()

	id, err := gs.parseIdentifierFromCookie(r)
	if err != nil {
		return r
	}

	session, err := gs.Store.GetSession(ctx, id)
	if err != nil {
		return r
	}

	if session.ExpireAt.Before(time.Now().UTC()) {
		return r
	}

	ctx = context.WithValue(ctx, SessionContextKey, session)
	return r.WithContext(ctx)
}
