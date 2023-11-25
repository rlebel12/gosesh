package identity

import (
	"context"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/google/uuid"
)

const (
	SessionContextKey = "session"
)

func (i *Identity) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		sessionCookieVal, err := r.Cookie(i.Config.AuthSessionCookieName)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		sessionIDRaw, err := base64.URLEncoding.DecodeString(sessionCookieVal.Value)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		sessionID, err := uuid.ParseBytes([]byte(sessionIDRaw))
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		session, err := i.Storer.GetSession(ctx, sessionID)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		if session.ExpireAt.Before(time.Now().UTC()) {
			next.ServeHTTP(w, r)
			return
		}

		if session.User == nil {
			next.ServeHTTP(w, r)
			return
		}

		ctx = context.WithValue(ctx, SessionContextKey, session)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func (i *Identity) AuthenticateAndRefresh(next http.Handler) http.Handler {
	return i.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		session, err := i.Storer.UpdateSession(ctx, session.ID, UpdateSessionValues{
			IdleAt:   now.Add(SessionActiveDuration),
			ExpireAt: now.Add(SessionIdleDuration),
		})
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		ctx = context.WithValue(ctx, SessionContextKey, session)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	}))
}

func (i *Identity) RequireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := CurrentSession(r)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func CurrentSession(r *http.Request) (Session, bool) {
	session, ok := r.Context().Value(SessionContextKey).(Session)
	return session, ok
}
