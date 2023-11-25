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

		sessionCookieVal, err := r.Cookie(AuthSessionCookieName)
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

		session, err := i.Identifier.GetSession(ctx, sessionID)
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

		authCtx := context.WithValue(ctx, SessionContextKey, session)
		r = r.WithContext(authCtx)
		next.ServeHTTP(w, r)
	})
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
