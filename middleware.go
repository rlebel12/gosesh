package gosesh

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

const (
	SessionContextKey   = "session"
	CallbackRedirectKey = "successRedirect"
	LogoutRedirectKey   = "logoutRedirect"
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
	session, ok := CurrentSession(r)
	if ok {
		return r
	}

	ctx := r.Context()

	sessionID, err := gs.sessionIDFromCookie(w, r)
	if err != nil {
		return r
	}

	session, err = gs.Store.GetSession(ctx, sessionID)
	if err != nil {
		return r
	}

	if session.ExpireAt.Before(time.Now().UTC()) {
		return r
	}

	ctx = context.WithValue(ctx, SessionContextKey, session)
	return r.WithContext(ctx)
}

func (gs *Gosesh) CallbackRedirect(url *url.URL) func(http.Handler) http.Handler {
	return redirect(url, CallbackRedirectKey)
}

func (gs *Gosesh) LogoutRedirect(url *url.URL) func(http.Handler) http.Handler {
	return redirect(url, LogoutRedirectKey)
}

func redirect(url *url.URL, key string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), key, url)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type ResponseWriter interface {
	http.ResponseWriter
	Status() int
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (w *responseWriter) WriteHeader(s int) {
	w.status = s
	w.ResponseWriter.WriteHeader(s)
}

func (w *responseWriter) Status() int {
	return w.status
}

func NewResponseWriter(w http.ResponseWriter) ResponseWriter {
	nrw := &responseWriter{
		ResponseWriter: w,
	}
	return nrw
}
