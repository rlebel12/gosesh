package gosesh

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/google/uuid"
)

const (
	defaultAuthSessionCookieName = "session"
	defaultOAuthStateCookieName  = "oauthstate"
)

func (gs *Gosesh) OauthStateCookie(value string, expires time.Time) http.Cookie {
	return http.Cookie{
		Name:     gs.Config.OAuthStateCookieName,
		Value:    value,
		Domain:   gs.Config.Origin.Hostname(),
		Path:     "/",
		Expires:  expires,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Secure:   gs.Config.Origin.Scheme == "https",
	}
}

func (gs *Gosesh) SessionCookie(sessionID uuid.UUID, expires time.Time) http.Cookie {
	return http.Cookie{
		Name:     gs.Config.AuthSessionCookieName,
		Value:    base64.URLEncoding.EncodeToString([]byte(sessionID.String())),
		Domain:   gs.Config.Origin.Hostname(),
		Path:     "/",
		Expires:  expires,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Secure:   gs.Config.Origin.Scheme == "https",
	}
}

func (gs *Gosesh) ExpireSessionCookie() http.Cookie {
	return gs.SessionCookie(uuid.UUID{}, time.Now().UTC())
}

func (gs *Gosesh) sessionIDFromCookie(w http.ResponseWriter, r *http.Request) (uuid.UUID, error) {
	sessionCookie, err := r.Cookie(gs.Config.AuthSessionCookieName)
	if err != nil {
		return uuid.UUID{}, err
	}

	sessionIDRaw, err := base64.URLEncoding.DecodeString(sessionCookie.Value)
	if err != nil {
		return uuid.UUID{}, err
	}

	return uuid.ParseBytes([]byte(sessionIDRaw))
}
