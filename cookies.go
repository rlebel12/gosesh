package identity

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/google/uuid"
)

const (
	AuthSessionCookieName = "vel_session"
	OauthStateCookieName  = "vel_oauthstate"
)

func (i *Identity) OauthStateCookie(value string, expires time.Time) http.Cookie {
	return http.Cookie{
		Name:     OauthStateCookieName,
		Value:    value,
		Domain:   i.Config.Origin.Hostname(),
		Path:     "/",
		Expires:  expires,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Secure:   i.Config.Origin.Scheme == "https",
	}
}

func (i *Identity) SessionCookie(sessionID uuid.UUID, expires time.Time) http.Cookie {
	return http.Cookie{
		Name:     AuthSessionCookieName,
		Value:    base64.URLEncoding.EncodeToString([]byte(sessionID.String())),
		Domain:   i.Config.Origin.Hostname(),
		Path:     "/",
		Expires:  expires,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Secure:   i.Config.Origin.Scheme == "https",
	}
}
