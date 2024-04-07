package gosesh

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

const (
	defaultAuthSessionCookieName = "session"
	defaultOAuthStateCookieName  = "oauthstate"
)

func (gs *Gosesh[T]) OauthStateCookie(value string, expires time.Time) http.Cookie {
	return http.Cookie{
		Name:     gs.Config.OAuth2StateCookieName,
		Value:    value,
		Domain:   gs.Config.Origin.Hostname(),
		Path:     "/",
		Expires:  expires,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Secure:   gs.Config.Origin.Scheme == "https",
	}
}

func (gs *Gosesh[T]) SessionCookie(identifier Identifier, expires time.Time) http.Cookie {
	return http.Cookie{
		Name:     gs.Config.SessionCookieName,
		Value:    base64.URLEncoding.EncodeToString([]byte(identifier.String())),
		Domain:   gs.Config.Origin.Hostname(),
		Path:     "/",
		Expires:  expires,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Secure:   gs.Config.Origin.Scheme == "https",
	}
}

type emptyIdentifier struct{}

func (emptyIdentifier) String() string {
	return ""
}

func (gs *Gosesh[T]) ExpireSessionCookie() http.Cookie {
	return gs.SessionCookie(emptyIdentifier{}, time.Now().UTC())
}

func (gs *Gosesh[T]) parseIdentifierFromCookie(w http.ResponseWriter, r *http.Request) (T, error) {
	sessionCookie, err := r.Cookie(gs.Config.SessionCookieName)
	if err != nil {
		var identifier T
		return identifier, fmt.Errorf("failed to get session cookie: %w", err)
	}

	sessionIDRaw, err := base64.URLEncoding.DecodeString(sessionCookie.Value)
	if err != nil {
		var identifier T
		return identifier, fmt.Errorf("failed to decode session cookie: %w", err)
	}

	return gs.IDParser(sessionIDRaw)
}
