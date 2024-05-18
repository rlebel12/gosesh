package gosesh

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

func (gs *Gosesh) OauthStateCookie(value string, expires time.Time) http.Cookie {
	return http.Cookie{
		Name:     gs.config.OAuth2StateCookieName,
		Value:    value,
		Domain:   gs.config.Origin.Hostname(),
		Path:     "/",
		Expires:  expires,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Secure:   gs.config.Origin.Scheme == "https",
	}
}

func (gs *Gosesh) SessionCookie(identifier Identifier, expires time.Time) http.Cookie {
	return http.Cookie{
		Name:     gs.config.SessionCookieName,
		Value:    base64.URLEncoding.EncodeToString([]byte(identifier.String())),
		Domain:   gs.config.Origin.Hostname(),
		Path:     "/",
		Expires:  expires,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Secure:   gs.config.Origin.Scheme == "https",
	}
}

type emptyIdentifier struct{}

func (emptyIdentifier) String() string {
	return ""
}

func (gs *Gosesh) ExpireSessionCookie() http.Cookie {
	return gs.SessionCookie(emptyIdentifier{}, time.Now().UTC())
}

func (gs *Gosesh) parseIdentifierFromCookie(r *http.Request) (Identifier, error) {
	sessionCookie, err := r.Cookie(gs.config.SessionCookieName)
	if err != nil {
		return nil, fmt.Errorf("failed to get session cookie: %w", err)
	}

	sessionIDRaw, err := base64.URLEncoding.DecodeString(sessionCookie.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to decode session cookie: %w", err)
	}

	return gs.idParser.Parse(sessionIDRaw)
}
