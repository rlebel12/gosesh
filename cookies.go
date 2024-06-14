package gosesh

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

func (gs *Gosesh) oauthStateCookie(value string, expires time.Time) http.Cookie {
	return http.Cookie{
		Name:     gs.oAuth2StateCookieName,
		Value:    value,
		Domain:   gs.origin.Hostname(),
		Path:     "/",
		Expires:  expires,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Secure:   gs.origin.Scheme == "https",
	}
}

func (gs *Gosesh) sessionCookie(identifier Identifier, expires time.Time) http.Cookie {
	return http.Cookie{
		Name:     gs.sessionCookieName,
		Value:    base64.URLEncoding.EncodeToString([]byte(identifier.String())),
		Domain:   gs.origin.Hostname(),
		Path:     "/",
		Expires:  expires,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Secure:   gs.origin.Scheme == "https",
	}
}

type emptyIdentifier struct{}

func (emptyIdentifier) String() string {
	return ""
}

func (gs *Gosesh) expireSessionCookie() *http.Cookie {
	cookie := gs.sessionCookie(emptyIdentifier{}, gs.now().UTC())
	return &cookie
}

func (gs *Gosesh) parseIdentifierFromCookie(r *http.Request) (Identifier, error) {
	sessionCookie, err := r.Cookie(gs.sessionCookieName)
	if err != nil {
		return nil, fmt.Errorf("failed to get session cookie: %w", err)
	}

	sessionIDRaw, err := base64.URLEncoding.DecodeString(sessionCookie.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to decode session cookie: %w", err)
	}

	return gs.idParser.ParseBytes(sessionIDRaw)
}
