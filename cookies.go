package gosesh

import (
	"encoding/base64"
	"net/http"
	"time"
)

func (gs *Gosesh) oauthStateCookie(value string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     gs.oAuth2StateCookieName,
		Value:    value,
		Domain:   gs.CookieDomain(),
		Path:     "/",
		Expires:  expires,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Secure:   gs.origin.Scheme == "https",
	}
}

func (gs *Gosesh) sessionCookie(identifier Identifier, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     gs.sessionCookieName,
		Value:    base64.URLEncoding.EncodeToString([]byte(identifier.String())),
		Domain:   gs.CookieDomain(),
		Path:     "/",
		Expires:  expires,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Secure:   gs.origin.Scheme == "https",
	}
}

func (gs *Gosesh) redirectCookie(path string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     gs.redirectCookieName,
		Value:    base64.URLEncoding.EncodeToString([]byte(path)),
		Domain:   gs.CookieDomain(),
		Path:     "/",
		Expires:  expires,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Secure:   gs.origin.Scheme == "https",
	}
}

func (gs *Gosesh) setRedirectCookie(path string, w http.ResponseWriter) {
	redirectCookie := gs.redirectCookie(path, gs.now().Add(5*time.Minute))
	http.SetCookie(w, redirectCookie)
}

type emptyIdentifier struct{}

func (emptyIdentifier) String() string {
	return ""
}

func (gs *Gosesh) expireSessionCookie() *http.Cookie {
	cookie := gs.sessionCookie(emptyIdentifier{}, gs.now().UTC())
	return cookie
}

func setSecureCookieHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", `private, no-cache="Set-Cookie"`)
	w.Header().Set("Vary", "Cookie")
}
