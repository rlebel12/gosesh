package gosesh

import (
	"encoding/base64"
	"net/http"
	"time"
)

// setSecureCookieHeaders sets secure cookie headers for all cookies.
func setSecureCookieHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", `private, no-cache="Set-Cookie"`)
	w.Header().Set("Vary", "Cookie")
}

// sessionCookie creates a secure session cookie with the given session ID and expiration.
func (gs *Gosesh) sessionCookie(sessionID Identifier, expireAt time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     gs.sessionCookieName,
		Value:    base64.URLEncoding.EncodeToString([]byte(sessionID.String())),
		Path:     "/",
		Domain:   gs.CookieDomain(),
		Expires:  expireAt,
		Secure:   gs.Scheme() == "https",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// expireSessionCookie creates a cookie that expires the session cookie.
func (gs *Gosesh) expireSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     gs.sessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		Secure:   gs.Scheme() == "https",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// oauthStateCookie creates a secure OAuth2 state cookie with the given state and expiration.
func (gs *Gosesh) oauthStateCookie(state string, expireAt time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     gs.oAuth2StateCookieName,
		Value:    state,
		Path:     "/",
		Domain:   gs.CookieDomain(),
		Expires:  expireAt,
		Secure:   gs.Scheme() == "https",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// redirectCookie creates a secure redirect cookie with the given path and expiration.
func (gs *Gosesh) redirectCookie(path string, expireAt time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     gs.redirectCookieName,
		Value:    base64.URLEncoding.EncodeToString([]byte(path)),
		Path:     "/",
		Domain:   gs.CookieDomain(),
		Expires:  expireAt,
		Secure:   gs.Scheme() == "https",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// setRedirectCookie sets a redirect cookie with the given path.
func (gs *Gosesh) setRedirectCookie(path string, w http.ResponseWriter) {
	expireAt := gs.now().UTC().Add(5 * time.Minute)
	cookie := gs.redirectCookie(path, expireAt)
	http.SetCookie(w, cookie)
}
