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

// deviceCodeCookie creates a secure device code cookie with the given code and expiration.
func (gs *Gosesh) deviceCodeCookie(deviceCode string, expireAt time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     gs.deviceCodeCookieName,
		Value:    base64.URLEncoding.EncodeToString([]byte(deviceCode)),
		Path:     "/",
		Domain:   gs.CookieDomain(),
		Expires:  expireAt,
		Secure:   gs.Scheme() == "https",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// setDeviceCodeCookie sets a device code cookie with 5-minute expiration.
func (gs *Gosesh) setDeviceCodeCookie(deviceCode string, w http.ResponseWriter) {
	expireAt := gs.now().UTC().Add(5 * time.Minute)
	cookie := gs.deviceCodeCookie(deviceCode, expireAt)
	http.SetCookie(w, cookie)
}
