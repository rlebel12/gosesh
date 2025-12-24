package gosesh

import (
	"encoding/base64"
	"net/http"
	"time"
)

// CookieCredentialSource reads and writes session IDs via HTTP cookies.
// It uses base64-encoded session IDs and follows browser security best practices
// with HttpOnly, Secure, and SameSite cookie attributes.
type CookieCredentialSource struct {
	cookieName    string
	domain        string
	secure        bool
	sessionConfig SessionConfig
}

// CookieSourceOption configures a CookieCredentialSource.
type CookieSourceOption func(*CookieCredentialSource)

// NewCookieCredentialSource creates a new cookie-based credential source with default settings.
// Defaults:
// - Cookie name: "session"
// - Domain: "" (current domain only)
// - Secure: true (requires HTTPS)
// - Session config: DefaultBrowserSessionConfig() (30min idle, 24h absolute, refresh enabled)
func NewCookieCredentialSource(opts ...CookieSourceOption) *CookieCredentialSource {
	source := &CookieCredentialSource{
		cookieName:    "session",
		domain:        "",
		secure:        true,
		sessionConfig: DefaultBrowserSessionConfig(),
	}

	for _, opt := range opts {
		opt(source)
	}

	return source
}

// WithCookieSourceName sets the name of the session cookie.
func WithCookieSourceName(name string) CookieSourceOption {
	return func(c *CookieCredentialSource) {
		c.cookieName = name
	}
}

// WithCookieSourceDomain sets the domain attribute of the session cookie.
// Use a leading dot (e.g., ".example.com") to allow the cookie across subdomains.
func WithCookieSourceDomain(domain string) CookieSourceOption {
	return func(c *CookieCredentialSource) {
		c.domain = domain
	}
}

// WithCookieSourceSecure sets whether the cookie requires HTTPS.
// Set to false for development on HTTP, but should be true in production.
func WithCookieSourceSecure(secure bool) CookieSourceOption {
	return func(c *CookieCredentialSource) {
		c.secure = secure
	}
}

// WithCookieSourceSessionConfig sets the session timeout configuration.
func WithCookieSourceSessionConfig(cfg SessionConfig) CookieSourceOption {
	return func(c *CookieCredentialSource) {
		c.sessionConfig = cfg
	}
}

// Name returns "cookie" to identify this credential source type.
func (c *CookieCredentialSource) Name() string {
	return "cookie"
}

// ReadSessionID extracts the session ID from the request's session cookie.
// Returns empty string if:
// - The cookie is not present
// - The cookie value is empty
// - The cookie value is not valid base64
func (c *CookieCredentialSource) ReadSessionID(r *http.Request) string {
	cookie, err := r.Cookie(c.cookieName)
	if err != nil {
		// Cookie not found
		return ""
	}

	if cookie.Value == "" {
		return ""
	}

	// Decode base64-encoded session ID
	decoded, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		// Invalid base64, return empty
		return ""
	}

	return string(decoded)
}

// WriteSession writes the session ID to a cookie in the response.
// The cookie is:
// - HttpOnly: prevents JavaScript access (XSS protection)
// - Secure: requires HTTPS (if configured)
// - SameSite=Lax: CSRF protection while allowing top-level navigation
// - Path=/: available site-wide
// - Expires: set to the session's absolute deadline
func (c *CookieCredentialSource) WriteSession(w http.ResponseWriter, session Session) error {
	// Base64 encode the session ID
	encodedID := base64.URLEncoding.EncodeToString([]byte(session.ID().String()))

	cookie := &http.Cookie{
		Name:     c.cookieName,
		Value:    encodedID,
		Path:     "/",
		Domain:   c.domain,
		Expires:  session.AbsoluteDeadline(),
		HttpOnly: true,
		Secure:   c.secure,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, cookie)

	// Set security headers for cookie handling
	setSecureCookieHeaders(w)

	return nil
}

// ClearSession removes the session cookie by setting it to expire immediately.
// This is done by setting MaxAge=-1 and Expires to a past time.
func (c *CookieCredentialSource) ClearSession(w http.ResponseWriter) error {
	cookie := &http.Cookie{
		Name:     c.cookieName,
		Value:    "",
		Path:     "/",
		Domain:   c.domain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   c.secure,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, cookie)

	return nil
}

// CanWrite returns true because cookies can be written to responses.
func (c *CookieCredentialSource) CanWrite() bool {
	return true
}

// SessionConfig returns the session timeout configuration for this source.
func (c *CookieCredentialSource) SessionConfig() SessionConfig {
	return c.sessionConfig
}
