package gosesh

import (
	"net/http"
	"strings"
)

// HeaderCredentialSource reads session IDs from HTTP headers (typically Authorization).
// This source is read-only - clients are responsible for storing and sending tokens
// in their requests. WriteSession and ClearSession are no-ops.
//
// By default, it reads from the "Authorization" header expecting "Bearer <token>" format
// per RFC 7235. The scheme comparison is case-insensitive.
//
// Tokens are attempted to be decoded as base64 for compatibility with cookie-based
// tokens, but if the token is not valid base64, it is used as-is.
type HeaderCredentialSource struct {
	headerName    string
	scheme        string
	sessionConfig SessionConfig
}

// HeaderSourceOption configures a HeaderCredentialSource.
type HeaderSourceOption func(*HeaderCredentialSource)

// WithHeaderName sets the header to read the session ID from.
// Default is "Authorization".
func WithHeaderName(name string) HeaderSourceOption {
	return func(h *HeaderCredentialSource) {
		h.headerName = name
	}
}

// WithHeaderScheme sets the authentication scheme to expect in the header.
// Default is "Bearer". Scheme comparison is case-insensitive per RFC 7235.
func WithHeaderScheme(scheme string) HeaderSourceOption {
	return func(h *HeaderCredentialSource) {
		h.scheme = scheme
	}
}

// WithHeaderSessionConfig sets the session configuration for header-based sessions.
// Default is DefaultNativeAppSessionConfig() (no idle timeout, 30 day absolute, no refresh).
func WithHeaderSessionConfig(cfg SessionConfig) HeaderSourceOption {
	return func(h *HeaderCredentialSource) {
		h.sessionConfig = cfg
	}
}

// NewHeaderCredentialSource creates a new header-based credential source.
// By default, it reads from the "Authorization" header expecting "Bearer <token>" format.
func NewHeaderCredentialSource(opts ...HeaderSourceOption) *HeaderCredentialSource {
	h := &HeaderCredentialSource{
		headerName:    "Authorization",
		scheme:        "Bearer",
		sessionConfig: DefaultNativeAppSessionConfig(),
	}

	for _, opt := range opts {
		opt(h)
	}

	return h
}

// Name returns "header" as the identifier for this credential source.
func (h *HeaderCredentialSource) Name() string {
	return "header"
}

// ReadSessionID extracts the session ID from the configured header.
// It expects the format: "<scheme> <token>"
//
// The scheme is compared case-insensitively per RFC 7235.
// The token is used as-is (no encoding/decoding).
//
// Returns empty RawSessionID if:
// - Header is not present
// - Scheme doesn't match
// - Token is missing or empty after the scheme
func (h *HeaderCredentialSource) ReadSessionID(r *http.Request) RawSessionID {
	headerValue := r.Header.Get(h.headerName)
	if headerValue == "" {
		return ""
	}

	// Split on first space: "<scheme> <token>"
	parts := strings.SplitN(headerValue, " ", 2)
	if len(parts) != 2 {
		return ""
	}

	scheme := parts[0]
	token := strings.TrimSpace(parts[1])

	// Compare scheme case-insensitively per RFC 7235
	if !strings.EqualFold(scheme, h.scheme) {
		return ""
	}

	return RawSessionID(token)
}

// WriteSession is a no-op for header-based credentials.
// The server cannot write headers to the client - clients are responsible
// for storing and sending tokens in their requests.
func (h *HeaderCredentialSource) WriteSession(w http.ResponseWriter, rawID RawSessionID, session Session) error {
	// No-op: headers cannot be written by server
	return nil
}

// ClearSession is a no-op for header-based credentials.
// The server cannot clear headers on the client side.
func (h *HeaderCredentialSource) ClearSession(w http.ResponseWriter) error {
	// No-op: headers cannot be cleared by server
	return nil
}

// CanWrite returns false because the server cannot write headers to clients.
// Clients must store and send tokens themselves.
func (h *HeaderCredentialSource) CanWrite() bool {
	return false
}

// SessionConfig returns the session configuration for header-based sessions.
func (h *HeaderCredentialSource) SessionConfig() SessionConfig {
	return h.sessionConfig
}
