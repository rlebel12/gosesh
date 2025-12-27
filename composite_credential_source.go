package gosesh

import (
	"net/http"
)

// CompositeCredentialSource chains multiple credential sources together.
// It reads from sources in order, returning the first non-empty session ID.
// It writes/clears to all sources that support writing.
//
// This allows supporting multiple authentication methods simultaneously,
// such as cookies for browsers and headers for native app/API clients.
//
// Source ordering matters:
// - The first source that returns a non-empty session ID wins on read
// - The first source's SessionConfig is used for the composite
// - All writable sources receive write/clear operations
type CompositeCredentialSource struct {
	sources []CredentialSource
}

// NewCompositeCredentialSource creates a new composite credential source
// that chains the provided sources together.
//
// If no sources are provided, all operations are no-ops:
// - ReadSessionID returns ""
// - WriteSession and ClearSession succeed without doing anything
// - CanWrite returns false
// - SessionConfig returns a zero value
func NewCompositeCredentialSource(sources ...CredentialSource) *CompositeCredentialSource {
	return &CompositeCredentialSource{
		sources: sources,
	}
}

// Name returns "composite" to identify this credential source type.
func (c *CompositeCredentialSource) Name() string {
	return "composite"
}

// ReadSessionID reads the session ID from the first source that returns
// a non-empty value. Sources are checked in the order they were provided
// to NewCompositeCredentialSource.
//
// Returns empty string if:
// - No sources are configured
// - All sources return empty string
func (c *CompositeCredentialSource) ReadSessionID(r *http.Request) string {
	for _, source := range c.sources {
		sessionID := source.ReadSessionID(r)
		if sessionID != "" {
			return sessionID
		}
	}
	return ""
}

// WriteSession writes the session to all sources that support writing.
// Sources are processed in order, and the operation fails fast on the first error.
//
// Design rationale: Partial writes are worse than no writes. If we successfully
// write to source A but fail on source B, the client would have inconsistent state.
// By failing fast, we ensure either all writable sources succeed or none do.
//
// Returns nil if no sources support writing or all writes succeed.
func (c *CompositeCredentialSource) WriteSession(w http.ResponseWriter, session Session) error {
	for _, source := range c.sources {
		if source.CanWrite() {
			if err := source.WriteSession(w, session); err != nil {
				return err
			}
		}
	}
	return nil
}

// ClearSession clears the session from all sources that support writing.
// Sources are processed in order, and the operation fails fast on the first error.
//
// Design rationale: Same as WriteSession - partial clears are worse than no clears.
// We want consistent state across all sources.
//
// Returns nil if no sources support writing or all clears succeed.
func (c *CompositeCredentialSource) ClearSession(w http.ResponseWriter) error {
	for _, source := range c.sources {
		if source.CanWrite() {
			if err := source.ClearSession(w); err != nil {
				return err
			}
		}
	}
	return nil
}

// CanWrite returns true if any configured source can write credentials.
// Returns false if no sources are configured or all sources are read-only.
func (c *CompositeCredentialSource) CanWrite() bool {
	for _, source := range c.sources {
		if source.CanWrite() {
			return true
		}
	}
	return false
}

// SessionConfig returns the session configuration from the first source.
// The first source is considered the "primary" source and determines the
// session timeout policy for the composite.
//
// Returns a zero SessionConfig if no sources are configured.
func (c *CompositeCredentialSource) SessionConfig() SessionConfig {
	if len(c.sources) == 0 {
		return SessionConfig{}
	}
	return c.sources[0].SessionConfig()
}
