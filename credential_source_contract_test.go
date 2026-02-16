package gosesh

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type CredentialSourceContract struct {
	Name                string
	NewSource           func() CredentialSource
	RequestFromResponse func(w *httptest.ResponseRecorder) *http.Request
}

func (c CredentialSourceContract) Test(t *testing.T) {
	t.Run("name_not_empty", func(t *testing.T) {
		source := c.NewSource()
		assert.NotEmpty(t, source.Name(), "Name() should return non-empty identifier")
	})

	t.Run("read_empty_request", func(t *testing.T) {
		source := c.NewSource()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		sessionID := source.ReadSessionID(req)
		assert.Empty(t, sessionID, "ReadSessionID() should return empty RawSessionID for request with no credentials")
	})

	t.Run("read_returns_consistent", func(t *testing.T) {
		source := c.NewSource()
		// Create a request that might have credentials
		req := httptest.NewRequest(http.MethodGet, "/", nil)

		// Read twice
		sessionID1 := source.ReadSessionID(req)
		sessionID2 := source.ReadSessionID(req)

		assert.Equal(t, sessionID1, sessionID2, "ReadSessionID() should return same value for same request")
	})

	t.Run("session_config_valid", func(t *testing.T) {
		source := c.NewSource()
		config := source.SessionConfig()
		assert.Greater(t, config.AbsoluteDuration, int64(0), "SessionConfig() must have non-zero AbsoluteDuration")
	})

	// Test write/clear round-trip for writable sources
	if c.RequestFromResponse != nil {
		t.Run("write_then_read", func(t *testing.T) {
			source := c.NewSource()
			if !source.CanWrite() {
				t.Skip("Source cannot write, skipping write_then_read test")
			}

			// Create a fake session
			rawID := RawSessionID("test-raw-session-id")
			hashedID := HashedSessionID("test-hashed-session-id")
			userID := StringIdentifier("test-user-id")
			now := time.Now()
			config := source.SessionConfig()
			session := NewFakeSession(
				hashedID,
				userID,
				now.Add(config.IdleDuration),
				now.Add(config.AbsoluteDuration),
				now,
			)

			// Write session to response
			w := httptest.NewRecorder()
			err := source.WriteSession(w, rawID, session)
			require.NoError(t, err, "WriteSession() should not return error")

			// Create request from response
			req := c.RequestFromResponse(w)

			// Read session ID back
			readSessionID := source.ReadSessionID(req)
			assert.Equal(t, rawID, readSessionID, "ReadSessionID() should return written raw session ID")
		})

		t.Run("clear_then_read", func(t *testing.T) {
			source := c.NewSource()
			if !source.CanWrite() {
				t.Skip("Source cannot write, skipping clear_then_read test")
			}

			// Clear session
			w := httptest.NewRecorder()
			err := source.ClearSession(w)
			require.NoError(t, err, "ClearSession() should not return error")

			// Create request from response
			req := c.RequestFromResponse(w)

			// Read session ID - should be empty
			readSessionID := source.ReadSessionID(req)
			assert.Empty(t, readSessionID, "ReadSessionID() should return empty RawSessionID after ClearSession()")
		})
	}

	// Test non-writable source behavior
	t.Run("can_write_false_noop", func(t *testing.T) {
		source := c.NewSource()
		if source.CanWrite() {
			t.Skip("Source can write, skipping can_write_false_noop test")
		}

		// Create a fake session
		rawID := RawSessionID("test-raw-session-id")
		hashedID := HashedSessionID("test-hashed-session-id")
		userID := StringIdentifier("test-user-id")
		now := time.Now()
		config := source.SessionConfig()
		session := NewFakeSession(
			hashedID,
			userID,
			now.Add(config.IdleDuration),
			now.Add(config.AbsoluteDuration),
			now,
		)

		// WriteSession should be no-op, no error
		w := httptest.NewRecorder()
		err := source.WriteSession(w, rawID, session)
		assert.NoError(t, err, "WriteSession() on non-writable source should be no-op without error")

		// ClearSession should also be no-op, no error
		err = source.ClearSession(w)
		assert.NoError(t, err, "ClearSession() on non-writable source should be no-op without error")
	})
}
