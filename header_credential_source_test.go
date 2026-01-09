package gosesh

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHeaderCredentialSource_Name(t *testing.T) {
	source := NewHeaderCredentialSource()
	assert.Equal(t, "header", source.Name())
}

func TestHeaderCredentialSource_CanWrite(t *testing.T) {
	source := NewHeaderCredentialSource()
	assert.False(t, source.CanWrite(), "CanWrite should return false - headers not writable by server")
}

func TestHeaderCredentialSource_SessionConfigDefaults(t *testing.T) {
	source := NewHeaderCredentialSource()
	config := source.SessionConfig()

	// Native app defaults: no idle timeout, 30 day absolute
	assert.Equal(t, time.Duration(0), config.IdleDuration, "Default should have no idle timeout")
	assert.Equal(t, 30*24*time.Hour, config.AbsoluteDuration, "Default should have 30 day absolute duration")
	assert.False(t, config.RefreshEnabled, "Default should have refresh disabled")
}

func TestHeaderCredentialSource_ReadSessionID(t *testing.T) {
	tests := []struct {
		name              string
		authHeader        string
		expectedSessionID string
	}{
		{
			name:              "read_missing_header",
			authHeader:        "",
			expectedSessionID: "",
		},
		{
			name:              "read_valid_bearer",
			authHeader:        "Bearer abc123",
			expectedSessionID: "abc123",
		},
		{
			name:              "read_bearer_base64",
			authHeader:        "Bearer " + base64.StdEncoding.EncodeToString([]byte("user123")),
			expectedSessionID: "user123",
		},
		{
			name:              "read_wrong_scheme",
			authHeader:        "Basic xxx",
			expectedSessionID: "",
		},
		{
			name:              "read_malformed_no_token",
			authHeader:        "Bearer ",
			expectedSessionID: "",
		},
		{
			name:              "read_malformed_no_space",
			authHeader:        "Bearerabc123",
			expectedSessionID: "",
		},
		{
			name:              "read_case_insensitive",
			authHeader:        "bearer abc123",
			expectedSessionID: "abc123",
		},
		{
			name:              "read_BEARER_caps",
			authHeader:        "BEARER abc123",
			expectedSessionID: "abc123",
		},
		{
			name:              "read_extra_whitespace",
			authHeader:        "Bearer   abc123  ",
			expectedSessionID: "abc123",
		},
		{
			name:              "read_token_with_special_chars",
			authHeader:        "Bearer abc-123_xyz.token",
			expectedSessionID: "abc-123_xyz.token",
		},
		{
			name:              "read_non_base64_token",
			authHeader:        "Bearer not-valid-base64!",
			expectedSessionID: "not-valid-base64!",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := NewHeaderCredentialSource()
			req := httptest.NewRequest(http.MethodGet, "/", nil)

			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			sessionID := source.ReadSessionID(req)
			assert.Equal(t, tt.expectedSessionID, sessionID)
		})
	}
}

func TestHeaderCredentialSource_WriteSession_NoOp(t *testing.T) {
	source := NewHeaderCredentialSource()

	sessionID := StringIdentifier("test-session-id")
	userID := StringIdentifier("test-user-id")
	now := time.Now()
	config := source.SessionConfig()
	session := NewFakeSession(
		sessionID,
		userID,
		now.Add(config.IdleDuration),
		now.Add(config.AbsoluteDuration),
		now,
	)

	w := httptest.NewRecorder()
	initialHeaders := w.Header().Clone()

	err := source.WriteSession(w, session)

	require.NoError(t, err, "WriteSession should not return error")
	assert.Equal(t, initialHeaders, w.Header(), "WriteSession should not modify response headers")
}

func TestHeaderCredentialSource_ClearSession_NoOp(t *testing.T) {
	source := NewHeaderCredentialSource()

	w := httptest.NewRecorder()
	initialHeaders := w.Header().Clone()

	err := source.ClearSession(w)

	require.NoError(t, err, "ClearSession should not return error")
	assert.Equal(t, initialHeaders, w.Header(), "ClearSession should not modify response headers")
}

func TestHeaderCredentialSource_CustomOptions(t *testing.T) {
	tests := []struct {
		name              string
		option            HeaderSourceOption
		headerName        string
		headerValue       string
		expectedSessionID string
	}{
		{
			name:              "WithHeaderName",
			option:            WithHeaderName("X-Session-ID"),
			headerName:        "X-Session-ID",
			headerValue:       "Bearer abc123",
			expectedSessionID: "abc123",
		},
		{
			name:              "WithHeaderScheme",
			option:            WithHeaderScheme("Token"),
			headerName:        "Authorization",
			headerValue:       "Token abc123",
			expectedSessionID: "abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := NewHeaderCredentialSource(tt.option)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(tt.headerName, tt.headerValue)

			sessionID := source.ReadSessionID(req)
			assert.Equal(t, tt.expectedSessionID, sessionID)
		})
	}
}

func TestHeaderCredentialSource_WithHeaderSessionConfig(t *testing.T) {
	customConfig := SessionConfig{
		IdleDuration:     10 * time.Minute,
		AbsoluteDuration: 7 * 24 * time.Hour,
		RefreshEnabled:   true,
	}

	source := NewHeaderCredentialSource(WithHeaderSessionConfig(customConfig))
	config := source.SessionConfig()

	assert.Equal(t, customConfig.IdleDuration, config.IdleDuration)
	assert.Equal(t, customConfig.AbsoluteDuration, config.AbsoluteDuration)
	assert.Equal(t, customConfig.RefreshEnabled, config.RefreshEnabled)
}

// TestHeaderCredentialSourceContract verifies HeaderCredentialSource
// satisfies the CredentialSource contract
func TestHeaderCredentialSourceContract(t *testing.T) {
	CredentialSourceContract{
		Name: "HeaderCredentialSource",
		NewSource: func() CredentialSource {
			return NewHeaderCredentialSource()
		},
		RequestFromResponse: nil, // Headers are not writable, so no round-trip test
	}.Test(t)
}
