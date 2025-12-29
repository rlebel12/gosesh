package providers

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoogleUserRequest(t *testing.T) {
	var gotMethod, gotURL string
	google := &Google{
		Provider: Provider{
			doRequest: func(method, url string, header http.Header) (io.ReadCloser, error) {
				gotMethod = method
				gotURL = url
				return nil, nil
			},
		},
	}
	_, err := google.requestUser(t.Context(), "accessToken")
	require.NoError(t, err)
	assert.Equal(t, "GET", gotMethod)
	assert.Equal(t, "https://www.googleapis.com/oauth2/v2/userinfo?access_token=accessToken", gotURL)
}

func TestGoogleUserString(t *testing.T) {
	setup := setup(t)
	google := NewGoogle(setup.sesh, "clientID", "clientSecret", "/callback")
	user := google.NewUser()
	user.ID = "123"
	user.Email = "google@example.com"
	assert.Equal(t, "google@example.com", user.String())
}

// mockRoundTripper is a test helper for mocking HTTP responses
type mockRoundTripper struct {
	response   *http.Response
	err        error
	gotRequest *http.Request
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	m.gotRequest = req
	return m.response, m.err
}

// newMockClient creates an HTTP client with a mocked response
func newMockClient(statusCode int, body string) (*http.Client, *mockRoundTripper) {
	transport := &mockRoundTripper{
		response: &http.Response{
			StatusCode: statusCode,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		},
	}
	return &http.Client{Transport: transport}, transport
}

// Test data for Google tokeninfo responses
const (
	validResponse = `{
		"audience": "123456789.apps.googleusercontent.com",
		"user_id": "1234567890",
		"scope": "email profile",
		"expires_in": 3600
	}`

	invalidTokenResponse = `{
		"error": "invalid_token",
		"error_description": "Token has been expired or revoked."
	}`
)

func TestGoogleTokenInfoValidator(t *testing.T) {
	tests := []struct {
		name             string
		statusCode       int
		responseBody     string
		expectedAudience string
		expectError      bool
		errorContains    string
	}{
		{
			name:             "valid_token_returns_audience",
			statusCode:       200,
			responseBody:     validResponse,
			expectedAudience: "123456789.apps.googleusercontent.com",
			expectError:      false,
		},
		{
			name:          "invalid_token_400",
			statusCode:    400,
			responseBody:  invalidTokenResponse,
			expectError:   true,
			errorContains: "validate token",
		},
		{
			name:          "malformed_json",
			statusCode:    200,
			responseBody:  "not-json",
			expectError:   true,
			errorContains: "unmarshal",
		},
		{
			name:             "missing_audience_field",
			statusCode:       200,
			responseBody:     `{"email": "user@example.com"}`,
			expectedAudience: "",
			expectError:      false,
		},
		{
			name:             "empty_audience",
			statusCode:       200,
			responseBody:     `{"audience": ""}`,
			expectedAudience: "",
			expectError:      false,
		},
		{
			name:          "http_500_error",
			statusCode:    500,
			responseBody:  `{"error": "internal_error"}`,
			expectError:   true,
			errorContains: "validate token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := newMockClient(tt.statusCode, tt.responseBody)
			validator := NewGoogleTokenInfoValidator(client)

			audience, err := validator.ValidateAudience(t.Context(), "test-token")

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
				assert.Empty(t, audience)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedAudience, audience)
			}
		})
	}
}

func TestGoogleTokenInfoValidator_HTTPError(t *testing.T) {
	transport := &mockRoundTripper{
		err: errors.New("connection refused"),
	}
	client := &http.Client{Transport: transport}
	validator := NewGoogleTokenInfoValidator(client)

	audience, err := validator.ValidateAudience(t.Context(), "test-token")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "send request")
	assert.Empty(t, audience)
}

func TestGoogleTokenInfoValidator_ContextCancellation(t *testing.T) {
	// Create a transport that returns context.Canceled error
	transport := &mockRoundTripper{
		err: context.Canceled,
	}
	client := &http.Client{Transport: transport}
	validator := NewGoogleTokenInfoValidator(client)

	// Create a cancelled context
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	audience, err := validator.ValidateAudience(ctx, "test-token")

	require.Error(t, err)
	assert.Empty(t, audience)
	assert.Contains(t, err.Error(), "send request")
}

func TestGoogleTokenInfoValidator_ContextTimeout(t *testing.T) {
	// Create a transport that returns context.DeadlineExceeded error
	transport := &mockRoundTripper{
		err: context.DeadlineExceeded,
	}
	client := &http.Client{Transport: transport}
	validator := NewGoogleTokenInfoValidator(client)

	// Create a context with a very short timeout
	ctx, cancel := context.WithTimeout(t.Context(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(10 * time.Millisecond) // Ensure timeout expires

	audience, err := validator.ValidateAudience(ctx, "test-token")

	require.Error(t, err)
	assert.Empty(t, audience)
	assert.Contains(t, err.Error(), "send request")
}

func TestGoogleTokenInfoValidator_RequestURLConstruction(t *testing.T) {
	client, transport := newMockClient(200, validResponse)
	validator := NewGoogleTokenInfoValidator(client)

	_, err := validator.ValidateAudience(t.Context(), "test-access-token")
	require.NoError(t, err)

	require.NotNil(t, transport.gotRequest)
	assert.Equal(t, "GET", transport.gotRequest.Method)
	assert.Equal(t, "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=test-access-token", transport.gotRequest.URL.String())
}

func TestGoogleTokenInfoValidator_NilClientUsesDefault(t *testing.T) {
	validator := NewGoogleTokenInfoValidator(nil)
	require.NotNil(t, validator)
	// We can't easily test that it uses http.DefaultClient without making a real HTTP call,
	// but we can verify the validator was created successfully
}

func TestGoogleTokenInfoValidator_SpecialCharactersInToken(t *testing.T) {
	client, transport := newMockClient(200, validResponse)
	validator := NewGoogleTokenInfoValidator(client)

	tokenWithSpecialChars := "token+with/special=chars&more"
	_, err := validator.ValidateAudience(t.Context(), tokenWithSpecialChars)
	require.NoError(t, err)

	require.NotNil(t, transport.gotRequest)
	// Verify the token was properly URL encoded in the query string
	assert.Equal(t, tokenWithSpecialChars, transport.gotRequest.URL.Query().Get("access_token"))
}

func TestGoogleTokenInfoValidator_VeryLongToken(t *testing.T) {
	client, _ := newMockClient(200, validResponse)
	validator := NewGoogleTokenInfoValidator(client)

	// Create a very long token (typical JWT tokens can be 1000+ characters)
	longToken := strings.Repeat("a", 2000)
	_, err := validator.ValidateAudience(t.Context(), longToken)
	require.NoError(t, err)
}

func TestGoogleTokenInfoValidator_ResponseWithExtraFields(t *testing.T) {
	client, _ := newMockClient(200, `{
		"audience": "client-id.apps.googleusercontent.com",
		"user_id": "12345",
		"email": "user@example.com",
		"verified_email": true,
		"scope": "email profile",
		"expires_in": 3600,
		"extra_field": "should be ignored"
	}`)
	validator := NewGoogleTokenInfoValidator(client)

	audience, err := validator.ValidateAudience(t.Context(), "test-token")
	require.NoError(t, err)
	assert.Equal(t, "client-id.apps.googleusercontent.com", audience)
}
