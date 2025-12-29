package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const (
	googleTokenInfoURL = "https://www.googleapis.com/oauth2/v1/tokeninfo"
	// maxResponseBodySize limits the response body to prevent memory issues with malformed responses.
	// Google's tokeninfo responses are typically < 1KB; 1MB is a safe upper limit.
	maxResponseBodySize = 1 << 20 // 1MB
)

// GoogleTokenInfoValidator validates Google OAuth tokens using the tokeninfo endpoint.
type GoogleTokenInfoValidator struct {
	client *http.Client
}

// NewGoogleTokenInfoValidator creates a validator for Google access tokens.
// If client is nil, http.DefaultClient will be used.
func NewGoogleTokenInfoValidator(client *http.Client) *GoogleTokenInfoValidator {
	if client == nil {
		client = http.DefaultClient
	}
	return &GoogleTokenInfoValidator{client: client}
}

// tokenInfoResponse represents the JSON response from Google's tokeninfo endpoint.
// Only fields we need are defined; extra fields are ignored by json.Unmarshal.
type tokenInfoResponse struct {
	Audience string `json:"audience"`
	Error    string `json:"error,omitempty"`
}

// ValidateAudience calls Google's tokeninfo endpoint to get the token's audience.
func (v *GoogleTokenInfoValidator) ValidateAudience(ctx context.Context, accessToken string) (string, error) {
	// Build URL using url.URL for proper query parameter handling
	u, err := url.Parse(googleTokenInfoURL)
	if err != nil {
		return "", fmt.Errorf("parse url: %w", err)
	}
	q := u.Query()
	q.Set("access_token", accessToken)
	u.RawQuery = q.Encode()

	// Create request with context for cancellation/timeout
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	// Execute request
	resp, err := v.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	// Read body with size limit to prevent memory exhaustion
	limitedReader := io.LimitReader(resp.Body, maxResponseBodySize)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	// Check status code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("validate token: %s", resp.Status)
	}

	// Parse JSON
	var tokenInfo tokenInfoResponse
	if err := json.Unmarshal(body, &tokenInfo); err != nil {
		return "", fmt.Errorf("unmarshal response: %w", err)
	}

	// Check for API-level error
	if tokenInfo.Error != "" {
		return "", fmt.Errorf("validate token: %s", tokenInfo.Error)
	}

	return tokenInfo.Audience, nil
}
