package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// CLIClient simulates a CLI application authenticating with the server.
// It supports both localhost callback flow and device code flow.
type CLIClient struct {
	BaseURL    string
	Token      string // stored session token
	HTTPClient *http.Client
}

// NewCLIClient creates a new CLI client that talks to the given base URL.
func NewCLIClient(baseURL string) *CLIClient {
	// Create cookie jar to maintain state cookies between requests
	jar, _ := cookiejar.New(nil)

	return &CLIClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
			Jar:     jar, // Maintain cookies for OAuth state
			// Don't follow redirects automatically for OAuth flow
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// AuthenticateViaLocalhost performs the localhost callback OAuth flow.
// This simulates a CLI tool that can open a browser and start a local server
// to receive the OAuth callback.
func (c *CLIClient) AuthenticateViaLocalhost(ctx context.Context) error {
	// Start local callback server on random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("start callback server: %w", err)
	}
	defer listener.Close()

	callbackAddr := listener.Addr().String()
	callbackURL := "http://" + callbackAddr + "/callback"

	// Channel to receive token from callback
	tokenCh := make(chan string, 1)
	errCh := make(chan error, 1)

	// Start callback server
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			errCh <- fmt.Errorf("no token in callback")
			http.Error(w, "No token received", http.StatusBadRequest)
			return
		}

		tokenCh <- token
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body><h1>Success!</h1><p>You can close this window.</p></body></html>"))
	})

	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Shutdown(ctx)

	// Build begin URL with callback parameter
	beginURL := fmt.Sprintf("%s/auth/cli/begin?callback=%s", c.BaseURL, url.QueryEscape(callbackURL))

	// Make request to begin endpoint (this will redirect to OAuth provider)
	req, err := http.NewRequestWithContext(ctx, "GET", beginURL, nil)
	if err != nil {
		return fmt.Errorf("create begin request: %w", err)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("begin request: %w", err)
	}
	defer resp.Body.Close()

	// Should redirect to OAuth provider
	if resp.StatusCode != http.StatusTemporaryRedirect && resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected begin response: %d: %s", resp.StatusCode, string(body))
	}

	// Manually update cookie jar with response cookies (since we're not following redirects)
	baseURL, _ := url.Parse(c.BaseURL)
	if cookies := resp.Cookies(); len(cookies) > 0 {
		c.HTTPClient.Jar.SetCookies(baseURL, cookies)
	}

	// Save cookies for later (includes state cookie)
	savedCookies := c.HTTPClient.Jar.Cookies(baseURL)

	// Follow redirect to OAuth provider (auto-approves in test)
	oauthURL := resp.Header.Get("Location")
	if oauthURL == "" {
		return fmt.Errorf("no redirect location in begin response")
	}

	// Follow OAuth redirect
	req, err = http.NewRequestWithContext(ctx, "GET", oauthURL, nil)
	if err != nil {
		return fmt.Errorf("create oauth request: %w", err)
	}

	resp, err = c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("oauth request: %w", err)
	}
	defer resp.Body.Close()

	// OAuth provider should redirect back to our app's callback
	if resp.StatusCode != http.StatusTemporaryRedirect && resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected oauth response: %d: %s", resp.StatusCode, string(body))
	}

	callbackRedirect := resp.Header.Get("Location")
	if callbackRedirect == "" {
		return fmt.Errorf("no redirect location in oauth response")
	}

	// Follow redirect to app callback (this processes the OAuth code)
	req, err = http.NewRequestWithContext(ctx, "GET", callbackRedirect, nil)
	if err != nil {
		return fmt.Errorf("create callback request: %w", err)
	}

	// Restore cookies from begin request (includes state cookie)
	for _, cookie := range savedCookies {
		req.AddCookie(cookie)
	}

	resp, err = c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("callback request: %w", err)
	}
	defer resp.Body.Close()

	// App callback should redirect to our local callback with token
	if resp.StatusCode != http.StatusTemporaryRedirect && resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected callback response: %d: %s", resp.StatusCode, string(body))
	}

	localCallbackURL := resp.Header.Get("Location")
	if localCallbackURL == "" {
		return fmt.Errorf("no redirect to local callback")
	}

	// Follow redirect to local callback
	req, err = http.NewRequestWithContext(ctx, "GET", localCallbackURL, nil)
	if err != nil {
		return fmt.Errorf("create local callback request: %w", err)
	}

	// Use default client for local callback (follows redirects)
	localClient := &http.Client{Timeout: 5 * time.Second}
	resp, err = localClient.Do(req)
	if err != nil {
		return fmt.Errorf("local callback request: %w", err)
	}
	resp.Body.Close()

	// Wait for token from callback server
	select {
	case token := <-tokenCh:
		c.Token = token
		return nil
	case err := <-errCh:
		return err
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout waiting for callback")
	}
}

// AuthenticateViaDeviceCode performs the device code OAuth flow.
// The authorizeFunc is called with the user code and should simulate
// the user authorizing the device via browser.
func (c *CLIClient) AuthenticateViaDeviceCode(ctx context.Context, authorizeFunc func(userCode string) error) error {
	// Step 1: Request device code
	beginURL := fmt.Sprintf("%s/auth/device/begin", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", beginURL, nil)
	if err != nil {
		return fmt.Errorf("create begin request: %w", err)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("begin request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("begin failed: %d: %s", resp.StatusCode, string(body))
	}

	var beginResp struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&beginResp); err != nil {
		return fmt.Errorf("decode begin response: %w", err)
	}

	// Step 2: Call authorize function (simulates user authorizing in browser)
	if err := authorizeFunc(beginResp.UserCode); err != nil {
		return fmt.Errorf("authorization failed: %w", err)
	}

	// Step 3: Poll for completion
	pollURL := fmt.Sprintf("%s/auth/device/poll", c.BaseURL)
	interval := time.Duration(beginResp.Interval) * time.Second
	timeout := time.Duration(beginResp.ExpiresIn) * time.Second
	deadline := time.Now().Add(timeout)

	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("device code expired")
		}

		// Wait interval before polling
		time.Sleep(interval)

		// Poll for status
		pollReq := map[string]string{
			"device_code": beginResp.DeviceCode,
		}
		pollBody, _ := json.Marshal(pollReq)

		req, err := http.NewRequestWithContext(ctx, "POST", pollURL, bytes.NewReader(pollBody))
		if err != nil {
			return fmt.Errorf("create poll request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			return fmt.Errorf("poll request: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			if resp.StatusCode == http.StatusTooManyRequests {
				// Rate limited - wait and try again
				continue
			}
			return fmt.Errorf("poll failed: %d", resp.StatusCode)
		}

		var pollResp struct {
			Status    string `json:"status"`
			SessionID string `json:"session_id"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&pollResp); err != nil {
			resp.Body.Close()
			return fmt.Errorf("decode poll response: %w", err)
		}
		resp.Body.Close()

		switch pollResp.Status {
		case "complete":
			c.Token = pollResp.SessionID
			return nil
		case "pending":
			// Continue polling
			continue
		case "expired":
			return fmt.Errorf("device code expired")
		default:
			return fmt.Errorf("unknown status: %s", pollResp.Status)
		}
	}
}

// Request makes an authenticated HTTP request using the stored token.
func (c *CLIClient) Request(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	url := c.BaseURL + path

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	if c.Token != "" {
		// Send token as Bearer token in Authorization header
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	return c.HTTPClient.Do(req)
}

// MeResponse represents the response from /api/me endpoint.
type MeResponse struct {
	UserID           string    `json:"user_id"`
	SessionID        string    `json:"session_id"`
	IdleDeadline     time.Time `json:"idle_deadline"`
	AbsoluteDeadline time.Time `json:"absolute_deadline"`
}

// GetMe calls /api/me to verify authentication and get session info.
func (c *CLIClient) GetMe(ctx context.Context) (*MeResponse, error) {
	resp, err := c.Request(ctx, "GET", "/api/me", nil)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var me MeResponse
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &me, nil
}

// RequestWithCookie makes an HTTP request with the token sent as a cookie instead of header.
// This simulates browser-based authentication.
func (c *CLIClient) RequestWithCookie(ctx context.Context, method, path, cookieName string) (*http.Response, error) {
	url := c.BaseURL + path

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	if c.Token != "" {
		// Send token as cookie
		cookie := &http.Cookie{
			Name:  cookieName,
			Value: c.Token,
		}
		req.AddCookie(cookie)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects
			return http.ErrUseLastResponse
		},
	}

	return client.Do(req)
}

// ExtractTokenFromSetCookie extracts a session token from Set-Cookie header.
func ExtractTokenFromSetCookie(resp *http.Response, cookieName string) string {
	for _, cookie := range resp.Cookies() {
		if cookie.Name == cookieName {
			return cookie.Value
		}
	}
	return ""
}

// BrowserAuthFlow simulates a browser OAuth flow and returns the session cookie.
// This is used for testing cookie-based authentication.
func (c *CLIClient) BrowserAuthFlow(ctx context.Context) error {
	// Step 1: Begin OAuth
	beginURL := fmt.Sprintf("%s/auth/login", c.BaseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", beginURL, nil)
	if err != nil {
		return fmt.Errorf("create begin request: %w", err)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("begin request: %w", err)
	}
	defer resp.Body.Close()

	// Should redirect to OAuth
	if resp.StatusCode != http.StatusTemporaryRedirect && resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected begin response: %d: %s", resp.StatusCode, string(body))
	}

	// Extract cookies (state cookie)
	var cookies []*http.Cookie
	for _, cookie := range resp.Cookies() {
		cookies = append(cookies, cookie)
	}

	// Follow OAuth redirect
	oauthURL := resp.Header.Get("Location")
	req, err = http.NewRequestWithContext(ctx, "GET", oauthURL, nil)
	if err != nil {
		return fmt.Errorf("create oauth request: %w", err)
	}

	resp, err = c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("oauth request: %w", err)
	}
	defer resp.Body.Close()

	// Should redirect to callback
	if resp.StatusCode != http.StatusTemporaryRedirect && resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected oauth response: %d: %s", resp.StatusCode, string(body))
	}

	callbackURL := resp.Header.Get("Location")
	req, err = http.NewRequestWithContext(ctx, "GET", callbackURL, nil)
	if err != nil {
		return fmt.Errorf("create callback request: %w", err)
	}

	// Add state cookie
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	resp, err = c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("callback request: %w", err)
	}
	defer resp.Body.Close()

	// Should set session cookie and redirect
	if resp.StatusCode != http.StatusTemporaryRedirect && resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected callback response: %d: %s", resp.StatusCode, string(body))
	}

	// Extract session cookie
	sessionCookie := ExtractTokenFromSetCookie(resp, "session")
	if sessionCookie == "" {
		return fmt.Errorf("no session cookie in callback response")
	}

	c.Token = sessionCookie
	return nil
}

// SimulateUserAuthorization simulates a user authorizing a device code.
// This makes the necessary HTTP requests that a browser would make.
func SimulateUserAuthorization(serverURL, userCode string) error {
	// Submit user code to authorization page
	authorizeURL := serverURL + "/auth/device"

	// POST form with user_code
	form := url.Values{}
	form.Set("user_code", userCode)

	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Follow redirects automatically
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	resp, err := client.Post(authorizeURL, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("post user code: %w", err)
	}
	defer resp.Body.Close()

	// Should redirect to OAuth, then back to callback, then to success page
	// The FakeOAuthProvider auto-approves, so this should complete the flow
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authorization failed: %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
