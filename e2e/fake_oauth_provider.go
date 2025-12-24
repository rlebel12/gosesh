package e2e

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"

	"golang.org/x/oauth2"
)

// FakeOAuthProvider simulates an OAuth2 provider for testing.
// It provides minimal OAuth2 endpoints for authorization code flow.
type FakeOAuthProvider struct {
	Server      *httptest.Server
	Config      *oauth2.Config
	AutoApprove bool // automatically approve authorization requests

	mu          sync.Mutex
	codes       map[string]*authCode // authorization codes
	accessToken map[string]*token    // access tokens
}

type authCode struct {
	Code        string
	RedirectURI string
	Used        bool
}

type token struct {
	AccessToken string
	UserID      string
}

// NewFakeOAuthProvider creates a new fake OAuth2 provider for testing.
// If autoApprove is true, authorization requests are immediately approved
// without user interaction, which is useful for automated testing.
func NewFakeOAuthProvider(autoApprove bool) *FakeOAuthProvider {
	provider := &FakeOAuthProvider{
		AutoApprove: autoApprove,
		codes:       make(map[string]*authCode),
		accessToken: make(map[string]*token),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", provider.handleAuthorize)
	mux.HandleFunc("/token", provider.handleToken)
	mux.HandleFunc("/userinfo", provider.handleUserInfo)

	provider.Server = httptest.NewServer(mux)

	// Configure oauth2.Config to point to our fake server
	provider.Config = &oauth2.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:  provider.Server.URL + "/authorize",
			TokenURL: provider.Server.URL + "/token",
		},
		Scopes: []string{"email", "profile"},
	}

	return provider
}

// handleAuthorize handles the OAuth2 authorization endpoint.
// GET /authorize?client_id=...&redirect_uri=...&response_type=code&state=...
func (p *FakeOAuthProvider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	redirectURI := query.Get("redirect_uri")
	state := query.Get("state")

	if redirectURI == "" {
		http.Error(w, "redirect_uri is required", http.StatusBadRequest)
		return
	}

	// Generate authorization code
	codeBytes := make([]byte, 16)
	rand.Read(codeBytes)
	code := hex.EncodeToString(codeBytes)

	// Store the authorization code
	p.mu.Lock()
	p.codes[code] = &authCode{
		Code:        code,
		RedirectURI: redirectURI,
		Used:        false,
	}
	p.mu.Unlock()

	// Build redirect URL
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}

	q := redirectURL.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	redirectURL.RawQuery = q.Encode()

	// If auto-approve is enabled, immediately redirect
	// Otherwise, would show an approval page (not needed for testing)
	if p.AutoApprove {
		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
		return
	}

	// For manual approval, show a simple form
	html := `<!DOCTYPE html>
<html>
<head><title>Authorize</title></head>
<body>
	<h1>Authorize Test Application</h1>
	<form method="POST" action="` + redirectURL.String() + `">
		<button type="submit">Approve</button>
	</form>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// handleToken handles the OAuth2 token exchange endpoint.
// POST /token with grant_type=authorization_code&code=...&redirect_uri=...
func (p *FakeOAuthProvider) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")

	if code == "" {
		http.Error(w, "code is required", http.StatusBadRequest)
		return
	}

	// Validate authorization code
	p.mu.Lock()
	authCode, ok := p.codes[code]
	if !ok || authCode.Used {
		p.mu.Unlock()
		http.Error(w, "invalid or expired authorization code", http.StatusBadRequest)
		return
	}

	// Validate redirect URI matches
	if authCode.RedirectURI != redirectURI {
		p.mu.Unlock()
		http.Error(w, "redirect_uri mismatch", http.StatusBadRequest)
		return
	}

	// Mark code as used
	authCode.Used = true

	// Generate access token
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	accessToken := hex.EncodeToString(tokenBytes)

	// Store token with fake user ID
	p.accessToken[accessToken] = &token{
		AccessToken: accessToken,
		UserID:      "test-user-" + code[:8], // Deterministic user ID based on code
	}
	p.mu.Unlock()

	// Return token response
	response := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleUserInfo handles the OAuth2 userinfo endpoint.
// GET /userinfo with Authorization: Bearer <access_token>
func (p *FakeOAuthProvider) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	// Extract access token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header required", http.StatusUnauthorized)
		return
	}

	// Parse "Bearer <token>"
	var accessToken string
	if _, err := fmt.Sscanf(authHeader, "Bearer %s", &accessToken); err != nil {
		http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
		return
	}

	// Validate access token
	p.mu.Lock()
	tok, ok := p.accessToken[accessToken]
	p.mu.Unlock()

	if !ok {
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}

	// Return fake user info
	userInfo := map[string]interface{}{
		"id":    tok.UserID,
		"email": tok.UserID + "@test.example.com",
		"name":  "Test User",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}

// Reset clears all stored authorization codes and access tokens.
// This is useful for isolating tests.
func (p *FakeOAuthProvider) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.codes = make(map[string]*authCode)
	p.accessToken = make(map[string]*token)
}

// Close shuts down the fake OAuth server.
func (p *FakeOAuthProvider) Close() {
	p.Server.Close()
}

// OAuthConfig returns the oauth2.Config pointing to this fake provider.
func (p *FakeOAuthProvider) OAuthConfig() *oauth2.Config {
	return p.Config
}
