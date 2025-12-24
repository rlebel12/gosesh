package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/rlebel12/gosesh"
	"golang.org/x/oauth2"
)

// TestServer wraps an HTTP test server with gosesh for e2e testing.
// It provides a complete working server with OAuth2, sessions, and authentication.
type TestServer struct {
	Server       *httptest.Server
	Gosesh       *gosesh.Gosesh
	Store        *gosesh.MemoryStore
	DeviceStore  *gosesh.MemoryDeviceCodeStore
	OAuthServer  *FakeOAuthProvider
	OAuthConfig  *oauth2.Config
}

// TestServerOption configures a TestServer.
type TestServerOption func(*TestServer)

// NewTestServer creates a new test server with gosesh configured for e2e testing.
// The server includes:
//   - FakeOAuthProvider for OAuth2 (auto-approves by default)
//   - MemoryStore for sessions
//   - MemoryDeviceCodeStore for device codes
//   - CompositeCredentialSource supporting both cookies and headers
//   - All authentication routes configured
func NewTestServer(opts ...TestServerOption) *TestServer {
	ts := &TestServer{}

	// Apply options first (allows overriding defaults)
	for _, opt := range opts {
		opt(ts)
	}

	// Create stores if not provided
	if ts.Store == nil {
		ts.Store = gosesh.NewMemoryStore()
	}
	if ts.DeviceStore == nil {
		ts.DeviceStore = gosesh.NewMemoryDeviceCodeStore()
	}

	// Create fake OAuth provider with auto-approve enabled
	if ts.OAuthServer == nil {
		ts.OAuthServer = NewFakeOAuthProvider(true)
	}

	// Create composite credential source (cookie + header)
	cookieSource := gosesh.NewCookieCredentialSource(
		gosesh.WithCookieSourceName("session"),
		gosesh.WithCookieSourceSecure(false), // HTTP for testing
		gosesh.WithCookieSourceSessionConfig(gosesh.DefaultBrowserSessionConfig()),
	)

	headerSource := gosesh.NewHeaderCredentialSource(
		gosesh.WithHeaderSessionConfig(gosesh.DefaultCLISessionConfig()),
	)

	// Cookie first in composite (takes precedence)
	credentialSource := gosesh.NewCompositeCredentialSource(cookieSource, headerSource)

	// Create Gosesh instance
	// We'll update the origin after the server starts to match the actual server URL
	if ts.Gosesh == nil {
		origin, _ := url.Parse("http://127.0.0.1:8080") // Temp, will be updated
		ts.Gosesh = gosesh.New(
			ts.Store,
			gosesh.WithOrigin(origin),
			gosesh.WithCredentialSource(credentialSource),
			gosesh.WithCookieDomain(func(*gosesh.Gosesh) func() string {
				return func() string { return "" }
			}), // Empty domain = current domain only (works with any IP/host)
		)
	}

	// Configure OAuth2 config to point to fake provider
	if ts.OAuthConfig == nil {
		ts.OAuthConfig = ts.OAuthServer.OAuthConfig()
		// Update redirect URIs to point to our test server
		// Note: We'll update this after the server starts
	}

	// Set up routes
	mux := http.NewServeMux()

	// Start test server first (we need the URL for OAuth config redirects)
	ts.Server = httptest.NewServer(mux)

	// Now configure OAuth redirects with actual server URL
	ts.OAuthConfig.RedirectURL = ts.Server.URL + "/auth/callback"

	// Create OAuth config for CLI
	cliOAuthConfig := &oauth2.Config{
		ClientID:     ts.OAuthConfig.ClientID,
		ClientSecret: ts.OAuthConfig.ClientSecret,
		Endpoint:     ts.OAuthConfig.Endpoint,
		Scopes:       ts.OAuthConfig.Scopes,
		RedirectURL:  ts.Server.URL + "/auth/cli/callback",
	}

	// Create OAuth config for device code flow
	deviceOAuthConfig := &oauth2.Config{
		ClientID:     ts.OAuthConfig.ClientID,
		ClientSecret: ts.OAuthConfig.ClientSecret,
		Endpoint:     ts.OAuthConfig.Endpoint,
		Scopes:       ts.OAuthConfig.Scopes,
		RedirectURL:  ts.Server.URL + "/auth/device/callback",
	}

	// Browser OAuth routes
	mux.HandleFunc("/auth/login", ts.Gosesh.OAuth2Begin(ts.OAuthConfig))
	mux.HandleFunc("/auth/callback", ts.Gosesh.OAuth2Callback(
		ts.OAuthConfig,
		fakeRequestUser,
		fakeUnmarshalUser,
		nil, // Use default done handler
	))

	// CLI localhost callback routes
	mux.HandleFunc("/auth/cli/begin", ts.Gosesh.OAuth2BeginCLI(cliOAuthConfig))
	mux.HandleFunc("/auth/cli/callback", ts.Gosesh.OAuth2CallbackCLI(
		cliOAuthConfig,
		fakeRequestUser,
		fakeUnmarshalUser,
	))

	// Device code routes
	mux.HandleFunc("/auth/device/begin", ts.Gosesh.DeviceCodeBegin(ts.DeviceStore))
	mux.HandleFunc("/auth/device/poll", ts.Gosesh.DeviceCodePoll(ts.DeviceStore))
	mux.HandleFunc("/auth/device", ts.handleDeviceAuthorize(deviceOAuthConfig))
	mux.HandleFunc("/auth/device/callback", ts.handleDeviceCallback(deviceOAuthConfig))

	// Protected API routes
	mux.Handle("/api/me", ts.Gosesh.Authenticate(http.HandlerFunc(ts.handleMe)))
	mux.Handle("/api/protected", ts.Gosesh.RequireAuthentication(http.HandlerFunc(ts.handleProtected)))

	// Logout
	mux.HandleFunc("/auth/logout", ts.Gosesh.Logout(nil))

	return ts
}

// handleMe returns the current session information.
func (ts *TestServer) handleMe(w http.ResponseWriter, r *http.Request) {
	session, ok := gosesh.CurrentSession(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	response := map[string]interface{}{
		"user_id":           session.UserID().String(),
		"session_id":        session.ID().String(),
		"idle_deadline":     session.IdleDeadline(),
		"absolute_deadline": session.AbsoluteDeadline(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleProtected is a simple protected endpoint for testing.
func (ts *TestServer) handleProtected(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "You are authenticated!",
	})
}

// handleDeviceAuthorize handles the device authorization page and form submission.
func (ts *TestServer) handleDeviceAuthorize(oauthConfig *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// Show authorization form
			html := `<!DOCTYPE html>
<html>
<head><title>Device Authorization</title></head>
<body>
	<h1>Device Authorization</h1>
	<form method="POST">
		<label>Device Code: <input type="text" name="user_code" required/></label>
		<button type="submit">Authorize</button>
	</form>
</body>
</html>`
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(html))
			return
		}

		if r.Method == http.MethodPost {
			// Validate user code exists
			if err := r.ParseForm(); err != nil {
				http.Error(w, "Invalid form", http.StatusBadRequest)
				return
			}

			userCode := r.FormValue("user_code")
			if userCode == "" {
				http.Error(w, "User code required", http.StatusBadRequest)
				return
			}

			ctx := r.Context()
			entry, err := ts.DeviceStore.GetByUserCode(ctx, userCode)
			if err != nil {
				http.Error(w, "Invalid or expired code", http.StatusBadRequest)
				return
			}

			// Store device code in state for callback
			// In a real implementation, we'd use a secure state cookie
			// For testing, we use the OAuth state parameter
			oauthURL := oauthConfig.AuthCodeURL(entry.DeviceCode)
			http.Redirect(w, r, oauthURL, http.StatusFound)
		}
	}
}

// handleDeviceCallback handles the OAuth callback for device flow.
func (ts *TestServer) handleDeviceCallback(oauthConfig *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Get code from query parameters (OAuth redirects use query params, not form values)
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Missing code parameter", http.StatusBadRequest)
			return
		}

		// Exchange code for token
		token, err := oauthConfig.Exchange(ctx, code)
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Get user data
		user, err := fakeUnmarshalUserFromToken(token.AccessToken)
		if err != nil {
			http.Error(w, "Failed to get user data", http.StatusInternalServerError)
			return
		}

		// Upsert user
		userID, err := ts.Store.UpsertUser(ctx, user)
		if err != nil {
			http.Error(w, "Failed to upsert user", http.StatusInternalServerError)
			return
		}

		// Create session with CLI config
		cliConfig := gosesh.DefaultCLISessionConfig()
		now := time.Now()
		idleDeadline := now.Add(cliConfig.AbsoluteDuration) // No idle timeout
		absoluteDeadline := now.Add(cliConfig.AbsoluteDuration)

		session, err := ts.Store.CreateSession(ctx, userID, idleDeadline, absoluteDeadline)
		if err != nil {
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}

		// Get device code from state parameter (OAuth uses query params for state)
		deviceCode := r.URL.Query().Get("state")
		if deviceCode == "" {
			http.Error(w, "Missing state parameter (device code)", http.StatusBadRequest)
			return
		}

		// Complete the device code
		if err := ts.DeviceStore.CompleteDeviceCode(ctx, deviceCode, session.ID()); err != nil {
			http.Error(w, "Failed to complete device code: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Show success page
		html := `<!DOCTYPE html>
<html>
<head><title>Success</title></head>
<body>
	<h1>Authorization Complete</h1>
	<p>You can close this window.</p>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
	}
}

// Reset clears all session and device code state.
// Call this between tests to isolate state.
func (ts *TestServer) Reset() {
	// Clear all sessions from the store
	ts.Store.Reset()

	// Clear device codes
	ts.DeviceStore.Reset()

	// Reset OAuth provider (clears auth codes and tokens)
	ts.OAuthServer.Reset()
}

// Close shuts down the test server and fake OAuth provider.
func (ts *TestServer) Close() {
	if ts.Server != nil {
		ts.Server.Close()
	}
	if ts.OAuthServer != nil {
		ts.OAuthServer.Close()
	}
}

// FakeUser represents a fake user for testing.
type FakeUser struct {
	ID    string
	Email string
}

// String implements Identifier interface.
func (f *FakeUser) String() string {
	return f.ID
}

// fakeRequestUser simulates fetching user data from OAuth provider.
// For e2e tests, we don't actually call the real OAuth provider's userinfo endpoint.
func fakeRequestUser(ctx context.Context, accessToken string) (io.ReadCloser, error) {
	// Return fake JSON user data
	jsonData := `{"id":"test-user-123","email":"test@example.com"}`
	return io.NopCloser(strings.NewReader(jsonData)), nil
}

// fakeUnmarshalUser creates a fake user from JSON data.
func fakeUnmarshalUser(b []byte) (gosesh.Identifier, error) {
	// Unmarshal simple JSON
	var data struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, err
	}

	return &FakeUser{
		ID:    data.ID,
		Email: data.Email,
	}, nil
}

// fakeUnmarshalUserFromToken creates a fake user from an access token string.
func fakeUnmarshalUserFromToken(accessToken string) (gosesh.Identifier, error) {
	return &FakeUser{
		ID:    "test-user-123",
		Email: "test@example.com",
	}, nil
}
