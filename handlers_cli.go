package gosesh

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"
)

// CLIStateData holds state + callback URL for CLI OAuth2 flow.
// This data is stored in the state cookie during OAuth2BeginCLI and
// retrieved during OAuth2CallbackCLI to validate CSRF and determine
// where to redirect with the session token.
type CLIStateData struct {
	State    string `json:"state"`
	Callback string `json:"callback"`
}

// isLocalhostURL validates that a URL is a localhost URL suitable for CLI callbacks.
// Only http://localhost or http://127.0.0.1 URLs are allowed (with any port).
// HTTPS is explicitly rejected to prevent misconfiguration.
//
// Security rationale:
// - Localhost callbacks are inherently local-only and don't need TLS
// - HTTPS on localhost is unusual and may indicate misconfiguration
// - Restricting to http prevents open redirect attacks via HTTPS URLs
func isLocalhostURL(u *url.URL) bool {
	// Must be http scheme (not https)
	if u.Scheme != "http" {
		return false
	}

	// Host must be localhost or 127.0.0.1 (any port is allowed)
	hostname := u.Hostname()
	return hostname == "localhost" || hostname == "127.0.0.1"
}

// OAuth2BeginCLI initiates the OAuth2 flow for CLI clients with a localhost callback.
// Unlike OAuth2Begin (for browser clients), this handler:
//   - Requires a "callback" query parameter with a localhost URL
//   - Validates the callback URL is localhost-only (security)
//   - Stores the callback URL in the state cookie for use in OAuth2CallbackCLI
//
// Query parameters:
//   - callback (required): The localhost URL to redirect to after OAuth completes.
//     Must be http://localhost:PORT or http://127.0.0.1:PORT
//
// Example: /auth/begin/cli?callback=http://localhost:8080/cb
//
// Security considerations:
//   - Only localhost/127.0.0.1 callbacks are allowed to prevent open redirects
//   - HTTPS localhost is rejected (unusual and may indicate misconfiguration)
//   - State parameter provides CSRF protection
func (gs *Gosesh) OAuth2BeginCLI(oauthCfg *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setSecureCookieHeaders(w)

		// Extract and validate callback URL
		callbackStr := r.URL.Query().Get("callback")
		if callbackStr == "" {
			http.Error(w, "callback parameter required", http.StatusBadRequest)
			return
		}

		callbackURL, err := url.Parse(callbackStr)
		if err != nil {
			http.Error(w, "invalid callback URL", http.StatusBadRequest)
			return
		}

		if !isLocalhostURL(callbackURL) {
			http.Error(w, "callback must be localhost", http.StatusBadRequest)
			return
		}

		// Generate secure state parameter
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			gs.logError("failed to create OAuth2 state", err)
			http.Error(w, "failed to create OAuth2 state", http.StatusInternalServerError)
			return
		}
		state := base64.URLEncoding.EncodeToString(b)

		// Store state + callback in cookie
		stateData := CLIStateData{
			State:    state,
			Callback: callbackStr,
		}

		stateJSON, err := json.Marshal(stateData)
		if err != nil {
			gs.logError("failed to marshal CLI state data", err)
			http.Error(w, "failed to create OAuth2 state", http.StatusInternalServerError)
			return
		}

		// Base64 encode the JSON to make it safe for cookie storage
		stateEncoded := base64.StdEncoding.EncodeToString(stateJSON)

		expiration := gs.now().UTC().Add(5 * time.Minute)
		cookie := gs.oauthStateCookie(stateEncoded, expiration)
		http.SetCookie(w, cookie)

		// Redirect to OAuth provider with state parameter
		authURL := oauthCfg.AuthCodeURL(state)
		http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
	}
}

// OAuth2CallbackCLI handles the OAuth2 callback for CLI clients.
// Unlike OAuth2Callback (for browser clients), this handler:
//   - Redirects to the localhost callback URL (instead of setting a session cookie)
//   - Passes the session token as a query parameter (not a cookie)
//   - Forwards OAuth errors to the callback URL
//   - Creates sessions with CLI session config (30-day absolute, no idle)
//
// The callback URL receives either:
//   - Success: ?token=<session_id>
//   - Error: ?error=<error>&error_description=<description>
//
// Security considerations:
//   - State parameter validates CSRF protection
//   - Callback URL is validated to be localhost-only
//   - Session token is passed in query param (client stores it)
func (gs *Gosesh) OAuth2CallbackCLI(
	oauthCfg *oauth2.Config,
	request RequestFunc,
	unmarshal UnmarshalFunc,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setSecureCookieHeaders(w)

		ctx := r.Context()

		// Read and parse state cookie
		oauthState, err := r.Cookie(gs.oAuth2StateCookieName)
		if err != nil {
			http.Error(w, "missing state cookie", http.StatusBadRequest)
			return
		}

		// Expire state cookie
		now := gs.now().UTC()
		stateCookie := gs.oauthStateCookie("", now)
		http.SetCookie(w, stateCookie)

		// Decode and parse state data
		stateJSON, err := base64.StdEncoding.DecodeString(oauthState.Value)
		if err != nil {
			http.Error(w, "invalid state cookie encoding", http.StatusBadRequest)
			return
		}

		var stateData CLIStateData
		if err := json.Unmarshal(stateJSON, &stateData); err != nil {
			http.Error(w, "invalid state cookie", http.StatusBadRequest)
			return
		}

		// Validate state parameter (CSRF protection)
		if r.FormValue("state") != stateData.State {
			http.Error(w, "invalid state parameter", http.StatusBadRequest)
			return
		}

		// Parse and re-validate callback URL (defense in depth)
		callbackURL, err := url.Parse(stateData.Callback)
		if err != nil {
			http.Error(w, "invalid callback URL in state", http.StatusBadRequest)
			return
		}

		// Re-validate callback is still localhost-only (prevent tampering)
		if !isLocalhostURL(callbackURL) {
			gs.logWarn("callback URL in state is not localhost", "url", stateData.Callback)
			http.Error(w, "invalid callback URL", http.StatusBadRequest)
			return
		}

		// Check for OAuth errors and forward them to callback
		if oauthError := r.FormValue("error"); oauthError != "" {
			q := callbackURL.Query()
			q.Set("error", oauthError)
			if errorDesc := r.FormValue("error_description"); errorDesc != "" {
				q.Set("error_description", errorDesc)
			}
			callbackURL.RawQuery = q.Encode()
			http.Redirect(w, r, callbackURL.String(), http.StatusTemporaryRedirect)
			return
		}

		// Exchange authorization code for token
		token, err := oauthCfg.Exchange(ctx, r.FormValue("code"))
		if err != nil {
			gs.logError("failed to exchange code for token", err)
			q := callbackURL.Query()
			q.Set("error", "token_exchange_failed")
			callbackURL.RawQuery = q.Encode()
			http.Redirect(w, r, callbackURL.String(), http.StatusTemporaryRedirect)
			return
		}

		// Fetch and unmarshal user data
		user, err := unmarshalUserData(ctx, request, unmarshal, token.AccessToken)
		if err != nil {
			gs.logError("failed to get user data", err)
			q := callbackURL.Query()
			q.Set("error", "user_data_failed")
			callbackURL.RawQuery = q.Encode()
			http.Redirect(w, r, callbackURL.String(), http.StatusTemporaryRedirect)
			return
		}

		// Upsert user in store
		id, err := gs.store.UpsertUser(ctx, user)
		if err != nil {
			gs.logError("failed to upsert user", err)
			q := callbackURL.Query()
			q.Set("error", "user_upsert_failed")
			callbackURL.RawQuery = q.Encode()
			http.Redirect(w, r, callbackURL.String(), http.StatusTemporaryRedirect)
			return
		}

		// Get CLI session config
		cliConfig := gs.getCLISessionConfig()

		// Create session with CLI config
		idleDeadline := now
		if cliConfig.IdleDuration > 0 {
			idleDeadline = now.Add(cliConfig.IdleDuration)
		} else {
			// No idle timeout - set to absolute deadline
			idleDeadline = now.Add(cliConfig.AbsoluteDuration)
		}
		absoluteDeadline := now.Add(cliConfig.AbsoluteDuration)

		session, err := gs.store.CreateSession(ctx, id, idleDeadline, absoluteDeadline)
		if err != nil {
			gs.logError("failed to create session", err)
			q := callbackURL.Query()
			q.Set("error", "session_creation_failed")
			callbackURL.RawQuery = q.Encode()
			http.Redirect(w, r, callbackURL.String(), http.StatusTemporaryRedirect)
			return
		}

		// Add token to callback URL query params
		q := callbackURL.Query()
		q.Set("token", session.ID().String())
		callbackURL.RawQuery = q.Encode()

		http.Redirect(w, r, callbackURL.String(), http.StatusTemporaryRedirect)
	}
}

// getCLISessionConfig returns the appropriate session configuration for CLI sessions.
// It attempts to extract the configuration from the credential source:
//   1. If using CompositeCredentialSource, finds the first HeaderCredentialSource
//   2. If using HeaderCredentialSource directly, uses its config
//   3. Otherwise, returns DefaultCLISessionConfig()
//
// This allows CLI sessions to have different timeout characteristics than
// browser sessions (e.g., 30-day absolute timeout, no idle timeout).
func (gs *Gosesh) getCLISessionConfig() SessionConfig {
	// Check if credential source is CompositeCredentialSource
	if composite, ok := gs.credentialSource.(*CompositeCredentialSource); ok {
		// Find HeaderCredentialSource in the chain
		for _, source := range composite.sources {
			if header, ok := source.(*HeaderCredentialSource); ok {
				return header.SessionConfig()
			}
		}
	}

	// Check if credential source is HeaderCredentialSource directly
	if header, ok := gs.credentialSource.(*HeaderCredentialSource); ok {
		return header.SessionConfig()
	}

	// Default to CLI session config
	return DefaultCLISessionConfig()
}
