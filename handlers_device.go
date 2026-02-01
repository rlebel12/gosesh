package gosesh

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// DeviceCodeBeginResponse is returned by the device code begin endpoint.
// It contains all the information needed for a device to complete the authorization flow.
type DeviceCodeBeginResponse struct {
	// DeviceCode is the long secret code the device uses to poll for completion.
	DeviceCode string `json:"device_code"`

	// UserCode is the short code the user enters on the verification page.
	UserCode string `json:"user_code"`

	// VerificationURI is the URL where the user should go to enter their code.
	VerificationURI string `json:"verification_uri"`

	// ExpiresIn is the number of seconds until the device code expires.
	ExpiresIn int `json:"expires_in"`

	// Interval is the minimum number of seconds between poll requests.
	Interval int `json:"interval"`
}

// DeviceCodePollResponse is returned by the device code poll endpoint.
// It indicates the current status of the authorization.
type DeviceCodePollResponse struct {
	// Status is one of: "pending", "complete", "expired"
	Status string `json:"status"`

	// SessionID is present when Status is "complete"
	SessionID string `json:"session_id,omitempty"`

	// ExpiresAt is the ISO 8601 timestamp when the session expires (when complete)
	ExpiresAt string `json:"expires_at,omitempty"`
}

// DeviceCodeBegin creates a new device authorization request.
// This endpoint is called by devices (like native apps or CLI tools) to initiate the device flow.
//
// POST /auth/device/begin
// Response: DeviceCodeBeginResponse
func (gs *Gosesh) DeviceCodeBegin(store DeviceCodeStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Generate user code with collision detection
		userCode, err := generateUserCode(store, ctx)
		if err != nil {
			gs.logger.Error("generate user code", "error", err)
			http.Error(w, "generate user code", http.StatusInternalServerError)
			return
		}

		// Set expiry to 15 minutes from now
		expiresAt := gs.now().Add(15 * time.Minute)

		// Create device code entry
		deviceCode, err := store.CreateDeviceCode(ctx, userCode, expiresAt)
		if err != nil {
			gs.logger.Error("create device code", "error", err)
			http.Error(w, "create device code", http.StatusInternalServerError)
			return
		}

		// Build verification URI
		verificationURI := fmt.Sprintf("%s://%s/auth/device", gs.Scheme(), gs.Host())

		// Return response
		response := DeviceCodeBeginResponse{
			DeviceCode:      deviceCode,
			UserCode:        userCode,
			VerificationURI: verificationURI,
			ExpiresIn:       int(15 * 60), // 15 minutes in seconds
			Interval:        5,            // 5 seconds
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			gs.logger.Error("encode response", "error", err)
		}
	}
}

// DeviceCodePoll checks the status of a device authorization.
// This endpoint is polled by devices to check if the user has authorized them.
//
// POST /auth/device/poll
// Request body: {"device_code": "..."}
// Response: DeviceCodePollResponse
func (gs *Gosesh) DeviceCodePoll(store DeviceCodeStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Parse request
		var request struct {
			DeviceCode string `json:"device_code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		if request.DeviceCode == "" {
			http.Error(w, "device_code is required", http.StatusBadRequest)
			return
		}

		// Get device code entry
		entry, err := store.GetDeviceCode(ctx, request.DeviceCode)
		if err != nil {
			if err == ErrDeviceCodeExpired {
				// Return expired status
				response := DeviceCodePollResponse{
					Status: "expired",
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
				return
			}
			// Not found or other error
			http.Error(w, "invalid device code", http.StatusBadRequest)
			return
		}

		// Check rate limiting
		if !entry.LastPoll.IsZero() {
			timeSinceLastPoll := time.Since(entry.LastPoll)
			if timeSinceLastPoll < entry.Interval {
				http.Error(w, "polling too frequently", http.StatusTooManyRequests)
				return
			}
		}

		// Update last poll time
		if err := store.UpdateLastPoll(ctx, request.DeviceCode, gs.now()); err != nil {
			gs.logger.Error("update last poll", "error", err)
			// Don't fail the request, just log
		}

		// Check if completed
		var response DeviceCodePollResponse
		if entry.Completed {
			response = DeviceCodePollResponse{
				Status:    "complete",
				SessionID: entry.SessionID.String(),
				ExpiresAt: entry.ExpiresAt.Format(time.RFC3339),
			}
		} else {
			response = DeviceCodePollResponse{
				Status: "pending",
			}
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			gs.logger.Error("encode response", "error", err)
		}
	}
}

// DeviceCodeAuthorize shows the authorization page where users enter their device code.
//
// GET /auth/device - Shows the form
// POST /auth/device - Validates the code and redirects to OAuth
func (gs *Gosesh) DeviceCodeAuthorize(store DeviceCodeStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// Show the authorization form
			html := `<!DOCTYPE html>
<html>
<head>
    <title>Device Authorization</title>
    <style>
        body {
            font-family: system-ui, -apple-system, sans-serif;
            max-width: 500px;
            margin: 50px auto;
            padding: 20px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"] {
            width: 100%;
            padding: 10px;
            font-size: 18px;
            border: 2px solid #ddd;
            border-radius: 4px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        button {
            background: #007bff;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            cursor: pointer;
        }
        button:hover {
            background: #0056b3;
        }
        .error {
            color: #dc3545;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <h1>Device Authorization</h1>
    <p>Enter the code shown on your device:</p>
    {{if .Error}}
    <div class="error">{{.Error}}</div>
    {{end}}
    <form method="POST">
        <div class="form-group">
            <label for="user_code">Device Code:</label>
            <input type="text" id="user_code" name="user_code" placeholder="XXXX-XXXX" required>
        </div>
        <button type="submit">Continue</button>
    </form>
</body>
</html>`
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(html))
			return
		}

		if r.Method == http.MethodPost {
			// Handle form submission
			if err := r.ParseForm(); err != nil {
				http.Error(w, "invalid form data", http.StatusBadRequest)
				return
			}

			userCode := r.FormValue("user_code")
			if userCode == "" {
				html := `<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
    <h1>Error</h1>
    <p>User code is required.</p>
    <a href="/auth/device">Try again</a>
</body>
</html>`
				w.Header().Set("Content-Type", "text/html")
				w.Write([]byte(html))
				return
			}

			// Validate user code exists
			ctx := r.Context()
			_, err := store.GetByUserCode(ctx, userCode)
			if err != nil {
				html := `<!DOCTYPE html>
<html>
<head><title>Invalid Code</title></head>
<body>
    <h1>Invalid Code</h1>
    <p>The code you entered is invalid or has expired.</p>
    <a href="/auth/device">Try again</a>
</body>
</html>`
				w.Header().Set("Content-Type", "text/html")
				w.Write([]byte(html))
				return
			}

			// Code is valid - redirect to OAuth
			// Note: In a real implementation, you would redirect to OAuth2Begin
			// with the device code stored in state/cookie so the callback knows which device to complete
			http.Redirect(w, r, "/auth/oauth/begin", http.StatusFound)
		}
	}
}

// DeviceCodeAuthorizeCallback handles the OAuth callback for device flow.
// After the user completes OAuth, this links the session to the device code.
//
// This is similar to OAuth2Callback but uses native app session config and completes the device code.
func (gs *Gosesh) DeviceCodeAuthorizeCallback(
	store DeviceCodeStore,
	oauthCfg *oauth2.Config,
	request RequestFunc,
	unmarshal UnmarshalFunc,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Exchange OAuth code for token
		token, err := oauthCfg.Exchange(ctx, r.FormValue("code"))
		if err != nil {
			gs.logger.Error("exchange token", "error", err)
			http.Error(w, "exchange token", http.StatusInternalServerError)
			return
		}

		// Fetch user data
		user, err := unmarshalUserData(ctx, request, unmarshal, token.AccessToken)
		if err != nil {
			gs.logger.Error("get user data", "error", err)
			http.Error(w, "get user data", http.StatusInternalServerError)
			return
		}

		// Upsert user
		userID, err := gs.store.UpsertUser(ctx, user)
		if err != nil {
			gs.logger.Error("upsert user", "error", err)
			http.Error(w, "upsert user", http.StatusInternalServerError)
			return
		}

		// Create session with native app session config (30 days, no idle timeout)
		now := gs.now()
		nativeAppConfig := DefaultNativeAppSessionConfig()
		var idleDeadline time.Time
		if nativeAppConfig.IdleDuration > 0 {
			idleDeadline = now.Add(nativeAppConfig.IdleDuration)
		} else {
			// No idle timeout - set to absolute deadline
			idleDeadline = now.Add(nativeAppConfig.AbsoluteDuration)
		}
		absoluteDeadline := now.Add(nativeAppConfig.AbsoluteDuration)

		session, err := gs.store.CreateSession(ctx, userID, idleDeadline, absoluteDeadline)
		if err != nil {
			gs.logger.Error("create session", "error", err)
			http.Error(w, "create session", http.StatusInternalServerError)
			return
		}

		// Get device code from state (in a real implementation)
		// For now, we'll extract it from the state parameter
		deviceCode := r.FormValue("state")

		// Complete the device code
		if err := store.CompleteDeviceCode(ctx, deviceCode, session.ID()); err != nil {
			gs.logger.Error("complete device code", "error", err)
			http.Error(w, "complete device code", http.StatusInternalServerError)
			return
		}

		// Show success page
		html := `<!DOCTYPE html>
<html>
<head>
    <title>Authorization Complete</title>
    <style>
        body {
            font-family: system-ui, -apple-system, sans-serif;
            max-width: 500px;
            margin: 50px auto;
            padding: 20px;
            text-align: center;
        }
        .success {
            color: #28a745;
            font-size: 24px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="success">✓ Authorization Complete</div>
    <p>You have successfully authorized the device.</p>
    <p>You can now close this window and return to your device.</p>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
	}
}

// generateUserCode creates a human-readable code with collision detection.
// Format: XXXX-XXXX (8 chars from safe alphabet with hyphen for readability)
// Safe alphabet: BCDFGHJKLMNPQRSTVWXYZ23456789 (no vowels, no 0/1/O/I)
func generateUserCode(store DeviceCodeStore, ctx context.Context) (string, error) {
	const safeAlphabet = "BCDFGHJKLMNPQRSTVWXYZ23456789"
	const codeLength = 8
	const maxAttempts = 10

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Generate 8 random characters
		bytes := make([]byte, codeLength)
		if _, err := rand.Read(bytes); err != nil {
			return "", fmt.Errorf("failed to generate random bytes: %w", err)
		}

		// Convert to safe alphabet
		code := make([]byte, codeLength)
		for i := 0; i < codeLength; i++ {
			code[i] = safeAlphabet[int(bytes[i])%len(safeAlphabet)]
		}

		// Format as XXXX-XXXX
		formattedCode := fmt.Sprintf("%s-%s", string(code[:4]), string(code[4:]))

		// Check for collision
		_, err := store.GetByUserCode(ctx, formattedCode)
		if err == ErrDeviceCodeNotFound {
			// No collision - this code is available
			return formattedCode, nil
		}
		if err != nil && err != ErrDeviceCodeExpired {
			// Unexpected error
			return "", fmt.Errorf("failed to check user code collision: %w", err)
		}

		// Collision or expired code - try again
	}

	return "", fmt.Errorf("failed to generate unique user code after %d attempts", maxAttempts)
}
