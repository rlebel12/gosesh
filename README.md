# gosesh

[![Go Reference](https://pkg.go.dev/badge/github.com/rlebel12/gosesh.svg)](https://pkg.go.dev/github.com/rlebel12/gosesh)
[![Test](https://github.com/rlebel12/gosesh/actions/workflows/test.yml/badge.svg)](https://github.com/rlebel12/gosesh/actions/workflows/test.yml)

An auth library that abstracts away the OAuth2 flow.

## ⚠️ Under Development ⚠️

This library is currently under active development, and the API is subject to change.

## Installation

```bash
go get github.com/rlebel12/gosesh
```

## Overview

`gosesh` is a Go library that simplifies OAuth2 authentication by handling the OAuth2 flow and session management. It provides:

- OAuth2 authentication flow handling (browser and native apps)
- Session management with configurable timeouts
- Protected route middleware
- Automatic session refresh
- Multiple OAuth2 provider support
- Device code flow for headless environments
- Token exchange for native apps handling OAuth directly

## Usage

### Basic Setup

First, create a store that implements the `Storer` interface. Here's an example using the in-memory store:

```go
import "github.com/rlebel12/gosesh"

// Create a new store
store := gosesh.NewMemoryStore()

// Initialize gosesh with the store
gs := gosesh.New(store)
```

### Configuration Options

`gosesh` can be configured with various options:

```go
gs := gosesh.New(store,
    gosesh.WithLogger(logger),                      // Set a custom logger
    gosesh.WithSessionCookieName("my_session"),     // Custom session cookie name
    gosesh.WithSessionIdleTimeout(1 * time.Hour),   // Session idle timeout (sliding window)
    gosesh.WithSessionMaxLifetime(24 * time.Hour),  // Maximum session lifetime (hard limit)
    gosesh.WithSessionRefreshThreshold(10 * time.Minute), // Refresh threshold
    gosesh.WithOrigin(&url.URL{                     // Set your application's origin
        Scheme: "https",
        Host:   "example.com",
    }),
)
```

### Using Built-in Providers

`gosesh` includes built-in support for several OAuth2 providers. The providers package handles all the OAuth2 configuration and user data retrieval, making it simple to integrate:

```go
import "github.com/rlebel12/gosesh/providers"

// Initialize a provider (e.g., Google)
google := providers.NewGoogle(
    gs,                    // Your gosesh instance
    "your-client-id",      // OAuth2 client ID
    "your-client-secret",  // OAuth2 client secret
    "/auth/google/callback", // Callback path
)

// Set up your routes
http.HandleFunc("/auth/google", google.OAuth2Begin())
http.HandleFunc("/auth/google/callback", google.OAuth2Callback(nil))
```

The providers package includes support for:

- Google
- Discord
- Twitch

Each provider handles:

- OAuth2 configuration
- User data retrieval
- User data unmarshaling
- Callback handling

### Setting Up Protected Routes

Set up protected routes using the authentication middleware:

```go
// Protected route
http.Handle("/protected", gs.RequireAuthentication(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    // This handler will only be called if the user is authenticated
    session, _ := gosesh.CurrentSession(r)
    fmt.Fprintf(w, "Hello, authenticated user %s!", session.UserID())
})))
```

### Logout

Handle user logout:

```go
http.HandleFunc("/logout", gs.Logout(nil))
```

### Custom Provider Implementation

For custom OAuth2 providers, you can directly use `gosesh`'s OAuth2 handlers with your own configuration and user data handling:

```go
import (
    "context"
    "encoding/json"
    "io"
    "net/http"
    "golang.org/x/oauth2"
)

// Define your OAuth2 configuration
config := &oauth2.Config{
    ClientID:     "your-client-id",
    ClientSecret: "your-client-secret",
    RedirectURL:  "https://your-app.com/auth/custom/callback",
    Scopes:       []string{"profile", "email"},
    Endpoint: oauth2.Endpoint{
        AuthURL:  "https://provider.com/oauth2/auth",
        TokenURL: "https://provider.com/oauth2/token",
    },
}

// Define how to request user data
requestUser := func(ctx context.Context, accessToken string) (io.ReadCloser, error) {
    req, err := http.NewRequestWithContext(ctx, "GET", "https://provider.com/userinfo", nil)
    if err != nil {
        return nil, err
    }
    req.Header.Set("Authorization", "Bearer "+accessToken)

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return nil, err
    }
    return resp.Body, nil
}

// Define how to unmarshal user data
unmarshalUser := func(b []byte) (gosesh.Identifier, error) {
    var user struct {
        ID    string `json:"id"`
        Email string `json:"email"`
    }
    if err := json.Unmarshal(b, &user); err != nil {
        return nil, err
    }
    return gosesh.StringIdentifier(user.ID), nil
}

// Set up your routes
http.HandleFunc("/auth/custom", gs.OAuth2Begin(config))
http.HandleFunc("/auth/custom/callback", gs.OAuth2Callback(
    config,
    requestUser,
    unmarshalUser,
    nil, // Optional: custom done handler
))
```

### Native App Authentication

For native applications (desktop, mobile, CLI), `gosesh` provides two authentication methods that don't rely on browser cookies:

#### Device Code Flow

The device code flow is ideal for headless environments or when you want users to authorize on a separate device:

```go
// Implement DeviceCodeStore interface for your storage
type DeviceCodeStore interface {
    CreateDeviceCode(ctx context.Context, userCode string, expiresAt time.Time) (deviceCode string, err error)
    GetDeviceCode(ctx context.Context, deviceCode string) (*DeviceCodeEntry, error)
    GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCodeEntry, error)
    CompleteDeviceCode(ctx context.Context, deviceCode string, sessionID string) error
    DeleteDeviceCode(ctx context.Context, deviceCode string) error
}

// Set up device code routes
http.HandleFunc("/auth/device/begin", gs.DeviceCodeBegin(deviceStore))
http.HandleFunc("/auth/device/poll", gs.DeviceCodePoll(deviceStore))
http.HandleFunc("/auth/device", gs.DeviceCodeAuthorize(deviceStore, oauthConfig))
http.HandleFunc("/auth/device/callback", gs.DeviceCodeAuthorizeCallback(
    deviceStore, oauthConfig, requestUser, unmarshalUser,
))
```

The flow works as follows:
1. Native app calls `/auth/device/begin` to get a user code
2. User enters the code at the verification URL in their browser
3. Native app polls `/auth/device/poll` until authorization completes
4. Native app receives a session token to use in subsequent requests

#### Token Exchange

For native apps that handle OAuth2/PKCE directly with the identity provider:

```go
// Native app completes OAuth with provider, then exchanges access token for session
http.HandleFunc("/api/token/exchange", gs.ExchangeExternalToken(
    requestUser,    // Same RequestFunc as browser flow
    unmarshalUser,  // Same UnmarshalFunc as browser flow
    nil,            // Optional: custom done handler
))
```

Request:
```json
POST /api/token/exchange
{"access_token": "token-from-oauth-provider"}
```

Response:
```json
{"session_id": "...", "expires_at": "2025-02-26T..."}
```

##### Audience Validation

When accepting external tokens, you can validate that the token was issued for your application by checking its audience claim. This prevents token confusion attacks where a token issued for a different application is used.

```go
import "github.com/rlebel12/gosesh/providers"

// Create a validator for Google access tokens
validator := providers.NewGoogleTokenInfoValidator(http.DefaultClient)

// Configure token exchange with audience validation
http.HandleFunc("/api/token/exchange", gs.ExchangeExternalToken(
    requestUser,
    unmarshalUser,
    nil,
    gosesh.WithAudienceValidator(validator),
    gosesh.WithExpectedAudiences("your-google-client-id.apps.googleusercontent.com"),
))
```

The `AudienceValidator` interface allows custom implementations for other providers:

```go
type AudienceValidator interface {
    ValidateAudience(ctx context.Context, accessToken string) (audience string, err error)
}
```

When validation fails, the error wraps `gosesh.ErrFailedValidatingAudience` for sentinel checking:

```go
if errors.Is(err, gosesh.ErrFailedValidatingAudience) {
    // Token audience didn't match expected values
}
```

#### Using Session Tokens

Native apps send the session token via the Authorization header:

```go
// Configure header-based authentication
headerSource := gosesh.NewHeaderCredentialSource(
    gosesh.WithHeaderSessionConfig(gosesh.DefaultNativeAppSessionConfig()),
)

gs := gosesh.New(store,
    gosesh.WithCredentialSource(headerSource),
)
```

Client requests include:
```
Authorization: Bearer <session_id>
```

#### Supporting Both Browser and Native Apps

Use a composite credential source to support both authentication methods:

```go
cookieSource := gosesh.NewCookieCredentialSource(
    gosesh.WithCookieSourceName("session"),
    gosesh.WithCookieSourceSessionConfig(gosesh.DefaultBrowserSessionConfig()),
)

headerSource := gosesh.NewHeaderCredentialSource(
    gosesh.WithHeaderSessionConfig(gosesh.DefaultNativeAppSessionConfig()),
)

// Cookie takes precedence (listed first)
credentialSource := gosesh.NewCompositeCredentialSource(cookieSource, headerSource)

gs := gosesh.New(store,
    gosesh.WithCredentialSource(credentialSource),
)
```

### Session Management

`gosesh` handles session management automatically. Sessions can be:

- Created during OAuth2 callback
- Retrieved using `CurrentSession(r)`
- Deleted during logout
- Automatically refreshed when active

### Error Handling

`gosesh` provides several error types:

```go
var (
    ErrUnauthorized              = errors.New("unauthorized")
    ErrFailedDeletingSession     = errors.New("failed deleting session(s)")
    ErrSessionExpired            = errors.New("session expired")
    ErrFailedValidatingAudience  = errors.New("failed validating audience")
    // ... more error types
)
```
