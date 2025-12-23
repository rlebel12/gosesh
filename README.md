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

- OAuth2 authentication flow handling
- Session management
- Protected route middleware
- Automatic session refresh
- Multiple OAuth2 provider support

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
    ErrUnauthorized          = errors.New("unauthorized")
    ErrFailedDeletingSession = errors.New("failed deleting session(s)")
    ErrSessionExpired        = errors.New("session expired")
    // ... more error types
)
```
