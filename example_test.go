package gosesh_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/rlebel12/gosesh"
	"github.com/rlebel12/gosesh/providers"
	"golang.org/x/oauth2"
)

// ExampleBasicSetup demonstrates the basic setup of gosesh
func Example_basicSetup() {
	// Create a new store
	store := gosesh.NewMemoryStore()

	// Initialize gosesh with the store
	gs := gosesh.New(store)
	_ = gs // Use gs for further configuration
}

// ExampleConfiguration demonstrates configuration options
func Example_configuration() {
	store := gosesh.NewMemoryStore()
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create a credential source with custom session configuration
	refreshThreshold := 10 * time.Minute
	credSource := gosesh.NewCookieCredentialSource(
		gosesh.WithCookieSourceName("my_session"),
		gosesh.WithCookieSourceSessionConfig(gosesh.SessionConfig{
			IdleDuration:     1 * time.Hour,  // Session idle timeout
			AbsoluteDuration: 24 * time.Hour, // Maximum session lifetime
			RefreshThreshold: &refreshThreshold,
		}),
	)

	gs := gosesh.New(store,
		gosesh.WithLogger(logger),             // Set a custom logger
		gosesh.WithCredentialSource(credSource), // Custom credential source
		gosesh.WithOrigin(&url.URL{ // Set your application's origin
			Scheme: "https",
			Host:   "example.com",
		}),
	)
	_ = gs // Use gs for further configuration
}

// ExampleBuiltInProvider demonstrates using a built-in provider
func Example_builtInProvider() {
	store := gosesh.NewMemoryStore()
	gs := gosesh.New(store)

	// Initialize a provider (e.g., Google)
	google := providers.NewGoogle(
		gs,                      // Your gosesh instance
		"your-client-id",        // OAuth2 client ID
		"your-client-secret",    // OAuth2 client secret
		"/auth/google/callback", // Callback path
	)

	// Set up your routes
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/google", google.OAuth2Begin())
	mux.HandleFunc("/auth/google/callback", google.OAuth2Callback(nil))
}

// ExampleCustomProvider demonstrates implementing a custom provider
func Example_customProvider() {
	store := gosesh.NewMemoryStore()
	gs := gosesh.New(store)

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
		return gosesh.StringIdentifier("user-1"), nil
	}

	// Set up your routes
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/custom", gs.OAuth2Begin(config))
	mux.HandleFunc("/auth/custom/callback", gs.OAuth2Callback(
		config,
		requestUser,
		unmarshalUser,
		nil, // Optional: custom done handler
	))
}

// TestExamples runs all the examples to ensure they compile and work as expected
func TestExamples(t *testing.T) {
	// These tests don't actually run the examples (which would require setting up
	// real OAuth2 providers), but they ensure the examples compile and the types
	// are correct.

	// Basic setup
	store := gosesh.NewMemoryStore()
	gs := gosesh.New(store)
	if gs == nil {
		t.Error("gosesh.New returned nil")
	}

	// Configuration with credential source
	refreshThreshold := 5 * time.Minute
	gs = gosesh.New(store,
		gosesh.WithCredentialSource(gosesh.NewCookieCredentialSource(
			gosesh.WithCookieSourceName("test_session"),
			gosesh.WithCookieSourceSessionConfig(gosesh.SessionConfig{
				IdleDuration:     30 * time.Minute,
				AbsoluteDuration: time.Hour,
				RefreshThreshold: &refreshThreshold,
			}),
		)),
	)
	if gs == nil {
		t.Error("gosesh.New with options returned nil")
	}

	// Built-in provider
	google := providers.NewGoogle(
		gs,
		"test-client-id",
		"test-client-secret",
		"/auth/google/callback",
	)
	if google == nil {
		t.Error("NewGoogle returned nil")
	}

	// Custom provider setup
	config := &oauth2.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost/auth/callback",
		Scopes:       []string{"profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "http://localhost/auth",
			TokenURL: "http://localhost/token",
		},
	}

	// Test OAuth2Begin
	handler := gs.OAuth2Begin(config)
	if handler == nil {
		t.Error("OAuth2Begin returned nil handler")
	}

	// Test OAuth2Callback
	handler = gs.OAuth2Callback(
		config,
		func(ctx context.Context, token string) (io.ReadCloser, error) {
			return nil, nil
		},
		func(b []byte) (gosesh.Identifier, error) {
			return gosesh.StringIdentifier("user-1"), nil
		},
		nil,
	)
	if handler == nil {
		t.Error("OAuth2Callback returned nil handler")
	}

	// Test RequireAuthentication
	authHandler := gs.RequireAuthentication(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	if authHandler == nil {
		t.Error("RequireAuthentication returned nil handler")
	}

	// Test Logout
	logoutHandler := gs.Logout(nil)
	if logoutHandler == nil {
		t.Error("Logout returned nil handler")
	}
}
