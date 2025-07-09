package providers

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"

	"github.com/rlebel12/gosesh"
	"golang.org/x/oauth2"
)

// Gosesher is an interface that defines the required methods for OAuth2 authentication.
// It is implemented by the gosesh.Gosesh type and used by providers to handle the OAuth2 flow.
type Gosesher interface {
	OAuth2Begin(cfg *oauth2.Config) http.HandlerFunc
	OAuth2Callback(
		config *oauth2.Config, request gosesh.RequestFunc, unmarshal gosesh.UnmarshalFunc, done gosesh.HandlerDoneFunc,
	) http.HandlerFunc
	Scheme() string
	Host() string
}

// Provider is the base type for all OAuth2 providers.
// It contains common functionality shared by all providers.
type Provider struct {
	Gosesh    Gosesher
	Config    *oauth2.Config
	doRequest requestDoer
}

// Opt is a function type for configuring provider options.
type Opt[T any] func(*T)

// newProvider creates a new Provider instance with the given configuration.
// It sets up the OAuth2 config and request handler for the provider.
func newProvider(sesh Gosesher, scopes []string, endpoint oauth2.Endpoint, clientID, clientSecret, redirectPath string) Provider {
	return Provider{
		Gosesh: sesh,
		Config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL: fmt.Sprintf(
				"%s://%s%s", sesh.Scheme(), sesh.Host(), redirectPath),
			Scopes:   scopes,
			Endpoint: endpoint,
		},
		doRequest: doRequest,
	}
}

// setDoRequest sets a custom request handler for the provider.
// This is primarily used for testing purposes.
func (p *Provider) setDoRequest(doRequest requestDoer) {
	p.doRequest = doRequest
}

// getConfig returns the provider's OAuth2 configuration.
func (p *Provider) getConfig() *oauth2.Config {
	return p.Config
}

// requestDoer is a function type that defines how HTTP requests should be made.
// It allows for customization of the request process, particularly useful for testing.
type requestDoer func(method, url string, header http.Header) (io.ReadCloser, error)

// doRequest performs an HTTP request with the given method, URL, and headers.
// It handles common error cases and returns the response body.
func doRequest(method, url string, header http.Header) (io.ReadCloser, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	maps.Copy(req.Header, header)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err = fmt.Errorf("response not ok: %s", resp.Status)
	}
	return resp.Body, err
}

// unmarshalUser creates an UnmarshalFunc for a specific user type.
// It uses a generic type parameter to ensure the user type implements the Identifier interface.
func unmarshalUser[T gosesh.Identifier](newUser func() T) gosesh.UnmarshalFunc {
	return func(b []byte) (gosesh.Identifier, error) {
		user := newUser()
		err := json.Unmarshal(b, &user)
		if err != nil {
			return user, fmt.Errorf("unmarshal user data: %w", err)
		}
		return user, nil
	}
}

// Ensure Gosesh implements the Gosesher interface
var _ Gosesher = &gosesh.Gosesh{}
