package providers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/rlebel12/gosesh"
	"golang.org/x/oauth2"
)

type (
	Gosesher interface {
		OAuth2Begin(cfg *oauth2.Config) http.HandlerFunc
		OAuth2Callback(
			config *oauth2.Config, request gosesh.RequestFunc, unmarshal gosesh.UnmarshalFunc, done gosesh.HandlerDoneFunc,
		) http.HandlerFunc
		Scheme() string
		Host() string
	}

	Provider struct {
		Gosesh    Gosesher
		Config    *oauth2.Config
		doRequest func(req *http.Request) (io.ReadCloser, error)
	}

	Opt[T any] func(*T)
)

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

func (p *Provider) setDoRequest(doRequest func(req *http.Request) (io.ReadCloser, error)) {
	p.doRequest = doRequest
}

func doRequest(req *http.Request) (io.ReadCloser, error) {
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send request: %s", err.Error())
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err = fmt.Errorf("response not ok: %s", resp.Status)
	}
	return resp.Body, err
}

func unmarshalUser[T gosesh.Identifier](newUser func() T) gosesh.UnmarshalFunc {
	return func(b []byte) (gosesh.Identifier, error) {
		user := newUser()
		err := json.Unmarshal(b, &user)
		if err != nil {
			return user, fmt.Errorf("failed to unmarshal user data: %s", err.Error())
		}
		return user, nil
	}
}

var _ Gosesher = &gosesh.Gosesh{}
