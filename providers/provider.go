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
		doRequest requestDoer
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

func (p *Provider) setDoRequest(doRequest requestDoer) {
	p.doRequest = doRequest
}

func (p *Provider) getConfig() *oauth2.Config {
	return p.Config
}

type requestDoer func(method, url string, header http.Header) (io.ReadCloser, error)

func doRequest(method, url string, header http.Header) (io.ReadCloser, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %s", err.Error())
	}
	for k, v := range header {
		req.Header[k] = v
	}

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
			return user, fmt.Errorf("unmarshal user data: %s", err.Error())
		}
		return user, nil
	}
}

var _ Gosesher = &gosesh.Gosesh{}
