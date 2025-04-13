package providers

import (
	"fmt"
	"io"
	"net/http"

	"github.com/rlebel12/gosesh"
	"golang.org/x/oauth2"
)

type Gosesher interface {
	OAuth2Begin(cfg *oauth2.Config) http.HandlerFunc
	OAuth2Callback(authProviderID gosesh.Identifier, cfg *oauth2.Config, handler gosesh.HandlerDoneFunc) http.HandlerFunc
	Scheme() string
	Host() string
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
