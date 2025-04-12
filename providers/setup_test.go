package providers

import (
	"net/http"
	"testing"

	"golang.org/x/oauth2"
)

type testSetup struct {
	sesh         Gosesher
	gotBeginCall struct {
		cfg *oauth2.Config
	}
}

func setup(t *testing.T) *testSetup {
	t.Helper()
	ts := &testSetup{}
	ts.sesh = NewFakeGosesher(
		"http",
		"localhost",
		func(cfg *oauth2.Config) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				ts.gotBeginCall.cfg = cfg
				w.WriteHeader(http.StatusOK)
			}
		},
	)
	return ts
}
