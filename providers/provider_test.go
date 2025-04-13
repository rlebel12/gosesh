package providers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rlebel12/gosesh"
	"github.com/rlebel12/gosesh/internal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDoRequest(t *testing.T) {
	for name, tc := range map[string]struct {
		giveContent   []byte
		giveStatus    int
		prepareServer func(s *httptest.Server)
		wantContent   []byte
		wantErr       string
	}{
		"success": {
			giveContent: []byte("content"),
			giveStatus:  http.StatusOK,
			wantContent: []byte("content"),
		},
		"send request error": {
			giveStatus:  http.StatusOK,
			giveContent: []byte("content"),
			prepareServer: func(s *httptest.Server) {
				s.Close()
			},
			wantErr: "send request",
		},
		"response not ok": {
			giveStatus:  http.StatusNotFound,
			giveContent: []byte("content"),
			wantErr:     "response not ok: 404 Not Found",
		},
	} {
		t.Run(name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/endpoint", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.giveStatus)
				_, err := w.Write(tc.giveContent)
				require.NoError(t, err)
			})
			server := httptest.NewServer(mux)
			t.Cleanup(server.Close)
			if tc.prepareServer != nil {
				tc.prepareServer(server)
			}

			req, err := http.NewRequest("GET", server.URL+"/endpoint", nil)
			require.NoError(t, err)

			got, err := doRequest(req)

			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			defer got.Close()
			gotContent, err := io.ReadAll(got)
			require.NoError(t, err)
			assert.Equal(t, tc.wantContent, gotContent)
		})
	}
}

func TestUnmarshalUser(t *testing.T) {
	for name, tc := range map[string]struct {
		giveContent []byte
		wantUser    gosesh.Identifier
		wantErr     string
	}{
		"success": {
			giveContent: []byte(`{"id": "123"}`),
			wantUser:    internal.NewFakeIdentifier("123"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := unmarshalUser(
				func() gosesh.Identifier { return internal.NewFakeIdentifier("") },
			)(tc.giveContent)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantUser, got)
		})
	}
}
