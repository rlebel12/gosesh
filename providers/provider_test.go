package providers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rlebel12/gosesh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func TestNewProvider(t *testing.T) {
	setup := setup(t)
	provider := newProvider(setup.sesh, []string{"identify"}, oauth2.Endpoint{
		AuthURL:   "http://localhost/authorize",
		TokenURL:  "http://localhost/token",
		AuthStyle: oauth2.AuthStyleInParams,
	}, "clientID", "clientSecret", "/callback")

	assert.Equal(t, &oauth2.Config{
		ClientID:     "clientID",
		ClientSecret: "clientSecret",
		RedirectURL:  "http://localhost/callback",
		Scopes:       []string{"identify"},
		Endpoint: oauth2.Endpoint{
			AuthURL:   "http://localhost/authorize",
			TokenURL:  "http://localhost/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}, provider.Config)
}

func TestDoRequest(t *testing.T) {
	for name, tc := range map[string]struct {
		giveMethod    string
		giveContent   []byte
		giveStatus    int
		prepareServer func(s *httptest.Server)
		wantContent   []byte
		wantErr       string
	}{
		"success": {
			giveMethod:  "GET",
			giveContent: []byte("content"),
			giveStatus:  http.StatusOK,
			wantContent: []byte("content"),
		},
		"create request error": {
			giveMethod: "NOT A REAL METHOD",
			wantErr:    "create request",
		},
		"send request error": {
			giveMethod: "GET",
			prepareServer: func(s *httptest.Server) {
				s.Close()
			},
			wantErr: "send request",
		},
		"response not ok": {
			giveMethod:  "GET",
			giveStatus:  http.StatusNotFound,
			giveContent: []byte("content"),
			wantErr:     "response not ok: 404 Not Found",
		},
	} {
		t.Run(name, func(t *testing.T) {
			var gotHeader http.Header
			mux := http.NewServeMux()
			mux.HandleFunc("/endpoint", func(w http.ResponseWriter, r *http.Request) {
				gotHeader = r.Header
				w.WriteHeader(tc.giveStatus)
				_, err := w.Write(tc.giveContent)
				require.NoError(t, err)
			})
			server := httptest.NewServer(mux)
			t.Cleanup(server.Close)
			if tc.prepareServer != nil {
				tc.prepareServer(server)
			}

			got, err := doRequest(tc.giveMethod, server.URL+"/endpoint", http.Header{"Authorization": {"Bearer accessToken"}})

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
			assert.Equal(t, "Bearer accessToken", gotHeader.Get("Authorization"))
		})
	}
}

type fakeUser struct {
	ID string `json:"id"`
}

func (u fakeUser) String() string {
	return u.ID
}

func TestUnmarshalUser(t *testing.T) {
	for name, tc := range map[string]struct {
		giveContent []byte
		wantUser    gosesh.AuthProviderID
		wantErr     string
	}{
		"success": {
			giveContent: []byte(`{"id": "123"}`),
			wantUser:    fakeUser{"123"},
		},
		"unmarshal error": {
			wantErr: "unmarshal user data",
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := unmarshalUser(
				func() fakeUser { return fakeUser{} },
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

func TestDiscordProvider(t *testing.T) {
	testProvider(t,
		func(sesh Gosesher, clientID, clientSecret, redirectPath string) *Discord {
			return NewDiscord(sesh, clientID, clientSecret, redirectPath)
		},
		[]string{"identify"},
		oauth2.Endpoint{
			AuthURL:   "https://discord.com/oauth2/authorize",
			TokenURL:  "https://discord.com/api/oauth2/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	)
}

func TestGoogleProvider(t *testing.T) {
	testProvider(t,
		func(sesh Gosesher, clientID, clientSecret, redirectPath string) *Google {
			return NewGoogle(sesh, clientID, clientSecret, redirectPath)
		},
		[]string{"https://www.googleapis.com/auth/userinfo.email"},
		google.Endpoint,
	)
}

func TestTwitchProvider(t *testing.T) {
	testProvider(t,
		func(sesh Gosesher, clientID, clientSecret, redirectPath string) *Twitch {
			return NewTwitch(sesh, clientID, clientSecret, redirectPath)
		},
		[]string{},
		oauth2.Endpoint{
			AuthURL:   "https://id.twitch.tv/oauth2/authorize",
			TokenURL:  "https://id.twitch.tv/oauth2/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	)
}

func testProvider[P interface {
	OAuth2Begin() http.HandlerFunc
	OAuth2Callback(handler gosesh.HandlerDoneFunc) http.HandlerFunc
	setDoRequest(requestDoer)
	getConfig() *oauth2.Config
}](t *testing.T,
	makeProvider func(sesh Gosesher, clientID, clientSecret, redirectPath string) P,
	wantScopes []string,
	wantEndpoint oauth2.Endpoint,
) {
	setup := setup(t)
	provider := makeProvider(setup.sesh, "clientID", "clientSecret", "/callback")
	prepareProvider(provider)

	t.Run("OAuth2Config", func(t *testing.T) {
		assert := assert.New(t)
		gotConfig := provider.getConfig()
		assert.Equal("clientID", gotConfig.ClientID)
		assert.Equal("clientSecret", gotConfig.ClientSecret)
		assert.Equal("http://localhost/callback", gotConfig.RedirectURL)
		assert.Equal(wantScopes, gotConfig.Scopes)
		assert.Equal(wantEndpoint, gotConfig.Endpoint)
	})

	t.Run("OAuth2Begin", func(t *testing.T) {
		provider.OAuth2Begin().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
		require.NotNil(t, setup.gotBeginCall.cfg)
		assert.Equal(t, "clientID", setup.gotBeginCall.cfg.ClientID)
	})

	t.Run("OAuth2Callback", func(t *testing.T) {
		var gotCalled bool
		var gotErr error
		provider.OAuth2Callback(func(w http.ResponseWriter, r *http.Request, err error) {
			gotErr = err
			gotCalled = true
		}).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
		require.NoError(t, gotErr)
		assert.True(t, gotCalled)
	})
}
