package gosesh

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// fakeIdentifier is a simple test identifier implementation
type fakeIdentifier struct {
	id    string
	email string
}

func (f *fakeIdentifier) ProviderID() string {
	return f.id
}

func (f *fakeIdentifier) String() string {
	return f.id
}

// TestOAuth2BeginCLI_CallbackValidation tests callback URL validation in OAuth2BeginCLI
func TestOAuth2BeginCLI_CallbackValidation(t *testing.T) {
	tests := []struct {
		name         string
		callbackURL  string
		shouldSucceed bool
		expectedCode int
	}{
		{
			name:         "begin_valid_callback_url",
			callbackURL:  "http://localhost:8080/cb",
			shouldSucceed: true,
			expectedCode: http.StatusTemporaryRedirect,
		},
		{
			name:         "begin_callback_with_port",
			callbackURL:  "http://localhost:54321/cb",
			shouldSucceed: true,
			expectedCode: http.StatusTemporaryRedirect,
		},
		{
			name:         "begin_callback_127_0_0_1",
			callbackURL:  "http://127.0.0.1:8080/cb",
			shouldSucceed: true,
			expectedCode: http.StatusTemporaryRedirect,
		},
		{
			name:         "begin_invalid_callback_host",
			callbackURL:  "http://evil.com/cb",
			shouldSucceed: false,
			expectedCode: http.StatusBadRequest,
		},
		{
			name:         "begin_callback_https_localhost",
			callbackURL:  "https://localhost:8080/cb",
			shouldSucceed: false,
			expectedCode: http.StatusBadRequest,
		},
		{
			name:         "begin_missing_callback",
			callbackURL:  "",
			shouldSucceed: false,
			expectedCode: http.StatusBadRequest,
		},
		{
			name:         "begin_callback_malformed",
			callbackURL:  "not-a-url",
			shouldSucceed: false,
			expectedCode: http.StatusBadRequest,
		},
		{
			name:         "begin_callback_with_query",
			callbackURL:  "http://localhost:8080/cb?existing=param",
			shouldSucceed: true,
			expectedCode: http.StatusTemporaryRedirect,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			store := NewMemoryStore()
			sesh := New(store, WithNow(func() time.Time {
				return time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
			}))

			oauthCfg := &oauth2.Config{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				RedirectURL:  "http://localhost/auth/callback/cli",
				Scopes:       []string{"email"},
				Endpoint: oauth2.Endpoint{
					AuthURL:  "http://example.com/auth",
					TokenURL: "http://example.com/token",
				},
			}

			handler := sesh.OAuth2BeginCLI(oauthCfg)
			rr := httptest.NewRecorder()

			reqURL, err := url.Parse("http://localhost/auth/begin/cli")
			require.NoError(err)

			if tt.callbackURL != "" {
				q := reqURL.Query()
				q.Set("callback", tt.callbackURL)
				reqURL.RawQuery = q.Encode()
			}

			req := httptest.NewRequest(http.MethodGet, reqURL.String(), nil)
			handler.ServeHTTP(rr, req)

			assert.Equal(tt.expectedCode, rr.Code)

			if tt.shouldSucceed {
				// Verify redirect to OAuth provider
				location := rr.Header().Get("Location")
				assert.NotEmpty(location)
				assert.Contains(location, "example.com/auth")

				// Verify state cookie is set
				cookies := rr.Result().Cookies()
				var stateCookie *http.Cookie
				for _, c := range cookies {
					if c.Name == sesh.oAuth2StateCookieName {
						stateCookie = c
						break
					}
				}
				require.NotNil(stateCookie, "state cookie should be set")
				assert.NotEmpty(stateCookie.Value)
			}
		})
	}
}

// TestOAuth2BeginCLI_StateHandling tests state cookie handling
func TestOAuth2BeginCLI_StateHandling(t *testing.T) {
	t.Run("begin_sets_state_cookie", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		store := NewMemoryStore()
		originURL, _ := url.Parse("https://localhost")
		sesh := New(store,
			WithNow(func() time.Time { return time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC) }),
			WithOrigin(originURL),
		)

		oauthCfg := &oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			Endpoint: oauth2.Endpoint{
				AuthURL:  "http://example.com/auth",
				TokenURL: "http://example.com/token",
			},
		}

		handler := sesh.OAuth2BeginCLI(oauthCfg)
		rr := httptest.NewRecorder()

		req := httptest.NewRequest(http.MethodGet, "http://localhost/auth/begin/cli?callback=http://localhost:8080/cb", nil)
		handler.ServeHTTP(rr, req)

		assert.Equal(http.StatusTemporaryRedirect, rr.Code)

		// Verify state cookie
		cookies := rr.Result().Cookies()
		var stateCookie *http.Cookie
		for _, c := range cookies {
			if c.Name == sesh.oAuth2StateCookieName {
				stateCookie = c
				break
			}
		}
		require.NotNil(stateCookie)
		assert.True(stateCookie.HttpOnly, "state cookie should be HttpOnly")
		assert.True(stateCookie.Secure, "state cookie should be Secure")
		assert.NotEmpty(stateCookie.Value)
	})

	t.Run("begin_stores_callback_in_state", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		store := NewMemoryStore()
		sesh := New(store, WithNow(func() time.Time {
			return time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
		}))

		oauthCfg := &oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			Endpoint: oauth2.Endpoint{
				AuthURL:  "http://example.com/auth",
				TokenURL: "http://example.com/token",
			},
		}

		handler := sesh.OAuth2BeginCLI(oauthCfg)
		rr := httptest.NewRecorder()

		callbackURL := "http://localhost:8080/cb"
		req := httptest.NewRequest(http.MethodGet, "http://localhost/auth/begin/cli?callback="+url.QueryEscape(callbackURL), nil)
		handler.ServeHTTP(rr, req)

		assert.Equal(http.StatusTemporaryRedirect, rr.Code)

		// Extract state cookie
		cookies := rr.Result().Cookies()
		var stateCookie *http.Cookie
		for _, c := range cookies {
			if c.Name == sesh.oAuth2StateCookieName {
				stateCookie = c
				break
			}
		}
		require.NotNil(stateCookie)

		// Decode state data (it's base64 encoded)
		stateJSON, err := base64.StdEncoding.DecodeString(stateCookie.Value)
		require.NoError(err)

		var stateData CLIStateData
		err = json.Unmarshal(stateJSON, &stateData)
		require.NoError(err)

		assert.NotEmpty(stateData.State, "state should be set")
		assert.Equal(callbackURL, stateData.Callback, "callback URL should be stored in state")
	})
}

// TestOAuth2CallbackCLI_ResponseScenarios tests different OAuth callback scenarios
func TestOAuth2CallbackCLI_ResponseScenarios(t *testing.T) {
	// Setup OAuth2 mock server
	oauth2Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"test-access-token","token_type":"bearer"}`))
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"user123","email":"test@example.com"}`))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer oauth2Server.Close()

	tests := []struct {
		name          string
		oauthResponse string // Query params for OAuth callback
		setupState    bool   // Whether to set valid state cookie
		stateMatch    bool   // Whether state should match
		expectedCode  int
		checkRedirect func(t *testing.T, location string)
	}{
		{
			name:          "callback_valid_flow",
			oauthResponse: "?code=valid-auth-code",
			setupState:    true,
			stateMatch:    true,
			expectedCode:  http.StatusTemporaryRedirect,
			checkRedirect: func(t *testing.T, location string) {
				assert.Contains(t, location, "http://localhost:8080/cb")
				assert.Contains(t, location, "token=")
			},
		},
		{
			name:          "callback_invalid_state",
			oauthResponse: "?code=valid-auth-code",
			setupState:    true,
			stateMatch:    false,
			expectedCode:  http.StatusBadRequest,
			checkRedirect: nil,
		},
		{
			name:          "callback_oauth_error",
			oauthResponse: "?error=access_denied",
			setupState:    true,
			stateMatch:    true,
			expectedCode:  http.StatusTemporaryRedirect,
			checkRedirect: func(t *testing.T, location string) {
				assert.Contains(t, location, "http://localhost:8080/cb")
				assert.Contains(t, location, "error=access_denied")
			},
		},
		{
			name:          "callback_oauth_error_desc",
			oauthResponse: "?error=access_denied&error_description=User%20denied",
			setupState:    true,
			stateMatch:    true,
			expectedCode:  http.StatusTemporaryRedirect,
			checkRedirect: func(t *testing.T, location string) {
				assert.Contains(t, location, "http://localhost:8080/cb")
				assert.Contains(t, location, "error=access_denied")
				assert.Contains(t, location, "error_description=User")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			store := NewMemoryStore()
			sesh := New(store, WithNow(func() time.Time {
				return time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
			}))

			oauthCfg := &oauth2.Config{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				Endpoint: oauth2.Endpoint{
					AuthURL:  oauth2Server.URL + "/auth",
					TokenURL: oauth2Server.URL + "/token",
				},
			}

			request := func(ctx context.Context, accessToken string) (io.ReadCloser, error) {
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, oauth2Server.URL+"/userinfo", nil)
				req.Header.Set("Authorization", "Bearer "+accessToken)
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					return nil, err
				}
				return resp.Body, nil
			}

			unmarshal := func(b []byte) (Identifier, error) {
				var data struct {
					ID    string `json:"id"`
					Email string `json:"email"`
				}
				if err := json.Unmarshal(b, &data); err != nil {
					return nil, err
				}
				return &fakeIdentifier{id: data.ID, email: data.Email}, nil
			}

			handler := sesh.OAuth2CallbackCLI(oauthCfg, request, unmarshal)
			rr := httptest.NewRecorder()

			callbackURL := "http://localhost:8080/cb"
			stateValue := "test-state-value"

			// Setup state cookie
			var req *http.Request
			if tt.setupState {
				stateData := CLIStateData{
					State:    stateValue,
					Callback: callbackURL,
				}
				stateJSON, _ := json.Marshal(stateData)
				stateEncoded := base64.StdEncoding.EncodeToString(stateJSON)

				reqURL := fmt.Sprintf("http://localhost/auth/callback/cli%s", tt.oauthResponse)
				if tt.stateMatch {
					reqURL += "&state=" + stateValue
				} else {
					reqURL += "&state=wrong-state"
				}

				req = httptest.NewRequest(http.MethodGet, reqURL, nil)
				req.AddCookie(&http.Cookie{
					Name:  sesh.oAuth2StateCookieName,
					Value: stateEncoded,
				})
			} else {
				reqURL := fmt.Sprintf("http://localhost/auth/callback/cli%s", tt.oauthResponse)
				req = httptest.NewRequest(http.MethodGet, reqURL, nil)
			}

			handler.ServeHTTP(rr, req)

			assert.Equal(tt.expectedCode, rr.Code)

			if tt.checkRedirect != nil {
				location := rr.Header().Get("Location")
				require.NotEmpty(location)
				tt.checkRedirect(t, location)
			}
		})
	}
}

// TestOAuth2CallbackCLI_SessionCreation tests session creation with CLI config
func TestOAuth2CallbackCLI_SessionCreation(t *testing.T) {
	// Setup OAuth2 mock server
	oauth2Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"test-access-token","token_type":"bearer"}`))
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"user123","email":"test@example.com"}`))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer oauth2Server.Close()

	t.Run("callback_creates_session", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		store := NewMemoryStore()
		sesh := New(store, WithNow(func() time.Time {
			return time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
		}))

		oauthCfg := &oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			Endpoint: oauth2.Endpoint{
				AuthURL:  oauth2Server.URL + "/auth",
				TokenURL: oauth2Server.URL + "/token",
			},
		}

		request := func(ctx context.Context, accessToken string) (io.ReadCloser, error) {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, oauth2Server.URL+"/userinfo", nil)
			req.Header.Set("Authorization", "Bearer "+accessToken)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return nil, err
			}
			return resp.Body, nil
		}

		unmarshal := func(b []byte) (Identifier, error) {
			var data struct {
				ID    string `json:"id"`
				Email string `json:"email"`
			}
			if err := json.Unmarshal(b, &data); err != nil {
				return nil, err
			}
			return &fakeIdentifier{id: data.ID, email: data.Email}, nil
		}

		handler := sesh.OAuth2CallbackCLI(oauthCfg, request, unmarshal)
		rr := httptest.NewRecorder()

		callbackURL := "http://localhost:8080/cb"
		stateValue := "test-state-value"
		stateData := CLIStateData{
			State:    stateValue,
			Callback: callbackURL,
		}
		stateJSON, _ := json.Marshal(stateData)
		stateEncoded := base64.StdEncoding.EncodeToString(stateJSON)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/auth/callback/cli?code=valid-code&state="+stateValue, nil)
		req.AddCookie(&http.Cookie{
			Name:  sesh.oAuth2StateCookieName,
			Value: stateEncoded,
		})

		handler.ServeHTTP(rr, req)

		assert.Equal(http.StatusTemporaryRedirect, rr.Code)

		// Verify session was created in store
		// Extract token from redirect URL
		location := rr.Header().Get("Location")
		require.NotEmpty(location)

		locURL, err := url.Parse(location)
		require.NoError(err)

		token := locURL.Query().Get("token")
		require.NotEmpty(token, "token should be present in redirect URL")

		// Verify session exists in store
		ctx := context.Background()
		session, err := store.GetSession(ctx, token)
		require.NoError(err)
		require.NotNil(session)
	})

	t.Run("callback_session_config", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		store := NewMemoryStore()
		now := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
		sesh := New(store, WithNow(func() time.Time { return now }))

		oauthCfg := &oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			Endpoint: oauth2.Endpoint{
				AuthURL:  oauth2Server.URL + "/auth",
				TokenURL: oauth2Server.URL + "/token",
			},
		}

		request := func(ctx context.Context, accessToken string) (io.ReadCloser, error) {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, oauth2Server.URL+"/userinfo", nil)
			req.Header.Set("Authorization", "Bearer "+accessToken)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return nil, err
			}
			return resp.Body, nil
		}

		unmarshal := func(b []byte) (Identifier, error) {
			var data struct {
				ID    string `json:"id"`
				Email string `json:"email"`
			}
			if err := json.Unmarshal(b, &data); err != nil {
				return nil, err
			}
			return &fakeIdentifier{id: data.ID, email: data.Email}, nil
		}

		handler := sesh.OAuth2CallbackCLI(oauthCfg, request, unmarshal)
		rr := httptest.NewRecorder()

		callbackURL := "http://localhost:8080/cb"
		stateValue := "test-state-value"
		stateData := CLIStateData{
			State:    stateValue,
			Callback: callbackURL,
		}
		stateJSON, _ := json.Marshal(stateData)
		stateEncoded := base64.StdEncoding.EncodeToString(stateJSON)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/auth/callback/cli?code=valid-code&state="+stateValue, nil)
		req.AddCookie(&http.Cookie{
			Name:  sesh.oAuth2StateCookieName,
			Value: stateEncoded,
		})

		handler.ServeHTTP(rr, req)

		assert.Equal(http.StatusTemporaryRedirect, rr.Code)

		// Extract token and verify session config
		location := rr.Header().Get("Location")
		require.NotEmpty(location)

		locURL, err := url.Parse(location)
		require.NoError(err)

		token := locURL.Query().Get("token")
		require.NotEmpty(token)

		ctx := context.Background()
		session, err := store.GetSession(ctx, token)
		require.NoError(err)

		// CLI sessions should have 30-day absolute timeout, no idle timeout
		expectedAbsolute := now.Add(30 * 24 * time.Hour)
		assert.Equal(expectedAbsolute, session.AbsoluteDeadline(), "session should have 30-day absolute timeout")

		// Note: IdleDeadline being same as AbsoluteDeadline indicates no idle timeout
		// This is the expected behavior for CLI sessions
	})

	t.Run("callback_token_param_name", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		store := NewMemoryStore()
		sesh := New(store, WithNow(func() time.Time {
			return time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
		}))

		oauthCfg := &oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			Endpoint: oauth2.Endpoint{
				AuthURL:  oauth2Server.URL + "/auth",
				TokenURL: oauth2Server.URL + "/token",
			},
		}

		request := func(ctx context.Context, accessToken string) (io.ReadCloser, error) {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, oauth2Server.URL+"/userinfo", nil)
			req.Header.Set("Authorization", "Bearer "+accessToken)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return nil, err
			}
			return resp.Body, nil
		}

		unmarshal := func(b []byte) (Identifier, error) {
			var data struct {
				ID    string `json:"id"`
				Email string `json:"email"`
			}
			if err := json.Unmarshal(b, &data); err != nil {
				return nil, err
			}
			return &fakeIdentifier{id: data.ID, email: data.Email}, nil
		}

		handler := sesh.OAuth2CallbackCLI(oauthCfg, request, unmarshal)
		rr := httptest.NewRecorder()

		callbackURL := "http://localhost:8080/cb"
		stateValue := "test-state-value"
		stateData := CLIStateData{
			State:    stateValue,
			Callback: callbackURL,
		}
		stateJSON, _ := json.Marshal(stateData)
		stateEncoded := base64.StdEncoding.EncodeToString(stateJSON)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/auth/callback/cli?code=valid-code&state="+stateValue, nil)
		req.AddCookie(&http.Cookie{
			Name:  sesh.oAuth2StateCookieName,
			Value: stateEncoded,
		})

		handler.ServeHTTP(rr, req)

		assert.Equal(http.StatusTemporaryRedirect, rr.Code)

		// Verify token is in query param, not in fragment or cookie
		location := rr.Header().Get("Location")
		require.NotEmpty(location)

		locURL, err := url.Parse(location)
		require.NoError(err)

		// Token should be in query parameter named "token"
		token := locURL.Query().Get("token")
		assert.NotEmpty(token, "token should be in query parameter")

		// Token should NOT be in fragment
		assert.Empty(locURL.Fragment, "token should not be in URL fragment")

		// Token should NOT be set as cookie
		cookies := rr.Result().Cookies()
		for _, c := range cookies {
			assert.NotEqual("token", c.Name, "token should not be set as cookie")
		}
	})
}
