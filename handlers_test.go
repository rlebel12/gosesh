package gosesh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"golang.org/x/oauth2"
)

func TestOAuth2Begin(t *testing.T) {
	for name, test := range map[string]struct {
		secure        bool
		next          string
		cookieAsserts []func(t *testing.T, cookie *http.Cookie)
	}{
		"insecure": {cookieAsserts: []func(t *testing.T, cookie *http.Cookie){
			func(t *testing.T, cookie *http.Cookie) {
				assert := assert.New(t)
				assert.Equal("customStateName", cookie.Name)
				assert.Equal(time.Date(2021, 1, 1, 0, 5, 0, 0, time.UTC), cookie.Expires)
				assert.Equal("localhost", cookie.Domain)
				assert.Equal("/", cookie.Path)
				assert.Equal(http.SameSiteLaxMode, cookie.SameSite)
				assert.False(cookie.Secure)
				assert.NotEmpty(cookie.Value)
			},
		}},
		"secure": {secure: true, cookieAsserts: []func(t *testing.T, cookie *http.Cookie){
			func(t *testing.T, cookie *http.Cookie) {
				assert := assert.New(t)
				assert.Equal("customStateName", cookie.Name)
				assert.Equal(time.Date(2021, 1, 1, 0, 5, 0, 0, time.UTC), cookie.Expires)
				assert.Equal("localhost", cookie.Domain)
				assert.Equal("/", cookie.Path)
				assert.Equal(http.SameSiteLaxMode, cookie.SameSite)
				assert.True(cookie.Secure)
				assert.NotEmpty(cookie.Value)
			},
		}},
		"next": {next: "/next", cookieAsserts: []func(t *testing.T, cookie *http.Cookie){
			func(t *testing.T, cookie *http.Cookie) {
				assert := assert.New(t)
				assert.Equal("customStateName", cookie.Name)
				assert.Equal(time.Date(2021, 1, 1, 0, 5, 0, 0, time.UTC), cookie.Expires)
				assert.Equal("localhost", cookie.Domain)
				assert.Equal("/", cookie.Path)
				assert.Equal(http.SameSiteLaxMode, cookie.SameSite)
				assert.False(cookie.Secure)
				assert.NotEmpty(cookie.Value)
			},
			func(t *testing.T, cookie *http.Cookie) {
				assert := assert.New(t)
				assert.Equal("customRedirectName", cookie.Name)
				assert.Equal("L25leHQ=", cookie.Value)
				assert.Equal(time.Date(2021, 1, 1, 0, 5, 0, 0, time.UTC), cookie.Expires)
				assert.Equal("localhost", cookie.Domain)
				assert.Equal("/", cookie.Path)
				assert.Equal(http.SameSiteLaxMode, cookie.SameSite)
				assert.False(cookie.Secure)
			},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			opts := []NewOpts{
				WithNow(func() time.Time { return time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC) }),
				WithOAuth2StateCookieName("customStateName"),
				WithRedirectCookieName("customRedirectName"),
				WithRedirectParamName("customRedirectParam"),
			}
			if test.secure {
				url, err := url.Parse("https://localhost")
				require.NoError(err)
				opts = append(opts, WithOrigin(url))
			}
			sesh := New(nil, nil, opts...)
			handler := sesh.OAuth2Begin(&oauth2.Config{
				ClientID:     "client_id",
				ClientSecret: "client_secret",
				RedirectURL:  "http://localhost/auth/callback",
				Scopes:       []string{"email"},
				Endpoint: oauth2.Endpoint{
					AuthURL:   "http://localhost/auth",
					TokenURL:  "http://localhost/token",
					AuthStyle: oauth2.AuthStyleInParams,
				},
			})
			rr := httptest.NewRecorder()
			url, err := url.Parse("http://localhost")
			params := url.Query()
			params.Add("customRedirectParam", test.next)
			url.RawQuery = params.Encode()
			require.NoError(err)

			handler.ServeHTTP(rr, &http.Request{
				URL: url,
			})

			response := rr.Result()
			assert.Equal(http.StatusTemporaryRedirect, response.StatusCode)
			assert.Len(response.Cookies(), len(test.cookieAsserts))
			for i, gotCookie := range response.Cookies() {
				test.cookieAsserts[i](t, gotCookie)
			}
			gotLocation, err := url.Parse(response.Header.Get("Location"))
			require.NoError(err)
			assert.Equal("http", gotLocation.Scheme)
			assert.Equal("localhost", gotLocation.Hostname())
			assert.Equal("/auth", gotLocation.Path)
			assert.Equal("client_id", gotLocation.Query().Get("client_id"))
			assert.Equal("http://localhost/auth/callback", gotLocation.Query().Get("redirect_uri"))
			assert.Equal("code", gotLocation.Query().Get("response_type"))
			assert.Equal("email", gotLocation.Query().Get("scope"))
			assert.NotEmpty(gotLocation.Query().Get("state"))

			assert.Equal(`private, no-cache="Set-Cookie"`, response.Header.Get("Cache-Control"))
			assert.Equal("Cookie", response.Header.Get("Vary"))
		})
	}
}

type Oauth2CallbackHandlerSuite struct {
	suite.Suite
	oauth2Server *httptest.Server
	now          time.Time
	withNow      func() time.Time
}

func (s *Oauth2CallbackHandlerSuite) SetupSuite() {
	s.oauth2Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_, err := w.Write([]byte(`{"access_token":"access_token","token_type":"bearer","refresh_token":"refresh_token","expiry":"2021-01-01T00:00:00Z"}`))
			s.Require().NoError(err)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	s.now = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	s.withNow = func() time.Time { return s.now }
}

func (s *Oauth2CallbackHandlerSuite) TearDownSuite() {
	s.oauth2Server.Close()
}

func (s *Oauth2CallbackHandlerSuite) SetupTest() {

}

type testCallbackRequestMode int

const (
	testCallbackSuccess testCallbackRequestMode = iota
	testCallbackErrNoStateCookie
	testCallbackInvalidStateCookie
	testFailedExchange
	testFailedUnmarshalRequest
	testFailedUnmarshalReadBody
	testFailedUnmarshalDataFinal
	testCallbackErrUpsertUser
	testCallbackErrCreateSession
)

type failReader struct{}

func (m *failReader) Read(p []byte) (n int, err error) {
	return 0, fmt.Errorf("failed read")
}

func (s *Oauth2CallbackHandlerSuite) prepareTest(
	mode testCallbackRequestMode) (r *http.Request, config *oauth2.Config, user *OAuth2UserMock, store *StorerMock,
) {
	var err error
	callbackURL := fmt.Sprintf("%s/auth/callback", s.oauth2Server.URL)
	r, err = http.NewRequest(http.MethodGet, callbackURL, nil)
	s.Require().NoError(err)

	if mode == testCallbackErrNoStateCookie {
		return
	}
	r.AddCookie(&http.Cookie{
		Name:  "oauthstate",
		Value: "ZGV0ZXJtaW5pc3RpYyByYQ==",
	})

	if mode == testCallbackInvalidStateCookie {
		return
	}
	urlValues := url.Values{}
	urlValues.Add("state", "ZGV0ZXJtaW5pc3RpYyByYQ==")
	urlValues.Add("code", "code")
	urlValuesEncoded := urlValues.Encode()
	r.URL.RawQuery = urlValuesEncoded
	config = &oauth2.Config{
		ClientID:     "client_id",
		ClientSecret: "client_secret",
		RedirectURL:  callbackURL,
		Scopes:       []string{"email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:   fmt.Sprintf("%s/auth", s.oauth2Server.URL),
			TokenURL:  fmt.Sprintf("%s/fail-exchange", s.oauth2Server.URL),
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}

	if mode == testFailedExchange {
		return
	}
	config.Endpoint.TokenURL = fmt.Sprintf("%s/token", s.oauth2Server.URL)
	user = &OAuth2UserMock{}

	if mode == testFailedUnmarshalRequest {
		user.RequestFunc = func(ctx context.Context, accessToken string) (*http.Response, error) {
			return nil, errors.New("test error")
		}
		return
	}

	if mode == testFailedUnmarshalReadBody {
		response := &http.Response{
			Body: io.NopCloser(&failReader{}),
		}
		user.RequestFunc = func(ctx context.Context, accessToken string) (*http.Response, error) {
			return response, nil
		}
		return
	}
	response := &http.Response{
		Body: io.NopCloser(strings.NewReader("")),
	}
	user.RequestFunc = func(ctx context.Context, accessToken string) (*http.Response, error) {
		return response, nil
	}

	if mode == testFailedUnmarshalDataFinal {
		user.UnmarshalFunc = func(b []byte) error {
			return fmt.Errorf("failed unmarshal")
		}
		return
	}

	user.UnmarshalFunc = func(b []byte) error {
		return nil
	}
	user.StringFunc = func() string {
		return "user"
	}
	store = &StorerMock{}
	if mode == testCallbackErrUpsertUser {
		store.UpsertUserFunc = func(ctx context.Context, user OAuth2User) (Identifier, error) {
			return nil, fmt.Errorf("failed upsert")
		}
		return
	}
	identifier := &IdentifierMock{}
	identifier.StringFunc = func() string {
		return "identifier"
	}
	store.UpsertUserFunc = func(ctx context.Context, user OAuth2User) (Identifier, error) {
		return identifier, nil
	}
	// createSessionRequest := CreateSessionRequest{
	// 	UserID:   identifier,
	// 	IdleAt:   s.now.Add(1 * time.Hour),
	// 	ExpireAt: s.now.Add(24 * time.Hour),
	// }

	if mode == testCallbackErrCreateSession {
		store.CreateSessionFunc = func(ctx context.Context, req CreateSessionRequest) (Session, error) {
			return nil, fmt.Errorf("failed create session")
		}
		return
	}

	session := &SessionMock{}
	session.IDFunc = func() Identifier {
		return identifier
	}
	session.ExpireAtFunc = func() time.Time {
		return s.now.Add(24 * time.Hour)
	}
	store.CreateSessionFunc = func(ctx context.Context, req CreateSessionRequest) (Session, error) {
		return session, nil
	}

	return
}

func (s *Oauth2CallbackHandlerSuite) errCallback(errString string) func(w http.ResponseWriter, r *http.Request, err error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		s.EqualError(err, errString)
	}
}

func (s *Oauth2CallbackHandlerSuite) TestErrNoStateCookie() {
	rr := httptest.NewRecorder()
	sesh := New(nil, nil, WithNow(s.withNow))
	request, config, _, _ := s.prepareTest(testCallbackErrNoStateCookie)
	sesh.OAuth2Callback(
		nil,
		config,
		s.errCallback("failed getting state cookie: http: named cookie not present"),
	).ServeHTTP(rr, request)
	response := rr.Result()
	s.Equal(`private, no-cache="Set-Cookie"`, response.Header.Get("Cache-Control"))
	s.Equal("Cookie", response.Header.Get("Vary"))
}

func (s *Oauth2CallbackHandlerSuite) TestErrInvalidStateCookie() {
	rr := httptest.NewRecorder()
	sesh := New(nil, nil, WithNow(s.withNow))
	request, config, _, _ := s.prepareTest(testCallbackInvalidStateCookie)
	sesh.OAuth2Callback(
		nil,
		config,
		s.errCallback("invalid state cookie"),
	).ServeHTTP(rr, request)
	s.assertCommonResponse(rr.Result())
}

func (s *Oauth2CallbackHandlerSuite) TestFailedExchange() {
	rr := httptest.NewRecorder()
	sesh := New(nil, nil, WithNow(s.withNow))
	request, config, _, _ := s.prepareTest(testFailedExchange)
	sesh.OAuth2Callback(
		nil,
		config,
		s.errCallback("failed exchanging token: oauth2: cannot fetch token: 404 Not Found\nResponse: not found\n"),
	).ServeHTTP(rr, request)
	s.assertCommonResponse(rr.Result())
}

func (s *Oauth2CallbackHandlerSuite) TestFailUnmarshalUserDataRequest() {
	rr := httptest.NewRecorder()
	sesh := New(nil, nil, WithNow(s.withNow))
	request, config, user, _ := s.prepareTest(testFailedUnmarshalRequest)
	sesh.OAuth2Callback(
		user,
		config,
		s.errCallback("failed unmarshalling data: failed getting user info: test error"),
	).ServeHTTP(rr, request)
	s.assertCommonResponse(rr.Result())
}

func (s *Oauth2CallbackHandlerSuite) TestFailUnmarshalUserDataReadBody() {
	rr := httptest.NewRecorder()
	sesh := New(nil, nil, WithNow(s.withNow))
	request, config, user, _ := s.prepareTest(testFailedUnmarshalReadBody)
	sesh.OAuth2Callback(
		user,
		config,
		s.errCallback("failed unmarshalling data: failed read response: failed read"),
	).ServeHTTP(rr, request)
	s.assertCommonResponse(rr.Result())
}

func (s *Oauth2CallbackHandlerSuite) TestFailUnmarshalDataFinal() {
	rr := httptest.NewRecorder()
	sesh := New(nil, nil, WithNow(s.withNow))
	request, config, user, _ := s.prepareTest(testFailedUnmarshalDataFinal)
	sesh.OAuth2Callback(
		user,
		config,
		s.errCallback("failed unmarshalling data: failed unmarshal"),
	).ServeHTTP(rr, request)
	s.assertCommonResponse(rr.Result())
}

func (s *Oauth2CallbackHandlerSuite) TestCallbackErrUpsertUser() {
	request, config, user, store := s.prepareTest(testCallbackErrUpsertUser)
	rr := httptest.NewRecorder()
	sesh := New(nil, store, WithNow(s.withNow))
	sesh.OAuth2Callback(
		user,
		config,
		s.errCallback("failed upserting user: failed upsert"),
	).ServeHTTP(rr, request)
	s.assertCommonResponse(rr.Result())
}

func (s *Oauth2CallbackHandlerSuite) TestCallbackErrCreateSession() {
	request, config, user, store := s.prepareTest(testCallbackErrCreateSession)
	rr := httptest.NewRecorder()
	sesh := New(nil, store, WithNow(s.withNow))
	sesh.OAuth2Callback(
		user,
		config,
		s.errCallback("failed creating session: failed create session"),
	).ServeHTTP(rr, request)
	s.assertCommonResponse(rr.Result())
}

func (s *Oauth2CallbackHandlerSuite) TestCallbackSuccess() {
	request, config, user, store := s.prepareTest(testCallbackSuccess)
	rr := httptest.NewRecorder()
	sesh := New(nil, store, WithNow(s.withNow))

	var success bool
	sesh.OAuth2Callback(user, config, func(w http.ResponseWriter, r *http.Request, err error) {
		s.NoError(err)
		success = true
		w.WriteHeader(http.StatusOK)
	})(rr, request)

	s.True(success)
	response := rr.Result()
	s.Equal(2, len(response.Cookies()))
	sessionCookie := response.Cookies()[1]
	s.Equal("session", sessionCookie.Name)
	s.Equal("aWRlbnRpZmllcg==", sessionCookie.Value)
	s.Equal(s.now.Add(24*time.Hour), sessionCookie.Expires)
	s.Equal("localhost", sessionCookie.Domain)
	s.Equal("/", sessionCookie.Path)
	s.Equal(http.SameSiteLaxMode, sessionCookie.SameSite)
	s.False(sessionCookie.Secure)
	s.assertCommonResponse(response)
}

func (s *Oauth2CallbackHandlerSuite) assertCommonResponse(response *http.Response) {
	cookie := response.Cookies()[0]
	s.Equal("oauthstate", cookie.Name)
	s.Equal("", cookie.Value)
	s.Equal(s.now, cookie.Expires)
	s.Equal("localhost", cookie.Domain)
	s.Equal("/", cookie.Path)
	s.Equal(http.SameSiteLaxMode, cookie.SameSite)
	s.False(cookie.Secure)
	s.Equal(`private, no-cache="Set-Cookie"`, response.Header.Get("Cache-Control"))
	s.Equal("Cookie", response.Header.Get("Vary"))
}

func TestOauth2CallbackHandlerSuite(t *testing.T) {
	suite.Run(t, new(Oauth2CallbackHandlerSuite))
}

type logoutTest struct {
	now        func() time.Time
	store      *StorerMock
	parser     IDParser
	r          *http.Request
	sesh       *Gosesh
	w          *httptest.ResponseRecorder
	identifier *IdentifierMock
	session    *SessionMock
}

func prepareLogoutTest(t *testing.T) (test *logoutTest) {
	now := func() time.Time { return time.Now() }
	store := &StorerMock{}
	r, err := http.NewRequest(http.MethodGet, "/", nil)
	require.NoError(t, err)
	sesh := New(
		func(b []byte) (Identifier, error) { return test.parser(b) },
		store,
		WithNow(now),
	)
	rr := httptest.NewRecorder()
	identifier := &IdentifierMock{}

	test = new(logoutTest)
	test.now = now
	test.store = store
	test.r = r
	test.sesh = sesh
	test.w = rr
	test.identifier = identifier
	test.session = &SessionMock{}
	return
}

func (t *logoutTest) execute() {
	t.sesh.Logout(nil).ServeHTTP(t.w, t.r)
}

func (t *logoutTest) setValidCOokie() {
	t.r.AddCookie(&http.Cookie{
		Name:  "session",
		Value: "aWRlbnRpZmllcg==",
	})
}

func (t *logoutTest) succeedParsingID() {
	t.setValidCOokie()
	t.identifier.StringFunc = func() string {
		return "identifier"
	}
	t.parser = func(b []byte) (Identifier, error) {
		return t.identifier, nil
	}
}

func (t *logoutTest) authenticated(test *testing.T) *http.Request {
	original := t.r
	t.identifier.StringFunc = func() string {
		return "identifier"
	}
	ctx := context.WithValue(t.r.Context(), SessionContextKey, t.session)
	t.r = t.r.WithContext(ctx)
	return original
}

func TestLogoutHandler(t *testing.T) {
	assert := assert.New(t)

	t.Run("no session cookie", func(t *testing.T) {
		test := prepareLogoutTest(t)
		test.execute()
		assert.Equal(http.StatusUnauthorized, test.w.Code)
	})

	t.Run("bad session cookie", func(t *testing.T) {
		test := prepareLogoutTest(t)

		test.r.AddCookie(&http.Cookie{
			Name:  "session",
			Value: "bad",
		})
		test.execute()
		assert.Equal(http.StatusUnauthorized, test.w.Code)
	})

	t.Run("failed parsing ID", func(t *testing.T) {
		test := prepareLogoutTest(t)

		test.setValidCOokie()
		test.parser = func(b []byte) (Identifier, error) {
			return nil, fmt.Errorf("failed parse")
		}
		test.execute()
		assert.Equal(http.StatusUnauthorized, test.w.Code)
	})

	t.Run("failed getting session", func(t *testing.T) {
		test := prepareLogoutTest(t)
		test.succeedParsingID()
		test.store.GetSessionFunc = func(ctx context.Context, id Identifier) (Session, error) {
			return nil, fmt.Errorf("failed get session")
		}

		test.execute()
		assert.Equal(http.StatusUnauthorized, test.w.Code)
	})

	t.Run("session expired", func(t *testing.T) {
		test := prepareLogoutTest(t)
		test.succeedParsingID()
		session := &SessionMock{}
		session.ExpireAtFunc = func() time.Time {
			return test.now().UTC().Add(-1 * time.Hour)
		}
		test.store.GetSessionFunc = func(ctx context.Context, id Identifier) (Session, error) {
			return session, nil
		}

		test.execute()
		assert.Equal(http.StatusUnauthorized, test.w.Code)
	})

	t.Run("failed deleting one session", func(t *testing.T) {
		test := prepareLogoutTest(t)

		test.authenticated(t)
		test.session.IDFunc = func() Identifier {
			return test.identifier
		}
		err := fmt.Errorf("failed delete session")
		test.store.DeleteSessionFunc = func(ctx context.Context, id Identifier) error {
			return err
		}

		test.execute()
		assert.Equal(http.StatusInternalServerError, test.w.Code)
	})

	t.Run("failed deleting all sessions", func(t *testing.T) {
		test := prepareLogoutTest(t)

		test.authenticated(t)
		test.session.UserIDFunc = func() Identifier {
			return test.identifier
		}

		err := fmt.Errorf("failed delete session")
		test.store.DeleteUserSessionsFunc = func(ctx context.Context, id Identifier) (int, error) {
			return 0, err
		}

		urlValues := url.Values{}
		urlValues.Add("all", "true")
		test.r.URL.RawQuery = urlValues.Encode()

		test.execute()
		assert.Equal(http.StatusInternalServerError, test.w.Code)
	})

	t.Run("success deleting one session", func(t *testing.T) {
		test := prepareLogoutTest(t)

		test.authenticated(t)
		test.session.IDFunc = func() Identifier {
			return test.identifier
		}
		test.store.DeleteSessionFunc = func(ctx context.Context, id Identifier) error {
			return nil
		}

		test.execute()
		assert.Equal(http.StatusTemporaryRedirect, test.w.Code)
	})

	t.Run("success deleting all sessions", func(t *testing.T) {
		test := prepareLogoutTest(t)

		test.authenticated(t)
		test.session.UserIDFunc = func() Identifier {
			return test.identifier
		}
		test.store.DeleteUserSessionsFunc = func(ctx context.Context, id Identifier) (int, error) {
			return 0, nil
		}

		urlValues := url.Values{}
		urlValues.Add("all", "true")
		test.r.URL.RawQuery = urlValues.Encode()

		test.execute()
		assert.Equal(http.StatusTemporaryRedirect, test.w.Code)
	})
}

func TestCallbackRedirect(t *testing.T) {
	for name, test := range map[string]struct {
		giveDefaultTarget string
		giveCookies       []*http.Cookie
		giveAllowedHosts  []string
		wantLocation      string
		cookieAsserts     []func(t *testing.T, cookie *http.Cookie)
	}{
		"no redirect cookie": {
			wantLocation: "/",
		},
		"no redirect cookie custom target": {
			giveDefaultTarget: "/custom",
			wantLocation:      "/custom",
		},
		"valid redirect cookie": {
			giveCookies: []*http.Cookie{
				{
					Name:  "redirect",
					Value: "L25leHQ=",
				},
			},
			wantLocation: "/next",
			cookieAsserts: []func(t *testing.T, cookie *http.Cookie){
				func(t *testing.T, cookie *http.Cookie) {
					assert := assert.New(t)
					assert.Equal("redirect", cookie.Name)
					assert.Equal("", cookie.Value)
					assert.Equal(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), cookie.Expires)
					assert.Equal("localhost", cookie.Domain)
					assert.Equal("/", cookie.Path)
					assert.Equal(http.SameSiteLaxMode, cookie.SameSite)
					assert.False(cookie.Secure)
				},
			},
		},
		"invalid redirect cookie": {
			giveCookies: []*http.Cookie{
				{
					Name:  "redirect",
					Value: "invalid",
				},
			},
			wantLocation: "/",
			cookieAsserts: []func(t *testing.T, cookie *http.Cookie){
				func(t *testing.T, cookie *http.Cookie) {
					assert := assert.New(t)
					assert.Equal("redirect", cookie.Name)
					assert.Equal("", cookie.Value)
					assert.Equal(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), cookie.Expires)
					assert.Equal("localhost", cookie.Domain)
					assert.Equal("/", cookie.Path)
					assert.Equal(http.SameSiteLaxMode, cookie.SameSite)
					assert.False(cookie.Secure)
				},
			},
		},
		"disallowed host": {
			giveCookies: []*http.Cookie{
				{
					Name:  "redirect",
					Value: "aHR0cDovL2V4YW1wbGUuY29t",
				},
			},
			wantLocation: "/",
			cookieAsserts: []func(t *testing.T, cookie *http.Cookie){
				func(t *testing.T, cookie *http.Cookie) {
					assert := assert.New(t)
					assert.Equal("redirect", cookie.Name)
					assert.Equal("", cookie.Value)
					assert.Equal(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), cookie.Expires)
					assert.Equal("localhost", cookie.Domain)
					assert.Equal("/", cookie.Path)
					assert.Equal(http.SameSiteLaxMode, cookie.SameSite)
					assert.False(cookie.Secure)
				},
			},
		},
		"allowed host": {
			giveCookies: []*http.Cookie{
				{
					Name:  "redirect",
					Value: "aHR0cHM6Ly9leGFtcGxlLmNvbS9mb28=",
				},
			},
			giveAllowedHosts: []string{"example.com"},
			wantLocation:     "https://example.com/foo",
			cookieAsserts: []func(t *testing.T, cookie *http.Cookie){
				func(t *testing.T, cookie *http.Cookie) {
					assert := assert.New(t)
					assert.Equal("redirect", cookie.Name)
					assert.Equal("", cookie.Value)
					assert.Equal(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), cookie.Expires)
					assert.Equal("localhost", cookie.Domain)
					assert.Equal("/", cookie.Path)
					assert.Equal(http.SameSiteLaxMode, cookie.SameSite)
					assert.False(cookie.Secure)
				},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			store := &StorerMock{}
			sesh := New(func(b []byte) (Identifier, error) {
				return &IdentifierMock{StringFunc: func() string { return "identifier" }}, nil
			}, store,
				WithNow(func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }),
				WithAllowedHosts(test.giveAllowedHosts...),
			)

			r, err := http.NewRequest(http.MethodGet, "/", nil)
			require.NoError(err)
			for _, cookie := range test.giveCookies {
				r.AddCookie(cookie)
			}
			rr := httptest.NewRecorder()

			sesh.CallbackRedirect(test.giveDefaultTarget).ServeHTTP(rr, r)

			assert.Equal(http.StatusTemporaryRedirect, rr.Result().StatusCode)
			assert.Equal(test.wantLocation, rr.Result().Header.Get("Location"))
			gotCookies := rr.Result().Cookies()
			assert.Len(gotCookies, len(test.cookieAsserts))
			for i, gotCookie := range gotCookies {
				test.cookieAsserts[i](t, gotCookie)
			}
		})
	}
}
