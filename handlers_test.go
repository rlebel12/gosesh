package gosesh

import (
	"context"
	"encoding/json"
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
			sesh := New(nil, opts...)
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
	mode testCallbackRequestMode,
) (r *http.Request, config *oauth2.Config, user Identifier, store *erroringStore, requestFunc RequestFunc, unmarshalFunc UnmarshalFunc) {
	var err error
	callbackURL := fmt.Sprintf("%s/auth/callback", s.oauth2Server.URL)
	r, err = http.NewRequest(http.MethodGet, callbackURL, nil)
	s.Require().NoError(err)

	store = &erroringStore{Storer: NewMemoryStore()}

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
	user = StringIdentifier("user")

	if mode == testFailedUnmarshalRequest {
		requestFunc = func(ctx context.Context, accessToken string) (io.ReadCloser, error) {
			return nil, errors.New("test error")
		}
		return
	}

	if mode == testFailedUnmarshalReadBody {
		requestFunc = func(ctx context.Context, accessToken string) (io.ReadCloser, error) {
			return io.NopCloser(&failReader{}), nil
		}
		return
	}
	requestFunc = func(_ context.Context, _ string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("")), nil
	}

	if mode == testFailedUnmarshalDataFinal {
		unmarshalFunc = func(b []byte) (Identifier, error) {
			return nil, fmt.Errorf("failed unmarshal")
		}
		return
	}
	unmarshalFunc = func(_ []byte) (Identifier, error) {
		return StringIdentifier("user"), nil
	}

	if mode == testCallbackErrUpsertUser {
		store.upsertUserError = true
		return
	}

	if mode == testCallbackErrCreateSession {
		store.createSessionError = true
		return
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
	sesh := New(nil, WithNow(s.withNow))
	request, config, _, _, requestFunc, unmarshalFunc := s.prepareTest(testCallbackErrNoStateCookie)
	sesh.OAuth2Callback(
		config,
		requestFunc,
		unmarshalFunc,
		s.errCallback("failed getting state cookie: http: named cookie not present"),
	).ServeHTTP(rr, request)
	response := rr.Result()
	s.Equal(`private, no-cache="Set-Cookie"`, response.Header.Get("Cache-Control"))
	s.Equal("Cookie", response.Header.Get("Vary"))
}

func (s *Oauth2CallbackHandlerSuite) TestErrInvalidStateCookie() {
	rr := httptest.NewRecorder()
	sesh := New(nil, WithNow(s.withNow))
	request, config, _, _, requestFunc, unmarshalFunc := s.prepareTest(testCallbackInvalidStateCookie)
	sesh.OAuth2Callback(
		config,
		requestFunc,
		unmarshalFunc,
		s.errCallback("invalid state cookie"),
	).ServeHTTP(rr, request)
	s.assertCommonResponse(rr.Result())
}

func (s *Oauth2CallbackHandlerSuite) TestFailedExchange() {
	rr := httptest.NewRecorder()
	sesh := New(nil, WithNow(s.withNow))
	request, config, _, _, requestFunc, unmarshalFunc := s.prepareTest(testFailedExchange)
	sesh.OAuth2Callback(
		config,
		requestFunc,
		unmarshalFunc,
		s.errCallback("failed exchanging token: oauth2: cannot fetch token: 404 Not Found\nResponse: not found\n"),
	).ServeHTTP(rr, request)
	s.assertCommonResponse(rr.Result())
}

func (s *Oauth2CallbackHandlerSuite) TestFailUnmarshalUserDataRequest() {
	rr := httptest.NewRecorder()
	sesh := New(nil, WithNow(s.withNow))
	request, config, _, _, requestFunc, unmarshalFunc := s.prepareTest(testFailedUnmarshalRequest)
	sesh.OAuth2Callback(
		config,
		requestFunc,
		unmarshalFunc,
		s.errCallback("failed unmarshalling data: get user info: test error"),
	).ServeHTTP(rr, request)
	s.assertCommonResponse(rr.Result())
}

func (s *Oauth2CallbackHandlerSuite) TestFailUnmarshalUserDataReadBody() {
	rr := httptest.NewRecorder()
	sesh := New(nil, WithNow(s.withNow))
	request, config, _, _, requestFunc, unmarshalFunc := s.prepareTest(testFailedUnmarshalReadBody)
	sesh.OAuth2Callback(
		config,
		requestFunc,
		unmarshalFunc,
		s.errCallback("failed unmarshalling data: read response: failed read"),
	).ServeHTTP(rr, request)
	s.assertCommonResponse(rr.Result())
}

func (s *Oauth2CallbackHandlerSuite) TestFailUnmarshalDataFinal() {
	rr := httptest.NewRecorder()
	sesh := New(nil, WithNow(s.withNow))
	request, config, _, _, requestFunc, unmarshalFunc := s.prepareTest(testFailedUnmarshalDataFinal)
	sesh.OAuth2Callback(
		config,
		requestFunc,
		unmarshalFunc,
		s.errCallback("failed unmarshalling data: unmarshal user data: failed unmarshal"),
	).ServeHTTP(rr, request)
	s.assertCommonResponse(rr.Result())
}

func (s *Oauth2CallbackHandlerSuite) TestCallbackErrUpsertUser() {
	request, config, _, store, requestFunc, unmarshalFunc := s.prepareTest(testCallbackErrUpsertUser)
	rr := httptest.NewRecorder()
	sesh := New(store, WithNow(s.withNow))
	sesh.OAuth2Callback(
		config,
		requestFunc,
		unmarshalFunc,
		s.errCallback("failed upserting user: mock failure"),
	).ServeHTTP(rr, request)
	s.assertCommonResponse(rr.Result())
}

func (s *Oauth2CallbackHandlerSuite) TestCallbackErrCreateSession() {
	request, config, _, store, requestFunc, unmarshalFunc := s.prepareTest(testCallbackErrCreateSession)
	rr := httptest.NewRecorder()
	sesh := New(store, WithNow(s.withNow))
	sesh.OAuth2Callback(
		config,
		requestFunc,
		unmarshalFunc,
		s.errCallback("failed creating session: mock failure"),
	).ServeHTTP(rr, request)
	s.assertCommonResponse(rr.Result())
}

func (s *Oauth2CallbackHandlerSuite) TestCallbackSuccess() {
	request, config, _, store, requestFunc, unmarshalFunc := s.prepareTest(testCallbackSuccess)
	rr := httptest.NewRecorder()
	sesh := New(store, WithNow(s.withNow))

	var success bool
	sesh.OAuth2Callback(
		config,
		requestFunc,
		unmarshalFunc,
		func(w http.ResponseWriter, r *http.Request, err error) {
			s.NoError(err)
			success = true
			w.WriteHeader(http.StatusOK)
		},
	)(rr, request)

	s.True(success)
	response := rr.Result()
	s.Equal(2, len(response.Cookies()))
	sessionCookie := response.Cookies()[1]
	s.Equal("session", sessionCookie.Name)
	s.NotEmpty(sessionCookie.Value, "session cookie should have a value")
	s.Equal(s.now.Add(24*time.Hour), sessionCookie.Expires)
	s.Equal("localhost", sessionCookie.Domain)
	s.Equal("/", sessionCookie.Path)
	s.Equal(http.SameSiteLaxMode, sessionCookie.SameSite)
	s.False(sessionCookie.Secure)
	s.assertCommonResponse(response)
}

func (s *Oauth2CallbackHandlerSuite) TestCallbackSuccessWithCustomCredentialSource() {
	request, config, _, store, requestFunc, unmarshalFunc := s.prepareTest(testCallbackSuccess)
	rr := httptest.NewRecorder()

	customCookieName := "custom_session"
	credentialSource := NewCookieCredentialSource(
		WithCookieSourceName(customCookieName),
		WithCookieSourceSecure(false),
	)
	sesh := New(store, WithNow(s.withNow), WithCredentialSources(credentialSource))

	var success bool
	sesh.OAuth2Callback(
		config,
		requestFunc,
		unmarshalFunc,
		func(w http.ResponseWriter, r *http.Request, err error) {
			s.NoError(err)
			success = true
			w.WriteHeader(http.StatusOK)
		},
	)(rr, request)

	s.True(success)
	response := rr.Result()
	s.Equal(2, len(response.Cookies()))
	sessionCookie := response.Cookies()[1]
	s.Equal(customCookieName, sessionCookie.Name)
	s.NotEmpty(sessionCookie.Value, "session cookie should have a value")
	s.Equal(s.now.Add(24*time.Hour), sessionCookie.Expires)
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
	store      *erroringStore
	identifier Identifier
	now        func() time.Time
	req        *http.Request
	resp       *httptest.ResponseRecorder
	handler    http.Handler
	session    Session
	gosesh     *Gosesh
	logger     *testLogger
}

func prepareLogoutTest(t *testing.T) *logoutTest {
	store := &erroringStore{Storer: NewMemoryStore()}
	now := func() time.Time {
		return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	req := httptest.NewRequest(http.MethodGet, "/logout", nil).WithContext(context.Background())
	resp := httptest.NewRecorder()
	withTestLogger, logger := withTestLogger()
	gosesh := New(store, WithNow(now), withTestLogger)
	handler := gosesh.Logout(nil)

	currentTime := now()
	hashedID := HashedSessionID("test-hashed-id")
	session, err := store.CreateSession(
		context.Background(),
		hashedID,
		StringIdentifier("identifier"),
		currentTime,
		currentTime.Add(time.Hour),
	)
	require.NoError(t, err)

	return &logoutTest{
		store:      store,
		identifier: StringIdentifier("identifier"),
		now:        now,
		req:        req,
		resp:       resp,
		handler:    handler,
		session:    session,
		gosesh:     gosesh,
		logger:     logger,
	}
}

func (t *logoutTest) execute() {
	t.handler.ServeHTTP(t.resp, t.req)
}

func (t *logoutTest) setValidCOokie() {
	t.req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: "aWRlbnRpZmllcg==",
	})
}

func (t *logoutTest) succeedParsingID() {
	t.setValidCOokie()
}

func (t *logoutTest) authenticated() *http.Request {
	original := t.req
	ctx := context.WithValue(t.req.Context(), sessionKey, t.session)
	t.req = t.req.WithContext(ctx)
	return original
}

func TestLogoutHandler(t *testing.T) {
	testCases := map[string]struct {
		setup          func(t *testing.T, test *logoutTest)
		wantStatusCode int
		wantLogs       []string
	}{
		"no session cookie": {
			setup:          func(t *testing.T, test *logoutTest) {},
			wantStatusCode: http.StatusUnauthorized,
			wantLogs:       []string{"level=WARN msg=\"no done handler provided for Logout, using default\""},
		},
		"bad session cookie": {
			setup: func(t *testing.T, test *logoutTest) {
				test.req.AddCookie(&http.Cookie{
					Name:  "session",
					Value: "bad",
				})
			},
			wantStatusCode: http.StatusUnauthorized,
			wantLogs: []string{
				"level=WARN msg=\"no done handler provided for Logout, using default\"",
			},
		},
		"failed parsing ID": {
			setup: func(t *testing.T, test *logoutTest) {
				test.setValidCOokie()
			},
			wantStatusCode: http.StatusUnauthorized,
			wantLogs: []string{
				"level=WARN msg=\"no done handler provided for Logout, using default\"",
				"level=ERROR msg=\"get session\" error=\"session not found\"",
			},
		},
		"failed getting session": {
			setup: func(t *testing.T, test *logoutTest) {
				test.succeedParsingID()
				test.store.getSessionError = true
			},
			wantStatusCode: http.StatusUnauthorized,
			wantLogs: []string{
				"level=WARN msg=\"no done handler provided for Logout, using default\"",
				"level=ERROR msg=\"get session\" error=\"mock failure\"",
			},
		},
		"session expired": {
			setup: func(t *testing.T, test *logoutTest) {
				test.succeedParsingID()

				hashedID := HashedSessionID("test-hashed-id-expired")
				_, err := test.store.CreateSession(
					t.Context(),
					hashedID,
					test.identifier,
					test.now().UTC().Add(-1*time.Hour),
					test.now().UTC().Add(-1*time.Hour),
				)
				require.NoError(t, err)
			},
			wantStatusCode: http.StatusUnauthorized,
			wantLogs: []string{
				"level=WARN msg=\"no done handler provided for Logout, using default\"",
				"level=ERROR msg=\"get session\" error=\"session not found\"",
			},
		},
		"failed deleting one session": {
			setup: func(t *testing.T, test *logoutTest) {
				test.authenticated()
				test.store.deleteSessionError = true
			},
			wantStatusCode: http.StatusInternalServerError,
			wantLogs: []string{
				"level=WARN msg=\"no done handler provided for Logout, using default\"",
				"level=ERROR msg=callback error=\"failed deleting session(s): mock failure\" name=Logout",
			},
		},
		"failed deleting all sessions": {
			setup: func(t *testing.T, test *logoutTest) {
				test.authenticated()
				test.store.deleteUserSessionsError = true
				test.req.URL.RawQuery = url.Values{"all": {"true"}}.Encode()
			},
			wantStatusCode: http.StatusInternalServerError,
			wantLogs: []string{
				"level=WARN msg=\"no done handler provided for Logout, using default\"",
				"level=ERROR msg=callback error=\"failed deleting session(s): mock failure\" name=Logout",
			},
		},
		"success deleting one session": {
			setup: func(t *testing.T, test *logoutTest) {
				test.authenticated()
			},
			wantStatusCode: http.StatusTemporaryRedirect,
			wantLogs: []string{
				"level=WARN msg=\"no done handler provided for Logout, using default\"",
			},
		},
		"success deleting all sessions": {
			setup: func(t *testing.T, test *logoutTest) {
				test.authenticated()
				test.req.URL.RawQuery = url.Values{"all": {"true"}}.Encode()
			},
			wantStatusCode: http.StatusTemporaryRedirect,
			wantLogs: []string{
				"level=WARN msg=\"no done handler provided for Logout, using default\"",
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			test := prepareLogoutTest(t)

			tc.setup(t, test)
			test.execute()

			assert.Equal(tc.wantStatusCode, test.resp.Code)
			test.logger.assertExpectedLogs(t, tc.wantLogs)
		})
	}
}

func TestLogoutWithCustomCredentialSource(t *testing.T) {
	assert, require := assert.New(t), require.New(t)

	store := NewMemoryStore()
	now := func() time.Time {
		return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	}

	customCookieName := "custom_session"
	credentialSource := NewCookieCredentialSource(
		WithCookieSourceName(customCookieName),
		WithCookieSourceSecure(false),
	)

	gs := New(store, WithNow(now), WithCredentialSources(credentialSource))

	currentTime := now()
	hashedID := HashedSessionID("test-hashed-id-logout")
	session, err := store.CreateSession(
		t.Context(),
		hashedID,
		StringIdentifier("user"),
		currentTime.Add(time.Hour),
		currentTime.Add(24*time.Hour),
	)
	require.NoError(err)

	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	ctx := context.WithValue(req.Context(), sessionKey, session)
	req = req.WithContext(ctx)

	resp := httptest.NewRecorder()

	var success bool
	gs.Logout(func(w http.ResponseWriter, r *http.Request, err error) {
		assert.NoError(err)
		success = true
		w.WriteHeader(http.StatusOK)
	}).ServeHTTP(resp, req)

	assert.True(success)

	cookies := resp.Result().Cookies()
	require.Len(cookies, 1)

	clearedCookie := cookies[0]
	assert.Equal(customCookieName, clearedCookie.Name)
	assert.Equal("", clearedCookie.Value)
	assert.Equal(-1, clearedCookie.MaxAge)
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
			store := NewMemoryStore()
			sesh := New(
				store,
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

func TestExchangeExternalToken(t *testing.T) {
	fixedTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	withNow := func() time.Time { return fixedTime }

	// Helper to create a successful request func
	successRequestFunc := func(_ context.Context, _ string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(`{"id":"user123"}`)), nil
	}

	// Helper to create a successful unmarshal func
	successUnmarshalFunc := func(_ []byte) (Identifier, error) {
		return StringIdentifier("user123"), nil
	}

	tests := map[string]struct {
		giveRequestBody    string
		giveRequestFunc    RequestFunc
		giveUnmarshalFunc  UnmarshalFunc
		giveOptions        []ExchangeOption
		giveValidator      *fakeAudienceValidator // Direct reference for call verification
		giveStoreSetup     func(t *testing.T, store *erroringStore)
		wantStatusCode     int
		wantErrContains    string
		wantSessionID      bool
		wantValidatorCall  bool
		wantValidatorToken string // Expected token passed to validator
	}{
		"valid_token_creates_session": {
			giveRequestBody:   `{"access_token":"valid-token"}`,
			giveRequestFunc:   successRequestFunc,
			giveUnmarshalFunc: successUnmarshalFunc,
			wantStatusCode:    http.StatusOK,
			wantSessionID:     true,
			wantValidatorCall: false,
		},
		"invalid_json_body": {
			giveRequestBody: `{invalid json`,
			wantStatusCode:  http.StatusBadRequest,
			wantErrContains: "parse request body",
			wantValidatorCall: false,
		},
		"missing_access_token": {
			giveRequestBody: `{"access_token":""}`,
			wantStatusCode:  http.StatusBadRequest,
			wantErrContains: "empty access_token",
			wantValidatorCall: false,
		},
		"request_func_error": {
			giveRequestBody: `{"access_token":"valid-token"}`,
			giveRequestFunc: func(_ context.Context, _ string) (io.ReadCloser, error) {
				return nil, errors.New("provider unreachable")
			},
			giveUnmarshalFunc: successUnmarshalFunc,
			wantStatusCode:    http.StatusInternalServerError,
			wantErrContains:   "failed exchanging token",
			wantValidatorCall: false,
		},
		"unmarshal_error": {
			giveRequestBody: `{"access_token":"valid-token"}`,
			giveRequestFunc: successRequestFunc,
			giveUnmarshalFunc: func(_ []byte) (Identifier, error) {
				return nil, errors.New("invalid user data")
			},
			wantStatusCode:  http.StatusInternalServerError,
			wantErrContains: "failed unmarshalling data",
			wantValidatorCall: false,
		},
		"upsert_user_error": {
			giveRequestBody:   `{"access_token":"valid-token"}`,
			giveRequestFunc:   successRequestFunc,
			giveUnmarshalFunc: successUnmarshalFunc,
			giveStoreSetup: func(t *testing.T, store *erroringStore) {
				t.Helper()
				store.upsertUserError = true
			},
			wantStatusCode:  http.StatusInternalServerError,
			wantErrContains: "failed upserting user",
			wantValidatorCall: false,
		},
		"create_session_error": {
			giveRequestBody:   `{"access_token":"valid-token"}`,
			giveRequestFunc:   successRequestFunc,
			giveUnmarshalFunc: successUnmarshalFunc,
			giveStoreSetup: func(t *testing.T, store *erroringStore) {
				t.Helper()
				store.createSessionError = true
			},
			wantStatusCode:  http.StatusInternalServerError,
			wantErrContains: "failed creating session",
			wantValidatorCall: false,
		},
		// Audience validation test cases
		"no_options_backward_compat": {
			giveRequestBody:    `{"access_token":"valid-token"}`,
			giveRequestFunc:    successRequestFunc,
			giveUnmarshalFunc:  successUnmarshalFunc,
			giveOptions:        nil,
			wantStatusCode:     http.StatusOK,
			wantSessionID:      true,
			wantValidatorCall:  false,
			wantValidatorToken: "",
		},
	}

	// Add audience validation test cases with validator references
	validator1 := &fakeAudienceValidator{audience: "client-a"}
	tests["validator_audience_matches"] = struct {
		giveRequestBody    string
		giveRequestFunc    RequestFunc
		giveUnmarshalFunc  UnmarshalFunc
		giveOptions        []ExchangeOption
		giveValidator      *fakeAudienceValidator
		giveStoreSetup     func(t *testing.T, store *erroringStore)
		wantStatusCode     int
		wantErrContains    string
		wantSessionID      bool
		wantValidatorCall  bool
		wantValidatorToken string
	}{
		giveRequestBody:    `{"access_token":"valid-token"}`,
		giveRequestFunc:    successRequestFunc,
		giveUnmarshalFunc:  successUnmarshalFunc,
		giveValidator:      validator1,
		giveOptions:        []ExchangeOption{WithAudienceValidator(validator1), WithExpectedAudiences("client-a")},
		wantStatusCode:     http.StatusOK,
		wantSessionID:      true,
		wantValidatorCall:  true,
		wantValidatorToken: "valid-token",
	}

	validator2 := &fakeAudienceValidator{audience: "client-b"}
	tests["validator_audience_mismatch"] = struct {
		giveRequestBody    string
		giveRequestFunc    RequestFunc
		giveUnmarshalFunc  UnmarshalFunc
		giveOptions        []ExchangeOption
		giveValidator      *fakeAudienceValidator
		giveStoreSetup     func(t *testing.T, store *erroringStore)
		wantStatusCode     int
		wantErrContains    string
		wantSessionID      bool
		wantValidatorCall  bool
		wantValidatorToken string
	}{
		giveRequestBody:    `{"access_token":"valid-token"}`,
		giveRequestFunc:    successRequestFunc,
		giveUnmarshalFunc:  successUnmarshalFunc,
		giveValidator:      validator2,
		giveOptions:        []ExchangeOption{WithAudienceValidator(validator2), WithExpectedAudiences("client-a")},
		wantStatusCode:     http.StatusInternalServerError,
		wantErrContains:    "failed validating audience",
		wantValidatorCall:  true,
		wantValidatorToken: "valid-token",
	}

	validator3 := &fakeAudienceValidator{audience: "b"}
	tests["validator_multiple_audiences_match"] = struct {
		giveRequestBody    string
		giveRequestFunc    RequestFunc
		giveUnmarshalFunc  UnmarshalFunc
		giveOptions        []ExchangeOption
		giveValidator      *fakeAudienceValidator
		giveStoreSetup     func(t *testing.T, store *erroringStore)
		wantStatusCode     int
		wantErrContains    string
		wantSessionID      bool
		wantValidatorCall  bool
		wantValidatorToken string
	}{
		giveRequestBody:    `{"access_token":"valid-token"}`,
		giveRequestFunc:    successRequestFunc,
		giveUnmarshalFunc:  successUnmarshalFunc,
		giveValidator:      validator3,
		giveOptions:        []ExchangeOption{WithAudienceValidator(validator3), WithExpectedAudiences("a", "b", "c")},
		wantStatusCode:     http.StatusOK,
		wantSessionID:      true,
		wantValidatorCall:  true,
		wantValidatorToken: "valid-token",
	}

	validator4 := &fakeAudienceValidator{err: errors.New("validator network error")}
	tests["validator_error"] = struct {
		giveRequestBody    string
		giveRequestFunc    RequestFunc
		giveUnmarshalFunc  UnmarshalFunc
		giveOptions        []ExchangeOption
		giveValidator      *fakeAudienceValidator
		giveStoreSetup     func(t *testing.T, store *erroringStore)
		wantStatusCode     int
		wantErrContains    string
		wantSessionID      bool
		wantValidatorCall  bool
		wantValidatorToken string
	}{
		giveRequestBody:    `{"access_token":"valid-token"}`,
		giveRequestFunc:    successRequestFunc,
		giveUnmarshalFunc:  successUnmarshalFunc,
		giveValidator:      validator4,
		giveOptions:        []ExchangeOption{WithAudienceValidator(validator4), WithExpectedAudiences("a")},
		wantStatusCode:     http.StatusInternalServerError,
		wantErrContains:    "failed validating audience",
		wantValidatorCall:  true,
		wantValidatorToken: "valid-token",
	}

	validator5 := &fakeAudienceValidator{audience: "any"}
	tests["validator_no_expected_audiences"] = struct {
		giveRequestBody    string
		giveRequestFunc    RequestFunc
		giveUnmarshalFunc  UnmarshalFunc
		giveOptions        []ExchangeOption
		giveValidator      *fakeAudienceValidator
		giveStoreSetup     func(t *testing.T, store *erroringStore)
		wantStatusCode     int
		wantErrContains    string
		wantSessionID      bool
		wantValidatorCall  bool
		wantValidatorToken string
	}{
		giveRequestBody:    `{"access_token":"valid-token"}`,
		giveRequestFunc:    successRequestFunc,
		giveUnmarshalFunc:  successUnmarshalFunc,
		giveValidator:      validator5,
		giveOptions:        []ExchangeOption{WithAudienceValidator(validator5)},
		wantStatusCode:     http.StatusOK,
		wantSessionID:      true,
		wantValidatorCall:  true,
		wantValidatorToken: "valid-token",
	}

	tests["expected_audiences_no_validator"] = struct {
		giveRequestBody    string
		giveRequestFunc    RequestFunc
		giveUnmarshalFunc  UnmarshalFunc
		giveOptions        []ExchangeOption
		giveValidator      *fakeAudienceValidator
		giveStoreSetup     func(t *testing.T, store *erroringStore)
		wantStatusCode     int
		wantErrContains    string
		wantSessionID      bool
		wantValidatorCall  bool
		wantValidatorToken string
	}{
		giveRequestBody:    `{"access_token":"valid-token"}`,
		giveRequestFunc:    successRequestFunc,
		giveUnmarshalFunc:  successUnmarshalFunc,
		giveOptions:        []ExchangeOption{WithExpectedAudiences("a")},
		wantStatusCode:     http.StatusOK,
		wantSessionID:      true,
		wantValidatorCall:  false,
		wantValidatorToken: "",
	}

	validator6 := &fakeAudienceValidator{audience: ""}
	tests["validator_empty_audience_with_expected"] = struct {
		giveRequestBody    string
		giveRequestFunc    RequestFunc
		giveUnmarshalFunc  UnmarshalFunc
		giveOptions        []ExchangeOption
		giveValidator      *fakeAudienceValidator
		giveStoreSetup     func(t *testing.T, store *erroringStore)
		wantStatusCode     int
		wantErrContains    string
		wantSessionID      bool
		wantValidatorCall  bool
		wantValidatorToken string
	}{
		giveRequestBody:    `{"access_token":"valid-token"}`,
		giveRequestFunc:    successRequestFunc,
		giveUnmarshalFunc:  successUnmarshalFunc,
		giveValidator:      validator6,
		giveOptions:        []ExchangeOption{WithAudienceValidator(validator6), WithExpectedAudiences("client-a")},
		wantStatusCode:     http.StatusInternalServerError,
		wantErrContains:    "failed validating audience",
		wantValidatorCall:  true,
		wantValidatorToken: "valid-token",
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			store := &erroringStore{Storer: NewMemoryStore()}
			if tc.giveStoreSetup != nil {
				tc.giveStoreSetup(t, store)
			}

			gs := New(store, WithNow(withNow))

			var capturedErr error
			doneHandler := func(w http.ResponseWriter, r *http.Request, err error) {
				capturedErr = err
				if err != nil {
					code := http.StatusInternalServerError
					errMsg := err.Error()
					if strings.HasPrefix(errMsg, "parse request body:") ||
						strings.HasPrefix(errMsg, "validate token:") {
						code = http.StatusBadRequest
					}
					http.Error(w, err.Error(), code)
					return
				}
			}

			handler := gs.ExchangeExternalToken(tc.giveRequestFunc, tc.giveUnmarshalFunc, doneHandler, tc.giveOptions...)

			req := httptest.NewRequest(http.MethodPost, "/api/token/exchange", strings.NewReader(tc.giveRequestBody))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			assert.Equal(tc.wantStatusCode, rr.Code)

			if tc.wantErrContains != "" {
				require.Error(capturedErr)
				assert.Contains(capturedErr.Error(), tc.wantErrContains)
			}

			if tc.wantSessionID {
				assert.NoError(capturedErr)
				assert.Equal("application/json", rr.Header().Get("Content-Type"))

				var response ExchangeTokenResponse
				err := json.NewDecoder(rr.Body).Decode(&response)
				require.NoError(err)
				assert.NotEmpty(response.SessionID)
				assert.False(response.ExpiresAt.IsZero())
			}

			// Verify validator was/wasn't called as expected
			if tc.giveValidator != nil {
				assert.Equal(tc.wantValidatorCall, tc.giveValidator.called, "validator call expectation mismatch")
				if tc.wantValidatorCall && tc.wantValidatorToken != "" {
					assert.Equal(tc.wantValidatorToken, tc.giveValidator.gotToken)
				}
			}
		})
	}
}

func TestExchangeExternalToken_NativeAppSessionConfig(t *testing.T) {
	fixedTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	withNow := func() time.Time { return fixedTime }

	store := NewMemoryStore()
	gs := New(store, WithNow(withNow))

	requestFunc := func(_ context.Context, _ string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(`{"id":"user123"}`)), nil
	}

	unmarshalFunc := func(_ []byte) (Identifier, error) {
		return StringIdentifier("user123"), nil
	}

	doneHandler := func(w http.ResponseWriter, r *http.Request, err error) {
		require.NoError(t, err)
	}

	handler := gs.ExchangeExternalToken(requestFunc, unmarshalFunc, doneHandler)

	req := httptest.NewRequest(http.MethodPost, "/api/token/exchange", strings.NewReader(`{"access_token":"valid-token"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	// Parse the response to get the session ID
	var response ExchangeTokenResponse
	err := json.NewDecoder(rr.Body).Decode(&response)
	require.NoError(t, err)

	// Retrieve the session from the store - need to hash the raw ID
	rawID := RawSessionID(response.SessionID)
	hashedID := gs.idHasher(rawID)
	capturedSession, err := store.GetSession(t.Context(), hashedID)
	require.NoError(t, err)

	// Verify native app session config: 30-day absolute, no idle timeout (idle = now)
	nativeAppConfig := DefaultNativeAppSessionConfig()
	expectedAbsoluteDeadline := fixedTime.Add(nativeAppConfig.AbsoluteDuration)
	expectedIdleDeadline := fixedTime.Add(nativeAppConfig.IdleDuration) // Should be 0, so idle = now

	assert.Equal(t, expectedAbsoluteDeadline, capturedSession.AbsoluteDeadline())
	assert.Equal(t, expectedIdleDeadline, capturedSession.IdleDeadline())
}

func TestExchangeExternalToken_AudienceErrorWrapping(t *testing.T) {
	// Test that AudienceValidationError is wrapped with ErrFailedValidatingAudience
	// and both errors.Is() and errors.As() work correctly
	fixedTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	withNow := func() time.Time { return fixedTime }

	store := NewMemoryStore()
	gs := New(store, WithNow(withNow))

	validator := &fakeAudienceValidator{audience: "client-b"}

	requestFunc := func(_ context.Context, _ string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(`{"id":"user123"}`)), nil
	}

	unmarshalFunc := func(_ []byte) (Identifier, error) {
		return StringIdentifier("user123"), nil
	}

	var capturedErr error
	doneHandler := func(w http.ResponseWriter, r *http.Request, err error) {
		capturedErr = err
	}

	handler := gs.ExchangeExternalToken(
		requestFunc,
		unmarshalFunc,
		doneHandler,
		WithAudienceValidator(validator),
		WithExpectedAudiences("client-a"),
	)

	req := httptest.NewRequest(http.MethodPost, "/api/token/exchange", strings.NewReader(`{"access_token":"valid-token"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Verify sentinel check works
	assert.True(t, errors.Is(capturedErr, ErrFailedValidatingAudience))

	// Verify structured error extraction works
	var audErr *AudienceValidationError
	assert.True(t, errors.As(capturedErr, &audErr))
	assert.Equal(t, []string{"client-a"}, audErr.Expected)
	assert.Equal(t, "client-b", audErr.Actual)
}

func TestExchangeExternalToken_DoneHandlerReceivesValidationError(t *testing.T) {
	// Test that when validation fails, done handler receives the error
	fixedTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	withNow := func() time.Time { return fixedTime }

	store := NewMemoryStore()
	gs := New(store, WithNow(withNow))

	validator := &fakeAudienceValidator{err: errors.New("network timeout")}

	requestFunc := func(_ context.Context, _ string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(`{"id":"user123"}`)), nil
	}

	unmarshalFunc := func(_ []byte) (Identifier, error) {
		return StringIdentifier("user123"), nil
	}

	var doneHandlerCalled bool
	var capturedErr error
	doneHandler := func(w http.ResponseWriter, r *http.Request, err error) {
		doneHandlerCalled = true
		capturedErr = err
	}

	handler := gs.ExchangeExternalToken(
		requestFunc,
		unmarshalFunc,
		doneHandler,
		WithAudienceValidator(validator),
		WithExpectedAudiences("client-a"),
	)

	req := httptest.NewRequest(http.MethodPost, "/api/token/exchange", strings.NewReader(`{"access_token":"valid-token"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.True(t, doneHandlerCalled, "done handler should be called")
	assert.Error(t, capturedErr, "done handler should receive error")
	assert.True(t, errors.Is(capturedErr, ErrFailedValidatingAudience))
}

func TestExchangeExternalToken_ValidationBeforeRequestFunc(t *testing.T) {
	// Test that if validation fails, RequestFunc is not called
	fixedTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	withNow := func() time.Time { return fixedTime }

	store := NewMemoryStore()
	gs := New(store, WithNow(withNow))

	validator := &fakeAudienceValidator{audience: "wrong-audience"}

	requestFuncCalled := false
	requestFunc := func(_ context.Context, _ string) (io.ReadCloser, error) {
		requestFuncCalled = true
		return io.NopCloser(strings.NewReader(`{"id":"user123"}`)), nil
	}

	unmarshalFunc := func(_ []byte) (Identifier, error) {
		return StringIdentifier("user123"), nil
	}

	doneHandler := func(w http.ResponseWriter, r *http.Request, err error) {
		// no-op
	}

	handler := gs.ExchangeExternalToken(
		requestFunc,
		unmarshalFunc,
		doneHandler,
		WithAudienceValidator(validator),
		WithExpectedAudiences("client-a"),
	)

	req := httptest.NewRequest(http.MethodPost, "/api/token/exchange", strings.NewReader(`{"access_token":"valid-token"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.False(t, requestFuncCalled, "RequestFunc should not be called when validation fails")
}

func TestExchangeExternalToken_ContextCancellation(t *testing.T) {
	// Test that context cancellation during validation is propagated correctly
	fixedTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	withNow := func() time.Time { return fixedTime }

	store := NewMemoryStore()
	gs := New(store, WithNow(withNow))

	// Validator that checks context cancellation
	validator := &fakeAudienceValidator{err: context.Canceled}

	requestFunc := func(_ context.Context, _ string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(`{"id":"user123"}`)), nil
	}

	unmarshalFunc := func(_ []byte) (Identifier, error) {
		return StringIdentifier("user123"), nil
	}

	var capturedErr error
	doneHandler := func(w http.ResponseWriter, r *http.Request, err error) {
		capturedErr = err
	}

	handler := gs.ExchangeExternalToken(
		requestFunc,
		unmarshalFunc,
		doneHandler,
		WithAudienceValidator(validator),
		WithExpectedAudiences("client-a"),
	)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	req := httptest.NewRequest(http.MethodPost, "/api/token/exchange", strings.NewReader(`{"access_token":"valid-token"}`))
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Error(t, capturedErr)
	assert.True(t, errors.Is(capturedErr, ErrFailedValidatingAudience))
	assert.True(t, errors.Is(capturedErr, context.Canceled))
}

func TestExchangeExternalToken_ResponseFormat(t *testing.T) {
	fixedTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	withNow := func() time.Time { return fixedTime }

	store := NewMemoryStore()
	gs := New(store, WithNow(withNow))

	requestFunc := func(_ context.Context, _ string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(`{"id":"user123"}`)), nil
	}

	unmarshalFunc := func(_ []byte) (Identifier, error) {
		return StringIdentifier("user123"), nil
	}

	doneHandler := func(w http.ResponseWriter, r *http.Request, err error) {
		require.NoError(t, err)
	}

	handler := gs.ExchangeExternalToken(requestFunc, unmarshalFunc, doneHandler)

	req := httptest.NewRequest(http.MethodPost, "/api/token/exchange", strings.NewReader(`{"access_token":"valid-token"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	// Verify response body has the required fields
	var response map[string]interface{}
	err := json.NewDecoder(rr.Body).Decode(&response)
	require.NoError(t, err)

	assert.Contains(t, response, "session_id")
	assert.Contains(t, response, "expires_at")
	assert.NotEmpty(t, response["session_id"])
	assert.NotEmpty(t, response["expires_at"])
}
