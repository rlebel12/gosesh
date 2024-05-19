package tests

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rlebel12/gosesh"
	"github.com/rlebel12/gosesh/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"golang.org/x/oauth2"
)

type Oauth2BeginHandlerSuite struct {
	suite.Suite
	originalReader io.Reader
}

func (s *Oauth2BeginHandlerSuite) SetupSuite() {
	s.originalReader = rand.Reader
}

func (s *Oauth2BeginHandlerSuite) SetupTest() {
	rand.Reader = strings.NewReader("deterministic random data")
}

func (s *Oauth2BeginHandlerSuite) SetupSubTest() {
	rand.Reader = strings.NewReader("deterministic random data")
}

func (s *Oauth2BeginHandlerSuite) TearDownSuite() {
	rand.Reader = s.originalReader
}

func (s *Oauth2BeginHandlerSuite) TestOAuth2BeginSuccess() {
	now := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	for name, test := range map[string]struct {
		secure bool
	}{
		"insecure": {secure: false},
		"secure":   {secure: true},
	} {
		s.Run(name, func() {
			opts := []gosesh.NewOpts{gosesh.WithNow(func() time.Time {
				return now
			})}
			if test.secure {
				url, err := url.Parse("https://localhost")
				s.Require().NoError(err)
				opts = append(opts, gosesh.WithOrigin(*url))
			}
			sesh := gosesh.New(nil, nil, opts...)
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
			handler.ServeHTTP(rr, &http.Request{})

			response := rr.Result()
			s.Equal(http.StatusTemporaryRedirect, response.StatusCode)
			s.Require().Equal(1, len(response.Cookies()))
			cookie := response.Cookies()[0]
			s.Equal("oauthstate", cookie.Name)
			s.Equal("ZGV0ZXJtaW5pc3RpYyByYQ==", cookie.Value)
			s.Equal(now.Add(5*time.Minute), cookie.Expires)
			s.Equal("localhost", cookie.Domain)
			s.Equal("/", cookie.Path)
			s.Equal(http.SameSiteLaxMode, cookie.SameSite)
			s.Equal(test.secure, cookie.Secure)
			s.Equal(
				"http://localhost/auth?client_id=client_id&redirect_uri=http%3A%2F%2Flocalhost%2Fauth%2Fcallback&response_type=code&scope=email&state=ZGV0ZXJtaW5pc3RpYyByYQ%3D%3D",
				response.Header.Get("Location"),
			)
		})
	}
}

func (s *Oauth2BeginHandlerSuite) TestOAuth2BeginFailure() {
	rand.Reader = strings.NewReader("")
	sesh := gosesh.New(nil, nil)
	rr := httptest.NewRecorder()
	sesh.OAuth2Begin(&oauth2.Config{})(rr, &http.Request{})
	response := rr.Result()
	s.Equal(http.StatusInternalServerError, response.StatusCode)
	s.Equal("failed to create OAuth2 state\n", rr.Body.String())
}

func TestHandlersSuite(t *testing.T) {
	suite.Run(t, new(Oauth2BeginHandlerSuite))

}

type Oauth2CallbackHandlerSuite struct {
	suite.Suite
	oauth2Server *httptest.Server
	now          time.Time
	withNow      func(*gosesh.Config)
}

func (s *Oauth2CallbackHandlerSuite) SetupSuite() {
	s.oauth2Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth":
			http.Redirect(w, r, "http://localhost/auth/callback?code=code&state="+r.FormValue("state"), http.StatusTemporaryRedirect)
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_, err := w.Write([]byte(`{"access_token":"access_token","token_type":"bearer","refresh_token":"refresh_token","expiry":"2021-01-01T00:00:00Z"}`))
			s.Require().NoError(err)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	s.now = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	s.withNow = func(c *gosesh.Config) { c.Now = func() time.Time { return s.now } }
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

func (s *Oauth2CallbackHandlerSuite) makeInputs(mode testCallbackRequestMode) (r *http.Request, config *oauth2.Config, user *mocks.OAuth2User, store *mocks.Storer) {
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
	user = mocks.NewOAuth2User(s.T())

	if mode == testFailedUnmarshalRequest {
		user.EXPECT().Request(r.Context(), "access_token").Return(nil, fmt.Errorf("failed request"))
		return
	}

	if mode == testFailedUnmarshalReadBody {
		response := &http.Response{
			Body: io.NopCloser(&failReader{}),
		}
		user.EXPECT().Request(r.Context(), "access_token").Return(response, nil)
		return
	}
	response := &http.Response{
		Body: io.NopCloser(strings.NewReader("")),
	}
	user.EXPECT().Request(r.Context(), "access_token").Return(response, nil)

	if mode == testFailedUnmarshalDataFinal {
		user.EXPECT().Unmarshal([]byte{}).Return(fmt.Errorf("failed unmarshal"))
		return
	}
	user.EXPECT().Unmarshal([]byte{}).Return(nil)
	user.EXPECT().String().Return("user")
	store = mocks.NewStorer(s.T())

	if mode == testCallbackErrUpsertUser {
		store.EXPECT().UpsertUser(r.Context(), user).Return(nil, fmt.Errorf("failed upsert"))
		return
	}
	identifier := mocks.NewIdentifier(s.T())
	identifier.EXPECT().String().Return("identifier")
	store.EXPECT().UpsertUser(r.Context(), user).Return(identifier, nil)
	createSessionRequest := gosesh.CreateSessionRequest{
		UserID:   identifier,
		IdleAt:   s.now.Add(1 * time.Hour),
		ExpireAt: s.now.Add(24 * time.Hour),
	}

	if mode == testCallbackErrCreateSession {
		store.EXPECT().CreateSession(r.Context(), createSessionRequest).
			Return(nil, fmt.Errorf("failed create session"))
		return
	}
	store.EXPECT().CreateSession(r.Context(), createSessionRequest).Return(&gosesh.Session{
		ID:       identifier,
		UserID:   identifier,
		IdleAt:   s.now.Add(1 * time.Hour),
		ExpireAt: s.now.Add(24 * time.Hour),
	}, nil)

	return
}

func (s *Oauth2CallbackHandlerSuite) TestErrNoStateCookie() {
	rr := httptest.NewRecorder()
	sesh := gosesh.New(nil, nil, s.withNow)
	request, config, _, _ := s.makeInputs(testCallbackErrNoStateCookie)
	err := sesh.OAuth2Callback(rr, request, nil, config)
	s.EqualError(err, "failed getting state cookie: http: named cookie not present")
}

func (s *Oauth2CallbackHandlerSuite) TestErrInvalidStateCookie() {
	rr := httptest.NewRecorder()
	sesh := gosesh.New(nil, nil, s.withNow)
	request, config, _, _ := s.makeInputs(testCallbackInvalidStateCookie)
	err := sesh.OAuth2Callback(rr, request, nil, config)
	s.assertStateCookieReset(rr.Result())
	s.EqualError(err, "invalid state cookie")
}

func (s *Oauth2CallbackHandlerSuite) TestFailedExchange() {
	rr := httptest.NewRecorder()
	sesh := gosesh.New(nil, nil, s.withNow)
	request, config, _, _ := s.makeInputs(testFailedExchange)
	err := sesh.OAuth2Callback(rr, request, nil, config)
	s.assertStateCookieReset(rr.Result())
	s.EqualError(err, "failed exchanging token: oauth2: cannot fetch token: 404 Not Found\nResponse: not found\n")
}

func (s *Oauth2CallbackHandlerSuite) TestFailUnmarshalUserDataRequest() {
	rr := httptest.NewRecorder()
	sesh := gosesh.New(nil, nil, s.withNow)
	request, config, user, _ := s.makeInputs(testFailedUnmarshalRequest)
	err := sesh.OAuth2Callback(rr, request, user, config)
	s.assertStateCookieReset(rr.Result())
	s.EqualError(err, "failed unmarshalling data: failed getting user info: failed request")
}

func (s *Oauth2CallbackHandlerSuite) TestFailUnmarshalUserDataReadBody() {
	rr := httptest.NewRecorder()
	sesh := gosesh.New(nil, nil, s.withNow)
	request, config, user, _ := s.makeInputs(testFailedUnmarshalReadBody)
	err := sesh.OAuth2Callback(rr, request, user, config)
	s.assertStateCookieReset(rr.Result())
	s.EqualError(err, "failed unmarshalling data: failed read response: failed read")
}

func (s *Oauth2CallbackHandlerSuite) TestFailUnmarshalDataFinal() {
	rr := httptest.NewRecorder()
	sesh := gosesh.New(nil, nil, s.withNow)
	request, config, user, _ := s.makeInputs(testFailedUnmarshalDataFinal)
	err := sesh.OAuth2Callback(rr, request, user, config)
	s.assertStateCookieReset(rr.Result())
	s.EqualError(err, "failed unmarshalling data: failed unmarshal")
}

func (s *Oauth2CallbackHandlerSuite) TestCallbackErrUpsertUser() {
	request, config, user, store := s.makeInputs(testCallbackErrUpsertUser)
	rr := httptest.NewRecorder()
	sesh := gosesh.New(nil, store, s.withNow)
	err := sesh.OAuth2Callback(rr, request, user, config)
	s.assertStateCookieReset(rr.Result())
	s.EqualError(err, "failed upserting user: failed upsert")
}

func (s *Oauth2CallbackHandlerSuite) TestCallbackErrCreateSession() {
	request, config, user, store := s.makeInputs(testCallbackErrCreateSession)
	rr := httptest.NewRecorder()
	sesh := gosesh.New(nil, store, s.withNow)
	err := sesh.OAuth2Callback(rr, request, user, config)
	s.assertStateCookieReset(rr.Result())
	s.EqualError(err, "failed creating session: failed create session")
}

func (s *Oauth2CallbackHandlerSuite) TestCallbackSuccess() {
	request, config, user, store := s.makeInputs(testCallbackSuccess)
	rr := httptest.NewRecorder()
	sesh := gosesh.New(nil, store, s.withNow)
	err := sesh.OAuth2Callback(rr, request, user, config)
	s.Require().NoError(err)
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
	s.assertStateCookieReset(response)
}

func (s *Oauth2CallbackHandlerSuite) assertStateCookieReset(response *http.Response) {
	cookie := response.Cookies()[0]
	s.Equal("oauthstate", cookie.Name)
	s.Equal("", cookie.Value)
	s.Equal(s.now, cookie.Expires)
	s.Equal("localhost", cookie.Domain)
	s.Equal("/", cookie.Path)
	s.Equal(http.SameSiteLaxMode, cookie.SameSite)
	s.False(cookie.Secure)
}

func TestOauth2CallbackHandlerSuite(t *testing.T) {
	suite.Run(t, new(Oauth2CallbackHandlerSuite))
}

type testLogoutStep int

const (
	testLogoutNoSessionCookie testLogoutStep = iota
	testLogoutBadSessionCookie
	testLogoutFailedParsingID
	testLogoutFailedGettingSession
	testLogoutSessionExpired
	testLogoutFailedDeletingSession
	testLogoutSuccess
)

func TestLogoutHandler(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	for name, test := range map[string]struct {
		step            testLogoutStep
		deleteAll       bool
		completeHandler bool
	}{
		"no session cookie":                                  {step: testLogoutNoSessionCookie},
		"bad session cookie":                                 {step: testLogoutBadSessionCookie},
		"failed parsing ID":                                  {step: testLogoutFailedParsingID},
		"failed getting session":                             {step: testLogoutFailedGettingSession},
		"session expired":                                    {step: testLogoutSessionExpired},
		"failed deleting one session":                        {step: testLogoutFailedDeletingSession},
		"failed deleting all sessions":                       {step: testLogoutFailedDeletingSession, deleteAll: true},
		"success deleting one session":                       {step: testLogoutSuccess},
		"success deleting all sessions":                      {step: testLogoutSuccess, deleteAll: true},
		"success deleting one session with complete handler": {step: testLogoutSuccess, completeHandler: true},
	} {
		t.Run(name, func(t *testing.T) {
			now := func() time.Time { return time.Now() }
			store := mocks.NewStorer(t)
			parser := mocks.NewIDParser(t)
			r, err := http.NewRequest(http.MethodGet, "/", nil)
			require.NoError(err)
			sesh := gosesh.New(parser, store, gosesh.WithNow(now))
			rr := httptest.NewRecorder()

			func() {
				if test.step == testLogoutNoSessionCookie {
					return
				}

				if test.step == testLogoutBadSessionCookie {
					r.AddCookie(&http.Cookie{
						Name:  "session",
						Value: "bad",
					})
					return
				}
				r.AddCookie(&http.Cookie{
					Name:  "session",
					Value: "aWRlbnRpZmllcg==",
				})

				if test.step == testLogoutFailedParsingID {
					parser.EXPECT().Parse([]byte("identifier")).Return(nil, fmt.Errorf("failed parse"))
					return
				}
				identifier := mocks.NewIdentifier(t)
				identifier.EXPECT().String().Return("identifier")
				parser.EXPECT().Parse([]byte("identifier")).Return(identifier, nil)

				if test.step == testLogoutFailedGettingSession {
					store.EXPECT().GetSession(r.Context(), identifier).Return(nil, fmt.Errorf("failed get session"))
					return
				}

				if test.step == testLogoutSessionExpired {
					store.EXPECT().GetSession(r.Context(), identifier).Return(&gosesh.Session{
						ID:       identifier,
						UserID:   identifier,
						IdleAt:   now().UTC().Add(-1 * time.Hour),
						ExpireAt: now().UTC().Add(-1 * time.Hour),
					}, nil)
					return
				}
				session := &gosesh.Session{
					ID:       identifier,
					UserID:   identifier,
					IdleAt:   now().UTC().Add(1 * time.Hour),
					ExpireAt: now().UTC().Add(24 * time.Hour),
				}
				store.EXPECT().GetSession(r.Context(), identifier).Return(session, nil)
				ctx := context.WithValue(r.Context(), gosesh.SessionContextKey, session)

				if test.deleteAll {
					urlValues := url.Values{}
					urlValues.Add("all", "true")
					r.URL.RawQuery = urlValues.Encode()
				}
				if test.step < testLogoutSuccess {
					if test.deleteAll {
						store.EXPECT().DeleteUserSessions(ctx, identifier).Return(0, fmt.Errorf("failed delete all sessions"))
					} else {
						store.EXPECT().DeleteSession(ctx, identifier).Return(fmt.Errorf("failed delete session"))
					}
					return
				}
				if test.deleteAll {
					store.EXPECT().DeleteUserSessions(ctx, identifier).Return(1, nil)
				} else {
					store.EXPECT().DeleteSession(ctx, identifier).Return(nil)
				}
			}()

			defer func() {
				if test.step <= testLogoutSessionExpired {
					assert.Equal(http.StatusUnauthorized, rr.Code)
					return
				}
				if test.step < testLogoutSuccess {
					assert.Equal(http.StatusInternalServerError, rr.Code)
					return
				}
				if test.completeHandler {
					assert.Equal(http.StatusTeapot, rr.Code)
				} else {
					assert.Equal(http.StatusNoContent, rr.Code)
				}
			}()

			var handler http.HandlerFunc
			if test.completeHandler {
				handler = func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusTeapot)
				}
			}
			sesh.LogoutHandler(handler).ServeHTTP(rr, r)
		})
	}
}
