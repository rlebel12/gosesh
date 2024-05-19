package tests

import (
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
}

func (s *Oauth2CallbackHandlerSuite) SetupSuite() {
	s.oauth2Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth":
			http.Redirect(w, r, "http://localhost/auth/callback?code=code&state="+r.FormValue("state"), http.StatusTemporaryRedirect)
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"access_token","token_type":"bearer","refresh_token":"refresh_token","expiry":"2021-01-01T00:00:00Z"}`))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
}

func (s *Oauth2CallbackHandlerSuite) TearDownSuite() {
	s.oauth2Server.Close()
}

func (s *Oauth2CallbackHandlerSuite) SetupTest() {

}

type testCallbackRequestMode int

const (
	testCallbackErrNoStateCookie testCallbackRequestMode = iota
	testCallbackInvalidStateCookie
	testFailedExchange
)

func (s *Oauth2CallbackHandlerSuite) makeInputs(mode testCallbackRequestMode) (r *http.Request, config *oauth2.Config) {
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

	return
}

func (s *Oauth2CallbackHandlerSuite) TestErrNoStateCookie() {
	rr := httptest.NewRecorder()
	sesh := gosesh.New(nil, nil)
	request, config := s.makeInputs(testCallbackErrNoStateCookie)
	err := sesh.OAuth2Callback(rr, request, nil, config)
	s.EqualError(err, "failed getting state cookie: http: named cookie not present")
}

func (s *Oauth2CallbackHandlerSuite) TestErrInvalidStateCookie() {
	rr := httptest.NewRecorder()
	sesh := gosesh.New(nil, nil)
	request, config := s.makeInputs(testCallbackInvalidStateCookie)
	err := sesh.OAuth2Callback(rr, request, nil, config)
	s.EqualError(err, "invalid state cookie")
}

func (s *Oauth2CallbackHandlerSuite) TestFailedExchange() {
	rr := httptest.NewRecorder()
	sesh := gosesh.New(nil, nil)
	request, config := s.makeInputs(testFailedExchange)
	err := sesh.OAuth2Callback(rr, request, nil, config)
	s.EqualError(err, "failed exchanging token: oauth2: cannot fetch token: 404 Not Found\nResponse: not found\n")
}

func TestOauth2CallbackHandlerSuite(t *testing.T) {
	suite.Run(t, new(Oauth2CallbackHandlerSuite))
}
