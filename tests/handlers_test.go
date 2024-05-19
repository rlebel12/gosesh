package tests

import (
	"crypto/rand"
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
}

func (s *Oauth2CallbackHandlerSuite) config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     "client_id",
		ClientSecret: "client_secret",
		RedirectURL:  "http://localhost/auth/callback",
		Scopes:       []string{"email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:   "http://localhost/auth",
			TokenURL:  "http://localhost/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
}

type testCallbackRequestMode int

const (
	testCallbackErrNoStateCookie testCallbackRequestMode = iota
	testCallbackInvalidStateCookie
)

func (s *Oauth2CallbackHandlerSuite) request(mode testCallbackRequestMode) *http.Request {
	req, err := http.NewRequest(http.MethodGet, "http://localhost/auth/callback", nil)
	s.Require().NoError(err)

	if mode == testCallbackErrNoStateCookie {
		return req
	}

	req.AddCookie(&http.Cookie{
		Name:  "oauthstate",
		Value: "ZGV0ZXJtaW5pc3RpYyByYQ==",
	})
	if mode == testCallbackInvalidStateCookie {
		return req
	}

	return req
}

func (s *Oauth2CallbackHandlerSuite) TestErrNoStateCookie() {
	rr := httptest.NewRecorder()
	sesh := gosesh.New(nil, nil)
	err := sesh.OAuth2Callback(rr, s.request(testCallbackErrNoStateCookie), nil, &oauth2.Config{})
	s.EqualError(err, "failed getting state cookie: http: named cookie not present")
}

func (s *Oauth2CallbackHandlerSuite) TestErrInvalidStateCookie() {
	rr := httptest.NewRecorder()
	sesh := gosesh.New(nil, nil)
	err := sesh.OAuth2Callback(rr, s.request(testCallbackInvalidStateCookie), nil, &oauth2.Config{})
	s.EqualError(err, "invalid state cookie")
}

func TestOauth2CallbackHandlerSuite(t *testing.T) {
	suite.Run(t, new(Oauth2CallbackHandlerSuite))
}
