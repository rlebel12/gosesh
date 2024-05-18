package gosesh

import (
	"log/slog"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type NewSuite struct {
	suite.Suite
	parser IDParser
	store  Storer
}

func (s *NewSuite) SetupTest() {
	s.parser = nil
	s.store = nil
}

func (s *NewSuite) new(opts ...NewOpts) *Gosesh {
	return New(s.parser, s.store, opts...)
}

func (s *NewSuite) defaultConfig() Config {
	url, _ := url.Parse("http://localhost")
	return Config{
		SessionCookieName:     "session",
		OAuth2StateCookieName: "oauthstate",
		SessionIdleDuration:   24 * time.Hour,
		SessionActiveDuration: 1 * time.Hour,
		Origin:                *url,
		Now:                   time.Now,
	}
}

func (s *NewSuite) equalSuite(sesh *Gosesh, expectedConfig Config) {
	s.Equal(s.parser, sesh.IDParser())
	s.Equal(s.store, sesh.Storer())
	s.Nil(sesh.Logger())
	s.Equal(expectedConfig.SessionCookieName, sesh.Config().SessionCookieName)
	s.Equal(expectedConfig.OAuth2StateCookieName, sesh.Config().OAuth2StateCookieName)
	s.Equal(expectedConfig.SessionIdleDuration, sesh.Config().SessionIdleDuration)
	s.Equal(expectedConfig.SessionActiveDuration, sesh.Config().SessionActiveDuration)
	s.Equal(expectedConfig.Origin, sesh.Config().Origin)
}

func (s *NewSuite) TestDefault() {
	actual := s.new()
	expectedConfig := s.defaultConfig()
	s.equalSuite(actual, expectedConfig)
}

func (s *NewSuite) TestWithSessionCookieName() {
	actual := s.new(WithSessionCookieName("foo"))
	expectedConfig := s.defaultConfig()
	expectedConfig.SessionCookieName = "foo"
	s.equalSuite(actual, expectedConfig)
}

func (s *NewSuite) TestWithOAuth2StateCookieName() {
	actual := s.new(WithOAuth2StateCookieName("foo"))
	expectedConfig := s.defaultConfig()
	expectedConfig.OAuth2StateCookieName = "foo"
	s.equalSuite(actual, expectedConfig)
}

func (s *NewSuite) TestWithSessionIdleDuration() {
	actual := s.new(WithSessionIdleDuration(1 * time.Second))
	expectedConfig := s.defaultConfig()
	expectedConfig.SessionIdleDuration = 1 * time.Second
	s.equalSuite(actual, expectedConfig)
}

func (s *NewSuite) TestWithSessionActiveDuration() {
	actual := s.new(WithSessionActiveDuration(1 * time.Second))
	expectedConfig := s.defaultConfig()
	expectedConfig.SessionActiveDuration = 1 * time.Second
	s.equalSuite(actual, expectedConfig)
}

func (s *NewSuite) TestWithOrigin() {
	url, err := url.ParseRequestURI("http://example.com")
	s.Require().NoError(err)
	actual := s.new(WithOrigin(*url))
	expectedConfig := s.defaultConfig()
	expectedConfig.Origin = *url
	s.equalSuite(actual, expectedConfig)
}

func (s *NewSuite) TestWithLogger() {
	logger := new(slog.Logger)
	actual := s.new(WithLogger(logger))
	expectedConfig := s.defaultConfig()
	expectedConfig.Logger = logger
	s.Equal(expectedConfig.Logger, actual.Config().Logger)
}

func TestNewSuite(t *testing.T) {
	suite.Run(t, new(NewSuite))
}
