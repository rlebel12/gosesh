package tests

import (
	"log/slog"
	"net/url"
	"testing"
	"time"

	"github.com/rlebel12/gosesh"
	mocks "github.com/rlebel12/gosesh/mocks"
	"github.com/stretchr/testify/suite"
)

type NewSuite struct {
	suite.Suite
	parser gosesh.IDParser
	store  gosesh.Storer
}

func (s *NewSuite) SetupTest() {
	s.parser = mocks.NewIDParser(s.T())
	s.store = mocks.NewStorer(s.T())
}

func (s *NewSuite) new(opts ...gosesh.NewOpts) *gosesh.Gosesh {
	return gosesh.New(s.parser, s.store, opts...)
}

func (s *NewSuite) defaultConfig() gosesh.Config {
	url, _ := url.Parse("http://localhost")
	return gosesh.Config{
		SessionCookieName:     "session",
		OAuth2StateCookieName: "oauthstate",
		SessionIdleDuration:   24 * time.Hour,
		SessionActiveDuration: 1 * time.Hour,
		Origin:                *url,
		Now:                   time.Now,
	}
}

func (s *NewSuite) equalSuite(sesh *gosesh.Gosesh, expectedConfig gosesh.Config) {
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
	actual := s.new(gosesh.WithSessionCookieName("foo"))
	expectedConfig := s.defaultConfig()
	expectedConfig.SessionCookieName = "foo"
	s.equalSuite(actual, expectedConfig)
}

func (s *NewSuite) TestWithOAuth2StateCookieName() {
	actual := s.new(gosesh.WithOAuth2StateCookieName("foo"))
	expectedConfig := s.defaultConfig()
	expectedConfig.OAuth2StateCookieName = "foo"
	s.equalSuite(actual, expectedConfig)
}

func (s *NewSuite) TestWithSessionIdleDuration() {
	actual := s.new(gosesh.WithSessionIdleDuration(1 * time.Second))
	expectedConfig := s.defaultConfig()
	expectedConfig.SessionIdleDuration = 1 * time.Second
	s.equalSuite(actual, expectedConfig)
}

func (s *NewSuite) TestWithSessionActiveDuration() {
	actual := s.new(gosesh.WithSessionActiveDuration(1 * time.Second))
	expectedConfig := s.defaultConfig()
	expectedConfig.SessionActiveDuration = 1 * time.Second
	s.equalSuite(actual, expectedConfig)
}

func (s *NewSuite) TestWithOrigin() {
	url, err := url.ParseRequestURI("http://example.com")
	s.Require().NoError(err)
	actual := s.new(gosesh.WithOrigin(*url))
	expectedConfig := s.defaultConfig()
	expectedConfig.Origin = *url
	s.equalSuite(actual, expectedConfig)
}

func (s *NewSuite) TestWithLogger() {
	logger := new(slog.Logger)
	actual := s.new(gosesh.WithLogger(logger))
	expectedConfig := s.defaultConfig()
	expectedConfig.Logger = logger
	s.Equal(expectedConfig.Logger, actual.Config().Logger)
}

func TestNewSuite(t *testing.T) {
	suite.Run(t, new(NewSuite))
}
