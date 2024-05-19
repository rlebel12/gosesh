package providers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rlebel12/gosesh"
	mock_providers "github.com/rlebel12/gosesh/mocks/providers"
	"github.com/stretchr/testify/suite"
)

type DiscordSuite struct {
	suite.Suite
}

func (s *DiscordSuite) TestOAuth2Begin() {
	var success bool
	sesh := mock_providers.NewGosesher(s.T())
	sesh.EXPECT().Scheme().Return("http")
	sesh.EXPECT().Host().Return("localhost")
	discord := NewDiscord(sesh, DiscordScopes{Email: true}, gosesh.OAuth2Credentials{
		ClientID:     "clientID",
		ClientSecret: "clientSecret",
	})
	sesh.EXPECT().OAuth2Begin(discord.cfg).Return(func(w http.ResponseWriter, r *http.Request) {
		success = true
	})

	rr := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	discord.OAuth2Begin(rr, r)

	result := rr.Result()
	s.True(success)
	_ = result
}

func (s *DiscordSuite) TestOAuth2Callback() {
	sesh := mock_providers.NewGosesher(s.T())
	sesh.EXPECT().Scheme().Return("http")
	sesh.EXPECT().Host().Return("localhost")
	discord := NewDiscord(sesh, DiscordScopes{Email: true}, gosesh.OAuth2Credentials{
		ClientID:     "clientID",
		ClientSecret: "clientSecret",
	})
	rr := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	sesh.EXPECT().OAuth2Callback(rr, r, new(DiscordUser), discord.cfg).Return(nil)

	err := discord.OAuth2Callback(rr, r)
	s.NoError(err)
}

func (s *DiscordSuite) TestUserRequest() {
	mux := http.NewServeMux()
	expectedUser := DiscordUser{
		ID:       "123",
		Username: "username",
		Email:    "gosesh@example.com",
		Verified: true,
	}
	mux.HandleFunc("GET /api/v9/users/@me", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(expectedUser); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	user := DiscordUser{testHost: &server.URL}

	resp, err := user.Request(context.Background(), "accessToken")
	s.Require().NoError(err)
	var actualUser DiscordUser
	content, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	err = actualUser.Unmarshal(content)
	s.Require().NoError(err)

	s.T().Run("TestFailedCreatingRequest", func(t *testing.T) {
		badURL := "\n"
		user := DiscordUser{testHost: &badURL}
		_, err := user.Request(context.Background(), "accessToken")
		s.Error(err)
	})
}

func TestDiscordSuite(t *testing.T) {
	suite.Run(t, new(DiscordSuite))
}
