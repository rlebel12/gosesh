package gosesh

import (
	"context"
	"net/http"

	"github.com/stretchr/testify/suite"
)

type MiddlewareSuite struct {
	suite.Suite
}

func (s *MiddlewareSuite) TestCurrentSession() {
	s.Run("valid", func() {
		r := new(http.Request)
		session := new(Session)
		ctx := context.WithValue(r.Context(), SessionContextKey, session)
		r = r.WithContext(ctx)

		actual, ok := CurrentSession(r)
		s.True(ok)
		s.Equal(session, actual)
	})

	s.Run("invalid", func() {
		r := new(http.Request)

		_, ok := CurrentSession(r)
		s.False(ok)
	})
}

// func (s *MiddlewareSuite) TestAuthenticatePrivate() {
// 	s.Run("already authenticated", func() {
// 		gs := new(Gosesh)
// 		r := new(http.Request)
// 		w := httptest.NewRecorder()
// 		session := new(Session)
// 		ctx := context.WithValue(r.Context(), SessionContextKey, session)
// 		result := gs.authenticate(w, r.WithContext(ctx))
// 		s.EqualRequestSession(session, result)
// 	})
// }

func (s *MiddlewareSuite) EqualRequestSession(expected *Session, actual *http.Request) {
	session, ok := CurrentSession(actual)
	s.True(ok)
	s.Equal(expected, session)
}
