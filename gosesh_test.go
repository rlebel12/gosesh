package gosesh

import (
	"github.com/stretchr/testify/suite"
)

type GoseshSuite struct {
	suite.Suite
}

func (s *GoseshSuite) TestNew() {
	store := NewMockStorer(s.T())
	gs := New(store)
	s.Equal(store, gs.Store)
	s.True(true)
}
