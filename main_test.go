package gosesh

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type MainSuite struct {
	suite.Suite
}

func (s *MainSuite) SetupTest() {
}

func (s *MainSuite) TestGoseshSuite() {
	suite.Run(s.T(), new(GoseshSuite))
}

func TestMain(t *testing.T) {
	suite.Run(t, new(MainSuite))
}
