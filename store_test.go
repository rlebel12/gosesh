package gosesh

import (
	"testing"
)

func TestMemoryStore(t *testing.T) {
	StorerContract{
		NewStorer: func() Storer {
			return NewMemoryStore()
		},
	}.Test(t)
}
