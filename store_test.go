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

func TestMemoryStoreActivityRecorder(t *testing.T) {
	ActivityRecorderContract{
		NewStorer: func() Storer {
			return NewMemoryStore()
		},
	}.Test(t)
}
