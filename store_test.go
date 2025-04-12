package gosesh

import (
	"testing"

	"github.com/rlebel12/gosesh/internal"
)

func TestMemoryStore(t *testing.T) {
	StorerContract{
		NewStorer: func() Storer {
			return NewMemoryStore()
		},
		NewOAuth2User: func(giveID string) OAuth2User {
			return internal.NewFakeOAuth2User(giveID)
		},
		NewIdentifier: func(giveID string) Identifier {
			return internal.NewFakeIdentifier(giveID)
		},
	}.Test(t)
}
