package gosesh

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type StorerContract struct {
	NewStorer func() Storer
}

func (c StorerContract) Test(t *testing.T) {
	t.Run("can upsert the same user in idempotent way", func(t *testing.T) {
		oauth2User := &OAuth2UserMock{
			StringFunc: func() string { return "user-id" },
		}
		store := c.NewStorer()
		gotUser1, err := store.UpsertUser(t.Context(), oauth2User)
		require.NoError(t, err)
		assert.Equal(t, "user-id", gotUser1.String())

		gotUser2, err := store.UpsertUser(t.Context(), oauth2User)
		require.NoError(t, err)
		assert.Equal(t, "user-id", gotUser2.String())

		assert.Equal(t, gotUser1.String(), gotUser2.String())

		anotherUser := &OAuth2UserMock{
			StringFunc: func() string { return "another-user-id" },
		}
		gotUser3, err := store.UpsertUser(t.Context(), anotherUser)
		require.NoError(t, err)
		assert.Equal(t, "another-user-id", gotUser3.String())

		assert.NotEqual(t, gotUser1.String(), gotUser3.String())
	})

	t.Run("can create and get a session", func(t *testing.T) {
		req := CreateSessionRequest{
			UserID:   &IdentifierMock{StringFunc: func() string { return "user-id" }},
			IdleAt:   time.Now(),
			ExpireAt: time.Now().Add(time.Hour),
		}
		store := c.NewStorer()

		gotSession, err := store.CreateSession(t.Context(), req)
		require.NoError(t, err)
		assert.Equal(t, "user-id", gotSession.UserID().String())
		assert.Equal(t, req.IdleAt, gotSession.IdleAt())
		assert.Equal(t, req.ExpireAt, gotSession.ExpireAt())

		gotSession2, err := store.GetSession(t.Context(), gotSession.ID())
		require.NoError(t, err)
		assert.Equal(t, "user-id", gotSession2.UserID().String())
		assert.Equal(t, req.IdleAt, gotSession2.IdleAt())
		assert.Equal(t, req.ExpireAt, gotSession2.ExpireAt())

		assert.Equal(t, gotSession.ID(), gotSession2.ID())
	})

	t.Run("can delete one session", func(t *testing.T) {
		req := CreateSessionRequest{
			UserID: &IdentifierMock{StringFunc: func() string { return "user-id" }},
		}
		store := c.NewStorer()

		gotSession, err := store.CreateSession(t.Context(), req)
		require.NoError(t, err)
		otherSession, err := store.CreateSession(t.Context(), req)
		require.NoError(t, err)

		err = store.DeleteSession(t.Context(), gotSession.ID())
		require.NoError(t, err)

		_, err = store.GetSession(t.Context(), gotSession.ID())
		assert.Error(t, err)

		_, err = store.GetSession(t.Context(), otherSession.ID())
		assert.NoError(t, err)
	})

	t.Run("can delete all sessions for a user", func(t *testing.T) {
		userID := &IdentifierMock{StringFunc: func() string { return "user-id" }}
		otherUserID := &IdentifierMock{StringFunc: func() string { return "other-user-id" }}
		req := CreateSessionRequest{
			UserID: userID,
		}
		store := c.NewStorer()

		gotSession, err := store.CreateSession(t.Context(), req)
		require.NoError(t, err)
		anotherSession, err := store.CreateSession(t.Context(), req)
		require.NoError(t, err)

		otherUserSession, err := store.CreateSession(t.Context(), CreateSessionRequest{
			UserID: otherUserID,
		})
		require.NoError(t, err)

		deleted, err := store.DeleteUserSessions(t.Context(), userID)
		require.NoError(t, err)
		assert.Equal(t, 2, deleted)

		_, err = store.GetSession(t.Context(), gotSession.ID())
		assert.Error(t, err)

		_, err = store.GetSession(t.Context(), anotherSession.ID())
		assert.Error(t, err)

		_, err = store.GetSession(t.Context(), otherUserSession.ID())
		assert.NoError(t, err)
	})
}

func TestMemoryStore(t *testing.T) {
	StorerContract{NewStorer: func() Storer {
		return NewMemoryStore()
	}}.Test(t)
}
