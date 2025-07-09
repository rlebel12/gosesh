package gosesh

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type IdentifierContract struct {
	NewIdentifier func(giveID string) Identifier
}

func (c IdentifierContract) Test(t *testing.T) {
	t.Run("returns correct ID", func(t *testing.T) {
		id := c.NewIdentifier("test-id")
		assert.Equal(t, "test-id", id.String())
	})

	t.Run("different IDs are not equal", func(t *testing.T) {
		id1 := c.NewIdentifier("id1")
		id2 := c.NewIdentifier("id2")
		assert.NotEqual(t, id1.String(), id2.String())
	})
}

type SessionContract struct {
	NewSession    func(id, userID Identifier, idleAt, expireAt time.Time) Session
	NewIdentifier func(giveID string) Identifier
}

func (c SessionContract) Test(t *testing.T) {
	t.Run("returns correct values", func(t *testing.T) {
		id := c.NewIdentifier("session-id")
		userID := c.NewIdentifier("user-id")
		idleAt := time.Now()
		expireAt := time.Now().Add(time.Hour)

		session := c.NewSession(id, userID, idleAt, expireAt)

		assert.Equal(t, id, session.ID())
		assert.Equal(t, userID, session.UserID())
		assert.Equal(t, idleAt, session.IdleAt())
		assert.Equal(t, expireAt, session.ExpireAt())
	})
}

type StorerContract struct {
	NewStorer func() Storer
}

func (c StorerContract) Test(t *testing.T) {
	t.Run("can upsert the same user in idempotent way", func(t *testing.T) {
		authProviderID := StringIdentifier("user-id")
		store := c.NewStorer()
		gotUser1, err := store.UpsertUser(t.Context(), authProviderID)
		require.NoError(t, err)
		assert.Equal(t, "user-id", gotUser1.String())

		gotUser2, err := store.UpsertUser(t.Context(), authProviderID)
		require.NoError(t, err)
		assert.Equal(t, "user-id", gotUser2.String())

		assert.Equal(t, gotUser1.String(), gotUser2.String())

		anotherAuthProviderID := StringIdentifier("another-user-id")
		gotUser3, err := store.UpsertUser(t.Context(), anotherAuthProviderID)
		require.NoError(t, err)
		assert.Equal(t, "another-user-id", gotUser3.String())

		assert.NotEqual(t, gotUser1.String(), gotUser3.String())
	})

	t.Run("can create and get a session", func(t *testing.T) {
		userID := StringIdentifier("user-id")
		idleAt := time.Now()
		expireAt := time.Now().Add(time.Hour)
		store := c.NewStorer()

		gotSession, err := store.CreateSession(t.Context(), userID, idleAt, expireAt)
		require.NoError(t, err)
		assert.Equal(t, "user-id", gotSession.UserID().String())
		assert.Equal(t, idleAt, gotSession.IdleAt())
		assert.Equal(t, expireAt, gotSession.ExpireAt())

		gotSession2, err := store.GetSession(t.Context(), gotSession.ID().String())
		require.NoError(t, err)
		assert.Equal(t, "user-id", gotSession2.UserID().String())
		assert.Equal(t, idleAt, gotSession2.IdleAt())
		assert.Equal(t, expireAt, gotSession2.ExpireAt())

		assert.Equal(t, gotSession.ID(), gotSession2.ID())
	})

	t.Run("can delete one session", func(t *testing.T) {
		userID := StringIdentifier("user-id")
		idleAt := time.Now()
		expireAt := time.Now().Add(time.Hour)
		store := c.NewStorer()

		gotSession, err := store.CreateSession(t.Context(), userID, idleAt, expireAt)
		require.NoError(t, err)
		otherSession, err := store.CreateSession(t.Context(), userID, idleAt, expireAt)
		require.NoError(t, err)

		err = store.DeleteSession(t.Context(), gotSession.ID().String())
		require.NoError(t, err)

		_, err = store.GetSession(t.Context(), gotSession.ID().String())
		assert.Error(t, err)

		_, err = store.GetSession(t.Context(), otherSession.ID().String())
		assert.NoError(t, err)
	})

	t.Run("returns error when deleting non-existent session", func(t *testing.T) {
		store := c.NewStorer()
		err := store.DeleteSession(t.Context(), "non-existent-session-id")
		assert.Error(t, err)
	})

	t.Run("can delete all sessions for a user", func(t *testing.T) {
		userID := StringIdentifier("user-id")
		otherUserID := StringIdentifier("other-user-id")
		idleAt := time.Now()
		expireAt := time.Now().Add(time.Hour)
		store := c.NewStorer()

		gotSession, err := store.CreateSession(t.Context(), userID, idleAt, expireAt)
		require.NoError(t, err)
		anotherSession, err := store.CreateSession(t.Context(), userID, idleAt, expireAt)
		require.NoError(t, err)

		otherUserSession, err := store.CreateSession(t.Context(), otherUserID, idleAt, expireAt)
		require.NoError(t, err)

		deleted, err := store.DeleteUserSessions(t.Context(), userID)
		require.NoError(t, err)
		assert.Equal(t, 2, deleted)

		_, err = store.GetSession(t.Context(), gotSession.ID().String())
		assert.Error(t, err)

		_, err = store.GetSession(t.Context(), anotherSession.ID().String())
		assert.Error(t, err)

		_, err = store.GetSession(t.Context(), otherUserSession.ID().String())
		assert.NoError(t, err)
	})
}
