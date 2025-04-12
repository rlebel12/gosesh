package gosesh

import (
	"context"
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

type OAuth2UserContract struct {
	NewOAuth2User func(giveID string) OAuth2User
}

func (c OAuth2UserContract) Test(t *testing.T) {
	t.Run("returns correct ID", func(t *testing.T) {
		user := c.NewOAuth2User("test-id")
		assert.Equal(t, "test-id", user.String())
	})

	t.Run("can make requests", func(t *testing.T) {
		user := c.NewOAuth2User("test-id")
		resp, err := user.Request(context.Background(), "test-token")
		require.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("can unmarshal data", func(t *testing.T) {
		user := c.NewOAuth2User("test-id")
		err := user.Unmarshal([]byte("test-data"))
		require.NoError(t, err)
	})
}

type OAuth2CredentialsContract struct {
	NewOAuth2Credentials func(giveClientID, giveClientSecret string) OAuth2Credentials
}

func (c OAuth2CredentialsContract) Test(t *testing.T) {
	t.Run("returns correct client ID and secret", func(t *testing.T) {
		creds := c.NewOAuth2Credentials("client-id", "client-secret")
		assert.Equal(t, "client-id", creds.ClientID())
		assert.Equal(t, "client-secret", creds.ClientSecret())
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
	NewStorer     func() Storer
	NewOAuth2User func(giveID string) OAuth2User
	NewIdentifier func(giveID string) Identifier
}

func (c StorerContract) Test(t *testing.T) {
	t.Run("can upsert the same user in idempotent way", func(t *testing.T) {
		oauth2User := c.NewOAuth2User("user-id")
		store := c.NewStorer()
		gotUser1, err := store.UpsertUser(t.Context(), oauth2User)
		require.NoError(t, err)
		assert.Equal(t, "user-id", gotUser1.String())

		gotUser2, err := store.UpsertUser(t.Context(), oauth2User)
		require.NoError(t, err)
		assert.Equal(t, "user-id", gotUser2.String())

		assert.Equal(t, gotUser1.String(), gotUser2.String())

		anotherUser := c.NewOAuth2User("another-user-id")
		gotUser3, err := store.UpsertUser(t.Context(), anotherUser)
		require.NoError(t, err)
		assert.Equal(t, "another-user-id", gotUser3.String())

		assert.NotEqual(t, gotUser1.String(), gotUser3.String())
	})

	t.Run("can create and get a session", func(t *testing.T) {
		req := CreateSessionRequest{
			UserID:   c.NewIdentifier("user-id"),
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
			UserID: c.NewIdentifier("user-id"),
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

	t.Run("returns error when deleting non-existent session", func(t *testing.T) {
		store := c.NewStorer()
		err := store.DeleteSession(t.Context(), c.NewIdentifier("non-existent-session-id"))
		assert.Error(t, err)
	})

	t.Run("can delete all sessions for a user", func(t *testing.T) {
		userID := c.NewIdentifier("user-id")
		otherUserID := c.NewIdentifier("other-user-id")
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
