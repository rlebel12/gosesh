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
	NewSession    func(id HashedSessionID, userID Identifier, idleDeadline, absoluteDeadline, lastActivityAt time.Time) Session
	NewIdentifier func(giveID string) Identifier
}

func (c SessionContract) Test(t *testing.T) {
	t.Run("returns correct values", func(t *testing.T) {
		id := HashedSessionID("session-id")
		userID := c.NewIdentifier("user-id")
		now := time.Now().UTC()
		idleDeadline := now.Add(time.Hour)
		absoluteDeadline := now.Add(24 * time.Hour)
		lastActivityAt := now

		session := c.NewSession(id, userID, idleDeadline, absoluteDeadline, lastActivityAt)

		assert.Equal(t, id, session.ID())
		assert.Equal(t, userID, session.UserID())
		assert.Equal(t, idleDeadline, session.IdleDeadline())
		assert.Equal(t, absoluteDeadline, session.AbsoluteDeadline())
		assert.Equal(t, lastActivityAt.Unix(), session.LastActivityAt().Unix())
	})

	t.Run("returns last activity timestamp", func(t *testing.T) {
		id := HashedSessionID("session-id")
		userID := c.NewIdentifier("user-id")
		now := time.Now().UTC()
		idleDeadline := now.Add(time.Hour)
		absoluteDeadline := now.Add(24 * time.Hour)
		lastActivityAt := now.Add(-5 * time.Minute) // Activity 5 minutes ago

		session := c.NewSession(id, userID, idleDeadline, absoluteDeadline, lastActivityAt)

		assert.Equal(t, lastActivityAt.Unix(), session.LastActivityAt().Unix())
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
		hashedID := HashedSessionID("test-hashed-id")
		userID := StringIdentifier("user-id")
		idleDeadline := time.Now()
		absoluteDeadline := time.Now().Add(time.Hour)
		store := c.NewStorer()

		gotSession, err := store.CreateSession(t.Context(), hashedID, userID, idleDeadline, absoluteDeadline)
		require.NoError(t, err)
		assert.Equal(t, "user-id", gotSession.UserID().String())
		assert.Equal(t, idleDeadline, gotSession.IdleDeadline())
		assert.Equal(t, absoluteDeadline, gotSession.AbsoluteDeadline())
		assert.Equal(t, hashedID, gotSession.ID())

		gotSession2, err := store.GetSession(t.Context(), hashedID)
		require.NoError(t, err)
		assert.Equal(t, "user-id", gotSession2.UserID().String())
		assert.Equal(t, idleDeadline, gotSession2.IdleDeadline())
		assert.Equal(t, absoluteDeadline, gotSession2.AbsoluteDeadline())

		assert.Equal(t, gotSession.ID(), gotSession2.ID())
	})

	t.Run("can delete one session", func(t *testing.T) {
		hashedID1 := HashedSessionID("test-hashed-id-1")
		hashedID2 := HashedSessionID("test-hashed-id-2")
		userID := StringIdentifier("user-id")
		idleDeadline := time.Now()
		absoluteDeadline := time.Now().Add(time.Hour)
		store := c.NewStorer()

		gotSession, err := store.CreateSession(t.Context(), hashedID1, userID, idleDeadline, absoluteDeadline)
		require.NoError(t, err)
		otherSession, err := store.CreateSession(t.Context(), hashedID2, userID, idleDeadline, absoluteDeadline)
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
		err := store.DeleteSession(t.Context(), HashedSessionID("non-existent-hashed-id"))
		assert.Error(t, err)
	})

	t.Run("can delete all sessions for a user", func(t *testing.T) {
		hashedID1 := HashedSessionID("test-hashed-id-1")
		hashedID2 := HashedSessionID("test-hashed-id-2")
		hashedID3 := HashedSessionID("test-hashed-id-3")
		userID := StringIdentifier("user-id")
		otherUserID := StringIdentifier("other-user-id")
		idleDeadline := time.Now()
		absoluteDeadline := time.Now().Add(time.Hour)
		store := c.NewStorer()

		gotSession, err := store.CreateSession(t.Context(), hashedID1, userID, idleDeadline, absoluteDeadline)
		require.NoError(t, err)
		anotherSession, err := store.CreateSession(t.Context(), hashedID2, userID, idleDeadline, absoluteDeadline)
		require.NoError(t, err)

		otherUserSession, err := store.CreateSession(t.Context(), hashedID3, otherUserID, idleDeadline, absoluteDeadline)
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

	t.Run("can extend an existing session", func(t *testing.T) {
		hashedID := HashedSessionID("test-hashed-id")
		userID := StringIdentifier("user-id")
		idleDeadline := time.Now()
		absoluteDeadline := time.Now().Add(time.Hour)
		store := c.NewStorer()

		gotSession, err := store.CreateSession(t.Context(), hashedID, userID, idleDeadline, absoluteDeadline)
		require.NoError(t, err)

		newIdleDeadline := time.Now().Add(30 * time.Minute)
		err = store.ExtendSession(t.Context(), gotSession.ID(), newIdleDeadline)
		require.NoError(t, err)

		// Verify the deadline was updated
		updatedSession, err := store.GetSession(t.Context(), gotSession.ID())
		require.NoError(t, err)
		assert.Equal(t, newIdleDeadline, updatedSession.IdleDeadline())
		assert.Equal(t, absoluteDeadline, updatedSession.AbsoluteDeadline()) // Should not change
	})

	t.Run("returns error when extending non-existent session", func(t *testing.T) {
		store := c.NewStorer()
		newIdleDeadline := time.Now().Add(30 * time.Minute)
		err := store.ExtendSession(t.Context(), HashedSessionID("non-existent-hashed-id"), newIdleDeadline)
		assert.Error(t, err)
	})

	t.Run("extend session updates deadline correctly", func(t *testing.T) {
		hashedID := HashedSessionID("test-hashed-id")
		userID := StringIdentifier("user-id")
		originalIdleDeadline := time.Now().Add(10 * time.Minute)
		absoluteDeadline := time.Now().Add(time.Hour)
		store := c.NewStorer()

		gotSession, err := store.CreateSession(t.Context(), hashedID, userID, originalIdleDeadline, absoluteDeadline)
		require.NoError(t, err)

		// Extend the session
		newIdleDeadline := time.Now().Add(20 * time.Minute)
		err = store.ExtendSession(t.Context(), gotSession.ID(), newIdleDeadline)
		require.NoError(t, err)

		// Verify persistence
		retrievedSession, err := store.GetSession(t.Context(), gotSession.ID())
		require.NoError(t, err)
		assert.Equal(t, newIdleDeadline, retrievedSession.IdleDeadline())
	})

	t.Run("extend session updates last activity timestamp", func(t *testing.T) {
		hashedID := HashedSessionID("test-hashed-id")
		userID := StringIdentifier("user-id")
		now := time.Now().UTC()
		idleDeadline := now.Add(10 * time.Minute)
		absoluteDeadline := now.Add(time.Hour)
		store := c.NewStorer()

		session, err := store.CreateSession(t.Context(), hashedID, userID, idleDeadline, absoluteDeadline)
		require.NoError(t, err)

		originalActivity := session.LastActivityAt()

		// Wait a moment to ensure timestamp difference
		time.Sleep(10 * time.Millisecond)

		// Extend the session
		newIdleDeadline := now.Add(20 * time.Minute)
		err = store.ExtendSession(t.Context(), session.ID(), newIdleDeadline)
		require.NoError(t, err)

		// Verify last activity was updated
		updatedSession, err := store.GetSession(t.Context(), session.ID())
		require.NoError(t, err)
		assert.True(t, updatedSession.LastActivityAt().After(originalActivity),
			"LastActivityAt should be updated during ExtendSession")
	})
}

type ActivityRecorderContract struct {
	NewStorer func() Storer // Must also implement ActivityRecorder
}

func (c ActivityRecorderContract) Test(t *testing.T) {
	t.Run("batch record activity updates multiple sessions", func(t *testing.T) {
		store := c.NewStorer()
		recorder := store.(ActivityRecorder) // Type assertion

		hashedID1 := HashedSessionID("test-hashed-id-1")
		hashedID2 := HashedSessionID("test-hashed-id-2")
		hashedID3 := HashedSessionID("test-hashed-id-3")
		userID := StringIdentifier("user-id")
		now := time.Now().UTC()

		// Create 3 sessions
		session1, _ := store.CreateSession(t.Context(), hashedID1, userID, now.Add(1*time.Hour), now.Add(24*time.Hour))
		session2, _ := store.CreateSession(t.Context(), hashedID2, userID, now.Add(1*time.Hour), now.Add(24*time.Hour))
		session3, _ := store.CreateSession(t.Context(), hashedID3, userID, now.Add(1*time.Hour), now.Add(24*time.Hour))

		time.Sleep(10 * time.Millisecond)

		// Batch update
		activityTime := time.Now().UTC()
		updates := map[HashedSessionID]time.Time{
			session1.ID(): activityTime,
			session2.ID(): activityTime,
		}

		count, err := recorder.BatchRecordActivity(t.Context(), updates)
		require.NoError(t, err)
		assert.Equal(t, 2, count)

		// Verify session1 updated
		updated1, _ := store.GetSession(t.Context(), session1.ID())
		assert.Equal(t, activityTime.Unix(), updated1.LastActivityAt().Unix())

		// Verify session2 updated
		updated2, _ := store.GetSession(t.Context(), session2.ID())
		assert.Equal(t, activityTime.Unix(), updated2.LastActivityAt().Unix())

		// Verify session3 NOT updated
		updated3, _ := store.GetSession(t.Context(), session3.ID())
		assert.True(t, updated3.LastActivityAt().Before(activityTime))
	})

	t.Run("batch record activity handles non-existent sessions gracefully", func(t *testing.T) {
		store := c.NewStorer()
		recorder := store.(ActivityRecorder)
		now := time.Now().UTC()

		updates := map[HashedSessionID]time.Time{
			HashedSessionID("non-existent-1"): now,
			HashedSessionID("non-existent-2"): now,
		}

		count, err := recorder.BatchRecordActivity(t.Context(), updates)
		require.NoError(t, err)
		assert.Equal(t, 0, count) // No sessions updated
	})

	t.Run("batch record activity handles empty map", func(t *testing.T) {
		store := c.NewStorer()
		recorder := store.(ActivityRecorder)
		updates := map[HashedSessionID]time.Time{}

		count, err := recorder.BatchRecordActivity(t.Context(), updates)
		require.NoError(t, err)
		assert.Equal(t, 0, count)
	})
}
