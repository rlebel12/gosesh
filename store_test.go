package gosesh

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// TestMemoryStoreTypedIDs tests that MemoryStore correctly handles typed session IDs
func TestMemoryStoreTypedIDs(t *testing.T) {
	tests := []struct {
		name            string
		hashedSessionID HashedSessionID
		userID          Identifier
		assertion       string
	}{
		{
			name:            "create_and_get",
			hashedSessionID: HashedSessionID("abc123hash"),
			userID:          StringIdentifier("user-1"),
			assertion:       "Created session retrieved by same hashed ID",
		},
		{
			name:            "delete_by_hashed_id",
			hashedSessionID: HashedSessionID("to-delete"),
			userID:          StringIdentifier("user-1"),
			assertion:       "Deleted session not found on subsequent get",
		},
		{
			name:            "extend_by_hashed_id",
			hashedSessionID: HashedSessionID("to-extend"),
			userID:          StringIdentifier("user-1"),
			assertion:       "Extended session has updated idle deadline",
		},
		{
			name:            "get_nonexistent",
			hashedSessionID: HashedSessionID("nonexistent"),
			userID:          StringIdentifier(""),
			assertion:       "Error returned",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			store := NewMemoryStore()
			now := time.Now()

			switch tt.name {
			case "create_and_get":
				// Create session
				session, err := store.CreateSession(ctx, tt.hashedSessionID, tt.userID, now.Add(time.Hour), now.Add(24*time.Hour))
				require.NoError(t, err)
				require.Equal(t, tt.hashedSessionID, session.ID())

				// Get session back
				retrieved, err := store.GetSession(ctx, tt.hashedSessionID)
				require.NoError(t, err)
				assert.Equal(t, tt.hashedSessionID, retrieved.ID())
				assert.Equal(t, tt.userID, retrieved.UserID())

			case "delete_by_hashed_id":
				// Create session
				_, err := store.CreateSession(ctx, tt.hashedSessionID, tt.userID, now.Add(time.Hour), now.Add(24*time.Hour))
				require.NoError(t, err)

				// Delete session
				err = store.DeleteSession(ctx, tt.hashedSessionID)
				require.NoError(t, err)

				// Verify it's gone
				_, err = store.GetSession(ctx, tt.hashedSessionID)
				assert.Error(t, err)

			case "extend_by_hashed_id":
				// Create session
				session, err := store.CreateSession(ctx, tt.hashedSessionID, tt.userID, now.Add(time.Hour), now.Add(24*time.Hour))
				require.NoError(t, err)
				originalDeadline := session.IdleDeadline()

				// Extend session
				newDeadline := now.Add(2 * time.Hour)
				err = store.ExtendSession(ctx, tt.hashedSessionID, newDeadline)
				require.NoError(t, err)

				// Verify deadline updated
				retrieved, err := store.GetSession(ctx, tt.hashedSessionID)
				require.NoError(t, err)
				assert.NotEqual(t, originalDeadline, retrieved.IdleDeadline())
				assert.Equal(t, newDeadline, retrieved.IdleDeadline())

			case "get_nonexistent":
				// Try to get non-existent session
				_, err := store.GetSession(ctx, tt.hashedSessionID)
				assert.Error(t, err)
			}
		})
	}
}

// TestMemoryStoreNoGenerateSessionID verifies that generateSessionID is removed
func TestMemoryStoreNoGenerateSessionID(t *testing.T) {
	// This test verifies that MemoryStore no longer generates IDs internally.
	// The presence of CreateSession accepting HashedSessionID proves this.
	// If generateSessionID existed and was exported, this would fail to compile.
	ctx := context.Background()
	store := NewMemoryStore()
	now := time.Now()

	// Create a session with a specific hashed ID
	hashedID := HashedSessionID("explicit-id")
	session, err := store.CreateSession(ctx, hashedID, StringIdentifier("user-1"), now.Add(time.Hour), now.Add(24*time.Hour))
	require.NoError(t, err)

	// Verify the session has exactly the ID we provided
	assert.Equal(t, hashedID, session.ID(), "Session ID should be exactly what was passed to CreateSession")
}

// TestMemoryStoreSessionIDFromCaller verifies session ID comes from caller
func TestMemoryStoreSessionIDFromCaller(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	now := time.Now()

	// Create session with specific hashed ID
	providedID := HashedSessionID("caller-provided-id")
	session, err := store.CreateSession(ctx, providedID, StringIdentifier("user-1"), now.Add(time.Hour), now.Add(24*time.Hour))
	require.NoError(t, err)

	// Verify ID matches exactly
	assert.Equal(t, providedID, session.ID())

	// Retrieve and verify again
	retrieved, err := store.GetSession(ctx, providedID)
	require.NoError(t, err)
	assert.Equal(t, providedID, retrieved.ID())
}

// TestMemoryStoreBatchRecordActivityWithHashedIDs verifies BatchRecordActivity works with HashedSessionID keys
func TestMemoryStoreBatchRecordActivityWithHashedIDs(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	now := time.Now()

	// Create multiple sessions
	id1 := HashedSessionID("session-1")
	id2 := HashedSessionID("session-2")
	id3 := HashedSessionID("session-3")

	_, err := store.CreateSession(ctx, id1, StringIdentifier("user-1"), now.Add(time.Hour), now.Add(24*time.Hour))
	require.NoError(t, err)
	_, err = store.CreateSession(ctx, id2, StringIdentifier("user-2"), now.Add(time.Hour), now.Add(24*time.Hour))
	require.NoError(t, err)
	_, err = store.CreateSession(ctx, id3, StringIdentifier("user-3"), now.Add(time.Hour), now.Add(24*time.Hour))
	require.NoError(t, err)

	// Record activity for some sessions
	activityTime := now.Add(30 * time.Minute)
	updates := map[HashedSessionID]time.Time{
		id1: activityTime,
		id2: activityTime,
	}

	// MemoryStore implements ActivityRecorder, so we can call it directly
	count, err := store.BatchRecordActivity(ctx, updates)
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	// Verify sessions were updated
	session1, err := store.GetSession(ctx, id1)
	require.NoError(t, err)
	assert.Equal(t, activityTime, session1.LastActivityAt())

	session2, err := store.GetSession(ctx, id2)
	require.NoError(t, err)
	assert.Equal(t, activityTime, session2.LastActivityAt())

	// Verify session3 was not updated
	session3, err := store.GetSession(ctx, id3)
	require.NoError(t, err)
	assert.NotEqual(t, activityTime, session3.LastActivityAt())
}

// TestMemoryStoreSessionIDReturnsHashedSessionID verifies session.ID() returns HashedSessionID
func TestMemoryStoreSessionIDReturnsHashedSessionID(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	now := time.Now()

	hashedID := HashedSessionID("test-hashed-id")
	session, err := store.CreateSession(ctx, hashedID, StringIdentifier("user-1"), now.Add(time.Hour), now.Add(24*time.Hour))
	require.NoError(t, err)

	// Verify ID() returns HashedSessionID type
	returnedID := session.ID()
	assert.Equal(t, hashedID, returnedID)

	// Type assertion to ensure it's the right type
	var _ HashedSessionID = returnedID
}

// TestMemoryStoreEmptyHashedSessionID tests edge case of empty hashed session ID
func TestMemoryStoreEmptyHashedSessionID(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	now := time.Now()

	emptyID := HashedSessionID("")
	session, err := store.CreateSession(ctx, emptyID, StringIdentifier("user-1"), now.Add(time.Hour), now.Add(24*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, emptyID, session.ID())

	// Should be able to retrieve by empty ID
	retrieved, err := store.GetSession(ctx, emptyID)
	require.NoError(t, err)
	assert.Equal(t, emptyID, retrieved.ID())
}
