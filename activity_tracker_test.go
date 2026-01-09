package gosesh

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActivityTracker(t *testing.T) {
	t.Run("records activity in pending map", func(t *testing.T) {
		store := NewMemoryStore()
		tracker := NewActivityTracker(store, 1*time.Hour, slog.Default()) // Long interval, won't flush
		defer tracker.Close()

		now := time.Now().UTC()
		tracker.RecordActivity("session-1", now)

		tracker.mu.Lock()
		timestamp, exists := tracker.pending["session-1"]
		tracker.mu.Unlock()

		assert.True(t, exists)
		assert.Equal(t, now.Unix(), timestamp.Unix())
	})

	t.Run("keeps latest timestamp for duplicate session IDs", func(t *testing.T) {
		store := NewMemoryStore()
		tracker := NewActivityTracker(store, 1*time.Hour, slog.Default())
		defer tracker.Close()

		time1 := time.Now().UTC()
		time2 := time1.Add(5 * time.Second)

		tracker.RecordActivity("session-1", time1)
		tracker.RecordActivity("session-1", time2)

		tracker.mu.Lock()
		timestamp := tracker.pending["session-1"]
		tracker.mu.Unlock()

		assert.Equal(t, time2.Unix(), timestamp.Unix())
	})

	t.Run("flush writes pending activities to store", func(t *testing.T) {
		store := NewMemoryStore()
		tracker := NewActivityTracker(store, 1*time.Hour, slog.Default())
		defer tracker.Close()

		// Create a session
		userID := StringIdentifier("user-1")
		session, err := store.CreateSession(context.Background(), userID,
			time.Now().Add(1*time.Hour), time.Now().Add(24*time.Hour))
		require.NoError(t, err)

		originalActivity := session.LastActivityAt()
		time.Sleep(10 * time.Millisecond)

		// Record activity
		newActivity := time.Now().UTC()
		tracker.RecordActivity(session.ID().String(), newActivity)

		// Manual flush
		tracker.flush()

		// Verify pending is cleared
		tracker.mu.Lock()
		assert.Empty(t, tracker.pending)
		tracker.mu.Unlock()

		// Verify store was updated
		updated, _ := store.GetSession(context.Background(), session.ID().String())
		assert.True(t, updated.LastActivityAt().After(originalActivity))
	})

	t.Run("automatic flush on interval", func(t *testing.T) {
		store := NewMemoryStore()
		tracker := NewActivityTracker(store, 50*time.Millisecond, slog.Default()) // Fast flush
		defer tracker.Close()

		// Create session
		userID := StringIdentifier("user-1")
		session, _ := store.CreateSession(context.Background(), userID,
			time.Now().Add(1*time.Hour), time.Now().Add(24*time.Hour))

		originalActivity := session.LastActivityAt()
		time.Sleep(10 * time.Millisecond)

		// Record activity
		tracker.RecordActivity(session.ID().String(), time.Now().UTC())

		// Wait for automatic flush
		time.Sleep(100 * time.Millisecond)

		// Verify was flushed
		updated, _ := store.GetSession(context.Background(), session.ID().String())
		assert.True(t, updated.LastActivityAt().After(originalActivity))
	})

	t.Run("flush on close", func(t *testing.T) {
		store := NewMemoryStore()
		tracker := NewActivityTracker(store, 1*time.Hour, slog.Default()) // Won't auto-flush

		// Create session
		userID := StringIdentifier("user-1")
		session, _ := store.CreateSession(context.Background(), userID,
			time.Now().Add(1*time.Hour), time.Now().Add(24*time.Hour))

		originalActivity := session.LastActivityAt()
		time.Sleep(10 * time.Millisecond)

		// Record activity
		tracker.RecordActivity(session.ID().String(), time.Now().UTC())

		// Close should trigger flush
		tracker.Close()

		// Verify was flushed
		updated, _ := store.GetSession(context.Background(), session.ID().String())
		assert.True(t, updated.LastActivityAt().After(originalActivity))
	})

	t.Run("handles concurrent recording safely", func(t *testing.T) {
		store := NewMemoryStore()
		tracker := NewActivityTracker(store, 1*time.Hour, slog.Default())
		defer tracker.Close()

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				sessionID := "session-" + string(rune(id))
				tracker.RecordActivity(sessionID, time.Now().UTC())
			}(i)
		}

		wg.Wait()

		tracker.mu.Lock()
		count := len(tracker.pending)
		tracker.mu.Unlock()

		assert.Equal(t, 100, count)
	})

	t.Run("logs flush errors but continues", func(t *testing.T) {
		// Use erroring store
		errorStore := &erroringStore{
			Storer:                 NewMemoryStore(),
			BatchRecordActivityErr: errors.New("database connection failed"),
		}

		logs := &testLogger{logs: []string{}}
		tracker := NewActivityTracker(errorStore, 1*time.Hour, slog.New(slog.NewTextHandler(&testLogWriter{logger: logs}, nil)))
		defer tracker.Close()

		tracker.RecordActivity("session-1", time.Now().UTC())
		tracker.flush()

		// Should log error
		assert.Contains(t, logs.logs[0], "failed to flush activity batch")

		// Pending should be cleared even on error (to prevent memory buildup)
		tracker.mu.Lock()
		assert.Empty(t, tracker.pending)
		tracker.mu.Unlock()
	})
}

// testLogWriter bridges between testLogger and slog
type testLogWriter struct {
	logger *testLogger
}

func (w *testLogWriter) Write(p []byte) (n int, err error) {
	return w.logger.Write(p)
}
