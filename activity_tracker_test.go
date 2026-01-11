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
		tracker.Start(t.Context())
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
		tracker.Start(t.Context())
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
		tracker.Start(t.Context())
		defer tracker.Close()

		// Create a session
		userID := StringIdentifier("user-1")
		session, err := store.CreateSession(t.Context(), userID,
			time.Now().Add(1*time.Hour), time.Now().Add(24*time.Hour))
		require.NoError(t, err)

		originalActivity := session.LastActivityAt()
		time.Sleep(10 * time.Millisecond)

		// Record activity
		newActivity := time.Now().UTC()
		tracker.RecordActivity(session.ID().String(), newActivity)

		// Manual flush
		tracker.flush(t.Context())

		// Verify pending is cleared
		tracker.mu.Lock()
		assert.Empty(t, tracker.pending)
		tracker.mu.Unlock()

		// Verify store was updated
		updated, _ := store.GetSession(t.Context(), session.ID().String())
		assert.True(t, updated.LastActivityAt().After(originalActivity))
	})

	t.Run("automatic flush on interval", func(t *testing.T) {
		store := NewMemoryStore()
		tracker := NewActivityTracker(store, 50*time.Millisecond, slog.Default()) // Fast flush
		tracker.Start(t.Context())
		defer tracker.Close()

		// Create session
		userID := StringIdentifier("user-1")
		session, _ := store.CreateSession(t.Context(), userID,
			time.Now().Add(1*time.Hour), time.Now().Add(24*time.Hour))

		originalActivity := session.LastActivityAt()
		time.Sleep(10 * time.Millisecond)

		// Record activity
		tracker.RecordActivity(session.ID().String(), time.Now().UTC())

		// Wait for automatic flush
		time.Sleep(100 * time.Millisecond)

		// Verify was flushed
		updated, _ := store.GetSession(t.Context(), session.ID().String())
		assert.True(t, updated.LastActivityAt().After(originalActivity))
	})

	t.Run("flush on close", func(t *testing.T) {
		store := NewMemoryStore()
		tracker := NewActivityTracker(store, 1*time.Hour, slog.Default()) // Won't auto-flush
		tracker.Start(t.Context())

		// Create session
		userID := StringIdentifier("user-1")
		session, _ := store.CreateSession(t.Context(), userID,
			time.Now().Add(1*time.Hour), time.Now().Add(24*time.Hour))

		originalActivity := session.LastActivityAt()
		time.Sleep(10 * time.Millisecond)

		// Record activity
		tracker.RecordActivity(session.ID().String(), time.Now().UTC())

		// Close should trigger flush
		tracker.Close()

		// Verify was flushed
		updated, _ := store.GetSession(t.Context(), session.ID().String())
		assert.True(t, updated.LastActivityAt().After(originalActivity))
	})

	t.Run("handles concurrent recording safely", func(t *testing.T) {
		store := NewMemoryStore()
		tracker := NewActivityTracker(store, 1*time.Hour, slog.Default())
		tracker.Start(t.Context())
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
		tracker.Start(t.Context())
		defer tracker.Close()

		tracker.RecordActivity("session-1", time.Now().UTC())
		tracker.flush(t.Context())

		// Should log error
		assert.Contains(t, logs.logs[0], "flush activity batch")

		// Pending should be cleared even on error (to prevent memory buildup)
		tracker.mu.Lock()
		assert.Empty(t, tracker.pending)
		tracker.mu.Unlock()
	})

	t.Run("warns if Start called while already running", func(t *testing.T) {
		store := NewMemoryStore()
		logs := &testLogger{logs: []string{}}
		tracker := NewActivityTracker(store, 1*time.Hour, slog.New(slog.NewTextHandler(&testLogWriter{logger: logs}, nil)))

		// Start once
		tracker.Start(t.Context())
		defer tracker.Close()

		// Try to start again
		tracker.Start(t.Context())

		// Should have logged a warning
		assert.Len(t, logs.logs, 1)
		assert.Contains(t, logs.logs[0], "activity tracker already running")
	})

	t.Run("IsRunning returns correct status", func(t *testing.T) {
		store := NewMemoryStore()
		tracker := NewActivityTracker(store, 1*time.Hour, slog.Default())

		// Not running initially
		assert.False(t, tracker.IsRunning())

		// Running after Start
		tracker.Start(t.Context())
		assert.True(t, tracker.IsRunning())

		// Not running after Close
		tracker.Close()
		// Give it a moment to clean up
		time.Sleep(10 * time.Millisecond)
		assert.False(t, tracker.IsRunning())
	})

	t.Run("can restart after Close", func(t *testing.T) {
		store := NewMemoryStore()
		tracker := NewActivityTracker(store, 1*time.Hour, slog.Default())

		// Start, close, and restart
		tracker.Start(t.Context())
		assert.True(t, tracker.IsRunning())

		tracker.Close()
		time.Sleep(10 * time.Millisecond)
		assert.False(t, tracker.IsRunning())

		// Should be able to start again
		tracker.Start(t.Context())
		assert.True(t, tracker.IsRunning())

		tracker.Close()
	})

	t.Run("recovers from panic in store", func(t *testing.T) {
		// Create a store that panics on BatchRecordActivity
		panicStore := &panicingStore{
			Storer: NewMemoryStore(),
		}

		logs := &testLogger{logs: []string{}}
		// Use a short interval to trigger automatic flush
		tracker := NewActivityTracker(panicStore, 50*time.Millisecond, slog.New(slog.NewTextHandler(&testLogWriter{logger: logs}, nil)))
		tracker.Start(t.Context())

		// Record activity - this will trigger a panic during automatic flush
		tracker.RecordActivity("session-1", time.Now().UTC())

		// Wait for automatic flush to trigger and panic handler to execute
		time.Sleep(200 * time.Millisecond)

		// Should have logged panic
		var found bool
		for _, log := range logs.logs {
			if contains(log, "activity tracker panic") {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected panic log, got: %v", logs.logs)

		// Tracker should no longer be running after panic
		assert.False(t, tracker.IsRunning())

		tracker.Close()
	})
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// testLogWriter bridges between testLogger and slog
type testLogWriter struct {
	logger *testLogger
}

func (w *testLogWriter) Write(p []byte) (n int, err error) {
	return w.logger.Write(p)
}

// panicingStore panics when BatchRecordActivity is called
type panicingStore struct {
	Storer
}

func (s *panicingStore) BatchRecordActivity(ctx context.Context, updates map[string]time.Time) (int, error) {
	panic("simulated panic in BatchRecordActivity")
}
