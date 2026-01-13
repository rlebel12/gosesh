package gosesh

import (
	"context"
	"log/slog"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGoseshHost(t *testing.T) {
	sesh := New(nil)
	assert.Equal(t, "localhost", sesh.Host())
}

func TestGoseshScheme(t *testing.T) {
	sesh := New(nil)
	assert.Equal(t, "http", sesh.Scheme())
}

func TestWithCookieDomain(t *testing.T) {
	origin, _ := url.Parse("https://example.com")
	sesh := New(nil,
		WithOrigin(origin),
		WithCookieDomain(func(g *Gosesh) func() string {
			return func() string {
				return "test." + g.Host()
			}
		}))
	assert.Equal(t, "test.example.com", sesh.CookieDomain())
}

func TestWithLogger(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	sesh := New(nil, WithLogger(logger))
	assert.Equal(t, logger, sesh.logger)
}

func TestWithActivityTracking(t *testing.T) {
	t.Run("creates activity tracker with specified interval", func(t *testing.T) {
		store := NewMemoryStore()
		gs := New(store, WithActivityTracking(ActivityTrackingConfig{FlushInterval: 100 * time.Millisecond}))
		gs.StartBackgroundTasks(t.Context())

		assert.NotNil(t, gs.activityTracker)
	})

	t.Run("nil when activity tracking not enabled", func(t *testing.T) {
		store := NewMemoryStore()
		gs := New(store)

		assert.Nil(t, gs.activityTracker)
	})

	t.Run("flushes on context cancellation", func(t *testing.T) {
		store := NewMemoryStore()
		gs := New(store, WithActivityTracking(ActivityTrackingConfig{FlushInterval: 1 * time.Hour})) // Won't auto-flush

		ctx, cancel := context.WithCancel(t.Context())
		errors := gs.StartBackgroundTasks(ctx)

		// Create session
		userID := StringIdentifier("user-1")
		session, _ := store.CreateSession(t.Context(), userID,
			time.Now().Add(1*time.Hour), time.Now().Add(24*time.Hour))

		originalActivity := session.LastActivityAt()
		time.Sleep(10 * time.Millisecond)

		// Record activity
		newActivity := time.Now().UTC()
		gs.activityTracker.RecordActivity(session.ID().String(), newActivity)

		// Cancel context to trigger flush
		cancel()
		// Wait for shutdown
		for range errors {
		}

		// Verify flushed
		updated, _ := store.GetSession(t.Context(), session.ID().String())
		assert.True(t, updated.LastActivityAt().After(originalActivity))
	})
}
