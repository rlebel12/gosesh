package gosesh

import (
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
		gs := New(store, WithActivityTracking(100*time.Millisecond))
		gs.Start(t.Context())
		defer gs.Close()

		assert.NotNil(t, gs.activityTracker)
	})

	t.Run("nil when activity tracking not enabled", func(t *testing.T) {
		store := NewMemoryStore()
		gs := New(store)

		assert.Nil(t, gs.activityTracker)
	})
}

func TestGoseshClose(t *testing.T) {
	t.Run("flushes activity tracker on close", func(t *testing.T) {
		store := NewMemoryStore()
		gs := New(store, WithActivityTracking(1*time.Hour)) // Won't auto-flush
		gs.Start(t.Context())

		// Create session
		userID := StringIdentifier("user-1")
		session, _ := store.CreateSession(t.Context(), userID,
			time.Now().Add(1*time.Hour), time.Now().Add(24*time.Hour))

		originalActivity := session.LastActivityAt()
		time.Sleep(10 * time.Millisecond)

		// Record activity
		newActivity := time.Now().UTC()
		gs.activityTracker.RecordActivity(session.ID().String(), newActivity)

		// Close should flush
		gs.Close()

		// Verify flushed
		updated, _ := store.GetSession(t.Context(), session.ID().String())
		assert.True(t, updated.LastActivityAt().After(originalActivity))
	})

	t.Run("Close is safe to call when no activity tracker", func(t *testing.T) {
		store := NewMemoryStore()
		gs := New(store)

		assert.NotPanics(t, func() {
			gs.Close()
		})
	})
}
