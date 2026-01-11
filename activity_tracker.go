package gosesh

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

// ActivityTracker periodically flushes session activity timestamps to the store in batches.
// This reduces database write load by batching multiple activity updates together.
type ActivityTracker struct {
	pending       map[string]time.Time
	mu            sync.Mutex
	store         ActivityRecorder  // Uses ActivityRecorder interface, not base Storer
	ticker        *time.Ticker
	logger        *slog.Logger
	flushInterval time.Duration
	eg            *errgroup.Group
	cancel        context.CancelFunc
}

// NewActivityTracker creates a new activity tracker that flushes at the specified interval.
// The logger parameter is required to avoid race conditions during initialization.
// Call Start(ctx) to begin background flushing.
func NewActivityTracker(store ActivityRecorder, flushInterval time.Duration, logger *slog.Logger) *ActivityTracker {
	return &ActivityTracker{
		pending:       make(map[string]time.Time),
		store:         store,
		flushInterval: flushInterval,
		logger:        logger,
	}
}

// Start begins the background flush loop using the provided context.
// The flush loop will run until the context is cancelled or Close is called.
func (at *ActivityTracker) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	at.cancel = cancel
	at.ticker = time.NewTicker(at.flushInterval)

	eg, ctx := errgroup.WithContext(ctx)
	at.eg = eg

	eg.Go(func() error {
		at.flushLoop(ctx)
		return nil
	})
}

// RecordActivity records that a session was active at the given timestamp.
// The activity is queued in memory and will be flushed on the next interval.
// If the same session ID is recorded multiple times, only the latest timestamp is kept.
//
// Performance: This method is non-blocking and extremely fast (<1μs).
// The mutex is held only for a map write operation (~50-100ns).
// At typical loads (1K-10K req/sec), contention probability is <1%.
// See PR #11 feedback for detailed blocking analysis.
func (at *ActivityTracker) RecordActivity(sessionID string, timestamp time.Time) {
	at.mu.Lock()
	at.pending[sessionID] = timestamp
	at.mu.Unlock()
}

// flushLoop runs in a goroutine and periodically flushes pending activities.
func (at *ActivityTracker) flushLoop(ctx context.Context) {
	defer at.ticker.Stop()
	for {
		select {
		case <-at.ticker.C:
			at.flush(ctx)
		case <-ctx.Done():
			at.flush(ctx) // Final flush before shutdown
			return
		}
	}
}

// flush writes all pending activities to the store and clears the pending map.
func (at *ActivityTracker) flush(ctx context.Context) {
	at.mu.Lock()
	if len(at.pending) == 0 {
		at.mu.Unlock()
		return
	}

	batch := at.pending
	at.pending = make(map[string]time.Time)
	at.mu.Unlock()

	flushCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	count, err := at.store.BatchRecordActivity(flushCtx, batch)
	if err != nil {
		at.logger.Error("failed to flush activity batch", "error", err, "batch_size", len(batch))
	} else {
		at.logger.Debug("flushed activity batch", "updated_count", count, "batch_size", len(batch))
	}
}

// Close stops the activity tracker and performs a final flush.
func (at *ActivityTracker) Close() {
	if at.cancel != nil {
		at.cancel()
	}
	if at.eg != nil {
		at.eg.Wait() // Wait for final flush to complete
	}
}
