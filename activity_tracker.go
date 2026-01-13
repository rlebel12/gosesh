package gosesh

import (
	"context"
	"log/slog"
	"maps"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

// ActivityTrackingConfig stores configuration for activity tracking.
type ActivityTrackingConfig struct {
	// FlushInterval is how often pending activity timestamps are flushed to the store.
	FlushInterval time.Duration
}

// FlushError represents an error that occurred during activity flush.
type FlushError struct {
	Err       error
	BatchSize int
}

func (e *FlushError) Error() string {
	return e.Err.Error()
}

func (e *FlushError) Unwrap() error {
	return e.Err
}

// ActivityTracker periodically flushes session activity timestamps to the store in batches.
// This reduces database write load by batching multiple activity updates together.
type ActivityTracker struct {
	pending       map[string]time.Time
	mu            sync.Mutex // See RWMutex note below
	store         ActivityRecorder
	ticker        *time.Ticker
	logger        *slog.Logger
	flushInterval time.Duration
	eg            *errgroup.Group
	cancel        context.CancelFunc
	errors        chan error
}

// Note on sync.Mutex vs sync.RWMutex:
// RWMutex would not provide benefit here because the hot path (RecordActivity)
// always writes to the pending map. RWMutex is beneficial when you have many
// concurrent readers and few writers. In this case, every request writes via
// RecordActivity, and flush() also requires write access to clone and delete.
// Using Mutex avoids the overhead of RWMutex's more complex locking semantics.

// NewActivityTracker creates a new activity tracker that flushes at the specified interval.
// Call Start(ctx) to begin background flushing.
// Flush errors are sent to the Errors() channel for client handling.
func NewActivityTracker(store ActivityRecorder, flushInterval time.Duration, logger *slog.Logger) *ActivityTracker {
	return &ActivityTracker{
		pending:       make(map[string]time.Time),
		store:         store,
		flushInterval: flushInterval,
		logger:        logger,
		errors:        make(chan error, 16), // Buffered to avoid blocking flush
	}
}

// Errors returns a channel that receives flush errors.
// Clients should read from this channel to handle errors (e.g., logging, alerting).
// The channel is buffered (16) to avoid blocking the flush loop.
// If the buffer fills, errors are logged and dropped.
// Errors are of type *FlushError which can be type-asserted for additional context.
func (at *ActivityTracker) Errors() <-chan error {
	return at.errors
}

// Start begins the background flush loop using the provided context.
// The flush loop will run until the context is cancelled or Stop is called.
// Start must only be called once. Calling Start multiple times will panic.
func (at *ActivityTracker) Start(ctx context.Context) {
	if at.eg != nil {
		panic("ActivityTracker.Start called multiple times")
	}

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
			// Final flush uses context.Background() - parent ctx is already cancelled.
			// Deriving from a cancelled context would produce an immediately-cancelled
			// child, causing flush() to fail. Using Background() allows the 5-second
			// timeout in flush() to function properly during graceful shutdown.
			at.flush(context.Background())
			return
		}
	}
}

// flush writes all pending activities to the store.
// On success, flushed items are removed from pending. On failure, items remain
// in pending for retry on the next flush interval.
func (at *ActivityTracker) flush(ctx context.Context) {
	at.mu.Lock()
	if len(at.pending) == 0 {
		at.mu.Unlock()
		return
	}

	// Clone the pending map so we can release the lock quickly
	batch := maps.Clone(at.pending)
	at.mu.Unlock()

	flushCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	count, err := at.store.BatchRecordActivity(flushCtx, batch)
	if err != nil {
		// Send error to channel (non-blocking to avoid stalling flush loop)
		flushErr := &FlushError{Err: err, BatchSize: len(batch)}
		select {
		case at.errors <- flushErr:
		default:
			at.logger.Warn("flush error channel full, dropping error", "error", err, "batch_size", len(batch))
		}
		return
	}

	at.logger.Debug("flushed activity batch", "updated_count", count, "batch_size", len(batch))

	// Only remove successfully flushed items from pending
	at.mu.Lock()
	for sessionID, timestamp := range batch {
		// Only delete if the timestamp hasn't been updated since we cloned
		if at.pending[sessionID] == timestamp {
			delete(at.pending, sessionID)
		}
	}
	at.mu.Unlock()
}

// Stop stops the activity tracker and performs a final flush.
// After Stop returns, the tracker cannot be restarted.
func (at *ActivityTracker) Stop() {
	if at.cancel != nil {
		at.cancel()
	}
	if at.eg != nil {
		at.eg.Wait() // Wait for final flush to complete
	}
	close(at.errors)
}
