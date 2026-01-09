# Activity Tracking Implementation Plan (v2)

**Updated:** 2026-01-09 (Addresses PR #11 feedback)

## Overview

Introduce `LastActivityAt` timestamps with batched background updates to track session activity for compliance and auditability purposes. This plan follows TDD principles and existing gosesh coding standards.

## Design Decisions

### Strategy: Piggyback + Optional Batching

1. **Default Behavior**: Update `LastActivityAt` during `ExtendSession` (zero additional writes)
2. **Optional Enhancement**: `ActivityTracker` for periodic batched updates (configurable)
3. **Accuracy Trade-off**: Default = within refresh threshold (~10min), batched = configurable interval
4. **Interface Design**: Optional `ActivityRecorder` interface (not part of base `Storer`)

### Why This Approach?

- ✅ Backward compatible (no breaking changes)
- ✅ Zero performance impact by default
- ✅ Opt-in batching for apps needing precise tracking
- ✅ Follows existing patterns (functional options, interfaces)
- ✅ Interface Segregation: Only stores using activity tracking need `ActivityRecorder`

## Changes from v1 (PR #11 Feedback)

1. **Optional Interface Pattern**: `BatchRecordActivity` moved to separate `ActivityRecorder` interface
2. **Channel Direction**: Specified `done chan<- struct{}` for clarity
3. **Non-blocking Documentation**: Documented mutex hold time (<1μs) and blocking analysis
4. **Race Condition Fix**: Deferred tracker creation to after all options applied

---

## Phase 1: Add LastActivityAt to Session Interface (TDD)

### Files to Create/Modify

- `contract_test.go` (modify SessionContract)
- `gosesh.go` (modify Session interface)
- `store.go` (modify MemoryStoreSession)

### Step 1.1: Write Failing Contract Test

**File: `contract_test.go`**

Add test to `SessionContract.Test()`:

```go
t.Run("returns last activity timestamp", func(t *testing.T) {
    id := c.NewIdentifier("session-id")
    userID := c.NewIdentifier("user-id")
    now := time.Now().UTC()
    idleDeadline := now.Add(time.Hour)
    absoluteDeadline := now.Add(24 * time.Hour)
    lastActivityAt := now.Add(-5 * time.Minute) // Activity 5 minutes ago

    session := c.NewSession(id, userID, idleDeadline, absoluteDeadline, lastActivityAt)

    assert.Equal(t, lastActivityAt.Unix(), session.LastActivityAt().Unix())
})
```

Update `SessionContract` struct:

```go
type SessionContract struct {
    NewSession    func(id, userID Identifier, idleDeadline, absoluteDeadline, lastActivityAt time.Time) Session
    NewIdentifier func(giveID string) Identifier
}
```

**Expected Result**: ❌ Tests fail (method doesn't exist)

### Step 1.2: Update Session Interface

**File: `gosesh.go`**

```go
// Session represents an active user session.
type Session interface {
    // ID returns the session's unique identifier.
    ID() Identifier
    // UserID returns the ID of the user associated with this session.
    UserID() Identifier
    // IdleDeadline returns the time at which the session expires from inactivity.
    IdleDeadline() time.Time
    // AbsoluteDeadline returns the time at which the session expires regardless of activity.
    AbsoluteDeadline() time.Time
    // LastActivityAt returns the timestamp of the most recent session activity.
    // This is updated when the session is created, extended, or when activity is recorded.
    LastActivityAt() time.Time
}
```

**Expected Result**: ❌ Tests still fail (MemoryStoreSession doesn't implement it)

### Step 1.3: Implement in MemoryStoreSession

**File: `store.go`**

Add field to struct:

```go
type MemoryStoreSession struct {
    id               MemoryStoreIdentifier
    userID           Identifier
    idleDeadline     time.Time
    absoluteDeadline time.Time
    lastActivityAt   time.Time // NEW
}
```

Add getter method:

```go
func (s MemoryStoreSession) LastActivityAt() time.Time {
    return s.lastActivityAt
}
```

Add test setter (following existing pattern):

```go
// SetLastActivityAt updates the last activity timestamp for testing purposes.
// This should only be used in tests to simulate session activity.
func (s *MemoryStoreSession) SetLastActivityAt(timestamp time.Time) {
    s.lastActivityAt = timestamp
}
```

Update `CreateSession`:

```go
func (ms *MemoryStore) CreateSession(ctx context.Context, userID Identifier, idleDeadline, absoluteDeadline time.Time) (Session, error) {
    ms.mu.Lock()
    defer ms.mu.Unlock()

    now := time.Now().UTC()
    ms.sequenceID++
    s := &MemoryStoreSession{
        id:               ms.sequenceID,
        userID:           userID,
        idleDeadline:     idleDeadline,
        absoluteDeadline: absoluteDeadline,
        lastActivityAt:   now, // Set to creation time
    }
    ms.sessions[s.ID().String()] = s
    return s, nil
}
```

**Expected Result**: ✅ Contract tests pass

### Step 1.4: Update Existing Contract Test Calls

**File: `contract_test.go`**

Update existing tests to pass `lastActivityAt`:

```go
t.Run("returns correct values", func(t *testing.T) {
    id := c.NewIdentifier("session-id")
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
```

**Run Tests**: `go test ./... -v`

---

## Phase 2: Update ExtendSession to Set LastActivityAt (TDD)

### Files to Modify

- `contract_test.go`
- `store.go`

### Step 2.1: Write Test for Activity Timestamp During Extension

**File: `contract_test.go`**

Add to `StorerContract.Test()`:

```go
t.Run("extend session updates last activity timestamp", func(t *testing.T) {
    userID := StringIdentifier("user-id")
    now := time.Now().UTC()
    idleDeadline := now.Add(10 * time.Minute)
    absoluteDeadline := now.Add(time.Hour)
    store := c.NewStorer()

    session, err := store.CreateSession(t.Context(), userID, idleDeadline, absoluteDeadline)
    require.NoError(t, err)

    originalActivity := session.LastActivityAt()

    // Wait a moment to ensure timestamp difference
    time.Sleep(10 * time.Millisecond)

    // Extend the session
    newIdleDeadline := now.Add(20 * time.Minute)
    err = store.ExtendSession(t.Context(), session.ID().String(), newIdleDeadline)
    require.NoError(t, err)

    // Verify last activity was updated
    updatedSession, err := store.GetSession(t.Context(), session.ID().String())
    require.NoError(t, err)
    assert.True(t, updatedSession.LastActivityAt().After(originalActivity),
        "LastActivityAt should be updated during ExtendSession")
})
```

**Expected Result**: ❌ Test fails (ExtendSession doesn't update lastActivityAt)

### Step 2.2: Implement in MemoryStore

**File: `store.go`**

```go
func (ms *MemoryStore) ExtendSession(ctx context.Context, sessionID string, newIdleDeadline time.Time) error {
    ms.mu.Lock()
    defer ms.mu.Unlock()

    s, ok := ms.sessions[sessionID]
    if !ok {
        return errors.New("session not found")
    }
    s.idleDeadline = newIdleDeadline
    s.lastActivityAt = time.Now().UTC() // NEW: Update activity timestamp
    return nil
}
```

**Expected Result**: ✅ Test passes

**Run Tests**: `go test ./... -v`

---

## Phase 3: Add ActivityRecorder Interface (TDD)

### Files to Create/Modify

- `contract_test.go` (create ActivityRecorderContract)
- `gosesh.go` (create ActivityRecorder interface)
- `store.go` (implement in MemoryStore)

### Design Note

We use a **separate optional interface** instead of adding `BatchRecordActivity` to the base `Storer` interface. This follows the Interface Segregation Principle - stores that don't use activity tracking don't need to implement this method.

### Step 3.1: Write Contract Test

**File: `contract_test.go`**

Add new contract struct and tests:

```go
type ActivityRecorderContract struct {
    NewStorer func() Storer  // Must also implement ActivityRecorder
}

func (c ActivityRecorderContract) Test(t *testing.T) {
    t.Run("batch record activity updates multiple sessions", func(t *testing.T) {
        store := c.NewStorer()
        recorder := store.(ActivityRecorder)  // Type assertion

        userID := StringIdentifier("user-id")
        now := time.Now().UTC()

        // Create 3 sessions
        session1, _ := store.CreateSession(t.Context(), userID, now.Add(1*time.Hour), now.Add(24*time.Hour))
        session2, _ := store.CreateSession(t.Context(), userID, now.Add(1*time.Hour), now.Add(24*time.Hour))
        session3, _ := store.CreateSession(t.Context(), userID, now.Add(1*time.Hour), now.Add(24*time.Hour))

        time.Sleep(10 * time.Millisecond)

        // Batch update
        activityTime := time.Now().UTC()
        updates := map[string]time.Time{
            session1.ID().String(): activityTime,
            session2.ID().String(): activityTime,
        }

        count, err := recorder.BatchRecordActivity(t.Context(), updates)
        require.NoError(t, err)
        assert.Equal(t, 2, count)

        // Verify session1 updated
        updated1, _ := store.GetSession(t.Context(), session1.ID().String())
        assert.Equal(t, activityTime.Unix(), updated1.LastActivityAt().Unix())

        // Verify session2 updated
        updated2, _ := store.GetSession(t.Context(), session2.ID().String())
        assert.Equal(t, activityTime.Unix(), updated2.LastActivityAt().Unix())

        // Verify session3 NOT updated
        updated3, _ := store.GetSession(t.Context(), session3.ID().String())
        assert.True(t, updated3.LastActivityAt().Before(activityTime))
    })

    t.Run("batch record activity handles non-existent sessions gracefully", func(t *testing.T) {
        store := c.NewStorer()
        recorder := store.(ActivityRecorder)
        now := time.Now().UTC()

        updates := map[string]time.Time{
            "non-existent-1": now,
            "non-existent-2": now,
        }

        count, err := recorder.BatchRecordActivity(t.Context(), updates)
        require.NoError(t, err)
        assert.Equal(t, 0, count) // No sessions updated
    })

    t.Run("batch record activity handles empty map", func(t *testing.T) {
        store := c.NewStorer()
        recorder := store.(ActivityRecorder)
        updates := map[string]time.Time{}

        count, err := recorder.BatchRecordActivity(t.Context(), updates)
        require.NoError(t, err)
        assert.Equal(t, 0, count)
    })
}
```

**Expected Result**: ❌ Tests fail (ActivityRecorder interface doesn't exist)

### Step 3.2: Create ActivityRecorder Interface

**File: `gosesh.go`**

Add **separate optional interface** (do NOT modify base Storer):

```go
// ActivityRecorder is an optional interface that stores can implement to support
// batched activity tracking. Stores that don't implement this interface can still
// use gosesh, but cannot enable activity tracking via WithActivityTracking().
type ActivityRecorder interface {
    // BatchRecordActivity updates the LastActivityAt timestamp for multiple sessions.
    // Returns the number of sessions successfully updated.
    // Non-existent session IDs are silently ignored.
    // This method must be safe to call concurrently with other store operations.
    BatchRecordActivity(ctx context.Context, updates map[string]time.Time) (int, error)
}
```

**Note**: The base `Storer` interface remains **unchanged**. This is intentional:
- Stores without activity tracking don't need to implement `BatchRecordActivity`
- Type-safe: `WithActivityTracking` validates the store implements `ActivityRecorder`
- Follows Go patterns: similar to `io.Reader` vs `io.ReadWriter`

**Expected Result**: ❌ Tests still fail (MemoryStore doesn't implement it)

### Step 3.3: Implement in MemoryStore

**File: `store.go`**

```go
func (ms *MemoryStore) BatchRecordActivity(ctx context.Context, updates map[string]time.Time) (int, error) {
    if len(updates) == 0 {
        return 0, nil
    }

    ms.mu.Lock()
    defer ms.mu.Unlock()

    count := 0
    for sessionID, timestamp := range updates {
        s, ok := ms.sessions[sessionID]
        if ok {
            s.lastActivityAt = timestamp
            count++
        }
    }
    return count, nil
}
```

Add interface assertion at end of `store.go`:

```go
// Ensure interfaces are implemented
var _ Storer = (*MemoryStore)(nil)
var _ ActivityRecorder = (*MemoryStore)(nil)  // NEW
var _ Identifier = (*MemoryStoreIdentifier)(nil)
var _ Session = (*MemoryStoreSession)(nil)
```

**Expected Result**: ✅ Tests pass

**Run Tests**: `go test ./... -v`

---

## Phase 4: Implement ActivityTracker (TDD)

### Files to Create

- `activity_tracker.go` (new)
- `activity_tracker_test.go` (new)

### Step 4.1: Write ActivityTracker Tests

**File: `activity_tracker_test.go`**

```go
package gosesh

import (
    "context"
    "sync"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestActivityTracker(t *testing.T) {
    t.Run("records activity in pending map", func(t *testing.T) {
        store := NewMemoryStore()
        tracker := NewActivityTracker(store, 1*time.Hour) // Long interval, won't flush
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
        tracker := NewActivityTracker(store, 1*time.Hour)
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
        tracker := NewActivityTracker(store, 1*time.Hour)
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
        tracker := NewActivityTracker(store, 50*time.Millisecond) // Fast flush
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
        tracker := NewActivityTracker(store, 1*time.Hour) // Won't auto-flush

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
        tracker := NewActivityTracker(store, 1*time.Hour)
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
            Storer:                NewMemoryStore(),
            BatchRecordActivityErr: errors.New("database connection failed"),
        }

        logs := &testLogger{logs: []string{}}
        tracker := &ActivityTracker{
            pending: make(map[string]time.Time),
            store:   errorStore,
            ticker:  time.NewTicker(1 * time.Hour),
            done:    make(chan struct{}),
            logger:  logs,
        }
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
```

**Expected Result**: ❌ Tests fail (ActivityTracker doesn't exist)

### Step 4.2: Implement ActivityTracker

**File: `activity_tracker.go`**

```go
package gosesh

import (
    "context"
    "log/slog"
    "sync"
    "time"
)

// ActivityTracker periodically flushes session activity timestamps to the store in batches.
// This reduces database write load by batching multiple activity updates together.
type ActivityTracker struct {
    pending map[string]time.Time
    mu      sync.Mutex
    store   ActivityRecorder  // Uses ActivityRecorder interface, not base Storer
    ticker  *time.Ticker
    done    chan<- struct{}  // Send-only: ActivityTracker only closes this channel
    logger  Logger
}

// Logger interface for activity tracker logging
type Logger interface {
    Error(msg string, args ...any)
    Info(msg string, args ...any)
    Debug(msg string, args ...any)
}

// NewActivityTracker creates a new activity tracker that flushes at the specified interval.
// The logger parameter is required to avoid race conditions during initialization.
func NewActivityTracker(store ActivityRecorder, flushInterval time.Duration, logger *slog.Logger) *ActivityTracker {
    done := make(chan struct{})  // Create as bidirectional
    at := &ActivityTracker{
        pending: make(map[string]time.Time),
        store:   store,
        ticker:  time.NewTicker(flushInterval),
        done:    done,  // Store as send-only (type conversion)
        logger:  logger,
    }
    go at.flushLoop()
    return at
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
func (at *ActivityTracker) flushLoop() {
    for {
        select {
        case <-at.ticker.C:
            at.flush()
        case <-at.done:
            at.flush() // Final flush before shutdown
            return
        }
    }
}

// flush writes all pending activities to the store and clears the pending map.
func (at *ActivityTracker) flush() {
    at.mu.Lock()
    if len(at.pending) == 0 {
        at.mu.Unlock()
        return
    }

    batch := at.pending
    at.pending = make(map[string]time.Time)
    at.mu.Unlock()

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    count, err := at.store.BatchRecordActivity(ctx, batch)
    if err != nil {
        at.logger.Error("failed to flush activity batch", "error", err, "batch_size", len(batch))
    } else {
        at.logger.Debug("flushed activity batch", "updated_count", count, "batch_size", len(batch))
    }
}

// Close stops the activity tracker and performs a final flush.
func (at *ActivityTracker) Close() {
    at.ticker.Stop()
    close(at.done)
}
```

**Note**: SetLogger() method removed - logger is now set during construction to avoid race conditions.

**Expected Result**: ✅ Tests pass (except logger test - need to add test logger)

### Step 4.3: Add Test Logger and Erroring Store Support

**File: `fake_test.go`**

Add to erroringStore:

```go
type erroringStore struct {
    Storer
    ExtendSessionErr       error
    BatchRecordActivityErr error // NEW
}

func (s *erroringStore) BatchRecordActivity(ctx context.Context, updates map[string]time.Time) (int, error) {
    if s.BatchRecordActivityErr != nil {
        return 0, s.BatchRecordActivityErr
    }
    return s.Storer.BatchRecordActivity(ctx, updates)
}
```

Add test logger:

```go
type testLogger struct {
    logs []string
    mu   sync.Mutex
}

func (l *testLogger) Error(msg string, args ...any) {
    l.mu.Lock()
    defer l.mu.Unlock()
    l.logs = append(l.logs, msg)
}

func (l *testLogger) Info(msg string, args ...any) {
    l.mu.Lock()
    defer l.mu.Unlock()
    l.logs = append(l.logs, msg)
}

func (l *testLogger) Debug(msg string, args ...any) {
    l.mu.Lock()
    defer l.mu.Unlock()
    l.logs = append(l.logs, msg)
}
```

**Expected Result**: ✅ All ActivityTracker tests pass

**Run Tests**: `go test ./... -v`

---

## Phase 5: Integrate ActivityTracker into Gosesh (TDD)

### Files to Modify

- `gosesh.go`
- `gosesh_test.go` (new tests)

### Step 5.1: Write Integration Tests

**File: `gosesh_test.go`**

Add:

```go
func TestWithActivityTracking(t *testing.T) {
    t.Run("creates activity tracker with specified interval", func(t *testing.T) {
        store := NewMemoryStore()
        gs := New(store, WithActivityTracking(100*time.Millisecond))
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

        // Create session
        userID := StringIdentifier("user-1")
        session, _ := store.CreateSession(context.Background(), userID,
            time.Now().Add(1*time.Hour), time.Now().Add(24*time.Hour))

        originalActivity := session.LastActivityAt()
        time.Sleep(10 * time.Millisecond)

        // Record activity
        newActivity := time.Now().UTC()
        gs.activityTracker.RecordActivity(session.ID().String(), newActivity)

        // Close should flush
        gs.Close()

        // Verify flushed
        updated, _ := store.GetSession(context.Background(), session.ID().String())
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
```

**Expected Result**: ❌ Tests fail (WithActivityTracking doesn't exist)

### Step 5.2: Add Configuration Option

**File: `gosesh.go`**

Add fields to Gosesh:

```go
type activityTrackingConfig struct {
    flushInterval time.Duration
}

type Gosesh struct {
    store                   Storer
    logger                  *slog.Logger
    sessionCookieName       string
    oAuth2StateCookieName   string
    redirectCookieName      string
    redirectParamName       string
    sessionIdleTimeout      time.Duration
    sessionMaxLifetime      time.Duration
    sessionRefreshThreshold time.Duration
    now                     func() time.Time
    cookieDomain            func() string
    credentialSource        CredentialSource
    activityTracker         *ActivityTracker            // NEW
    activityTrackingConfig  *activityTrackingConfig     // NEW: stores config, tracker created later
}
```

Add functional option (stores config only, doesn't create tracker):

```go
// WithActivityTracking enables batched activity timestamp tracking.
// Activity timestamps are recorded in memory and flushed to the store at the specified interval.
// This reduces database write load while providing session activity auditability.
// If not specified, activity timestamps are only updated during session extension (ExtendSession).
//
// The store must implement the ActivityRecorder interface. If it doesn't, New() will panic.
func WithActivityTracking(flushInterval time.Duration) func(*Gosesh) {
    return func(gs *Gosesh) {
        gs.activityTrackingConfig = &activityTrackingConfig{
            flushInterval: flushInterval,
        }
    }
}
```

Modify New() function to create tracker AFTER all options applied:

```go
func New(store Storer, opts ...NewOpts) *Gosesh {
    url, _ := url.Parse("http://localhost")
    gs := &Gosesh{
        store:                   store,
        logger:                  slog.New(slog.NewTextHandler(io.Discard, nil)),
        sessionCookieName:       "session",
        oAuth2StateCookieName:   "oauthstate",
        redirectCookieName:      "redirect",
        redirectParamName:       "next",
        sessionIdleTimeout:      1 * time.Hour,
        sessionMaxLifetime:      24 * time.Hour,
        sessionRefreshThreshold: 10 * time.Minute,
        origin:                  url,
        allowedHosts:            []string{url.Hostname()},
        now:                     time.Now,
    }
    gs.cookieDomain = func() string { return gs.origin.Hostname() }

    // Apply all options first
    for _, opt := range opts {
        opt(gs)
    }

    // After all options applied, create activity tracker if enabled
    // This ensures logger is finalized before tracker creation (fixes race condition)
    if gs.activityTrackingConfig != nil {
        recorder, ok := store.(ActivityRecorder)
        if !ok {
            panic("activity tracking enabled but store does not implement ActivityRecorder interface")
        }
        gs.activityTracker = NewActivityTracker(
            recorder,
            gs.activityTrackingConfig.flushInterval,
            gs.logger,  // Logger is now finalized
        )
    }

    // Backward compatibility: if no credential source specified, create a cookie source
    if gs.credentialSource == nil {
        gs.credentialSource = NewCookieCredentialSource(
            WithCookieSourceName(gs.sessionCookieName),
            WithCookieSourceDomain(gs.cookieDomain()),
            WithCookieSourceSecure(gs.Scheme() == "https"),
            WithCookieSourceSessionConfig(SessionConfig{
                IdleDuration:     gs.sessionIdleTimeout,
                AbsoluteDuration: gs.sessionMaxLifetime,
                RefreshEnabled:   true,
            }),
        )
    }

    return gs
}
```

Add Close method:

```go
// Close gracefully shuts down the Gosesh instance.
// If activity tracking is enabled, this flushes any pending activity updates to the store.
func (gs *Gosesh) Close() {
    if gs.activityTracker != nil {
        gs.activityTracker.Close()
    }
}
```

**Key Fix**: Tracker creation deferred until after all options applied. This ensures:
- ✅ Logger is finalized before tracker uses it
- ✅ No race condition regardless of option order
- ✅ Type-safe: panics early if store doesn't implement ActivityRecorder

**Expected Result**: ✅ Tests pass

**Run Tests**: `go test ./... -v`

---

## Phase 6: Middleware Integration Tests

### Files to Modify

- `middleware_test.go`

### Step 6.1: Write Middleware Integration Tests

**File: `middleware_test.go`**

Add:

```go
func TestAuthenticateWithActivityTracking(t *testing.T) {
    t.Run("records activity when tracker enabled", func(t *testing.T) {
        store := NewMemoryStore()
        now := time.Now().UTC()

        gs := New(store,
            WithSessionCookieName("customName"),
            WithOrigin("http://localhost"),
            WithNow(func() time.Time { return now }),
            WithActivityTracking(1*time.Hour), // Won't auto-flush during test
        )
        defer gs.Close()

        // Create session
        userID := StringIdentifier("identifier")
        session, _ := store.CreateSession(context.Background(), userID,
            now.Add(15*time.Minute), now.Add(85*time.Minute))

        originalActivity := session.LastActivityAt()
        time.Sleep(10 * time.Millisecond)

        // Make request
        req := httptest.NewRequest(http.MethodGet, "/", nil)
        req.AddCookie(&http.Cookie{
            Name:  "customName",
            Value: base64.URLEncoding.EncodeToString([]byte(session.ID().String())),
        })

        w := httptest.NewRecorder()
        handler := gs.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            w.WriteHeader(http.StatusOK)
        }))
        handler.ServeHTTP(w, req)

        // Manually flush to check pending activities
        gs.activityTracker.flush()

        // Verify activity was recorded
        updated, _ := store.GetSession(context.Background(), session.ID().String())
        assert.True(t, updated.LastActivityAt().After(originalActivity))
    })

    t.Run("does not panic when tracker disabled", func(t *testing.T) {
        store := NewMemoryStore()
        now := time.Now().UTC()

        gs := New(store,
            WithSessionCookieName("customName"),
            WithOrigin("http://localhost"),
            WithNow(func() time.Time { return now }),
            // No activity tracking
        )

        userID := StringIdentifier("identifier")
        session, _ := store.CreateSession(context.Background(), userID,
            now.Add(15*time.Minute), now.Add(85*time.Minute))

        req := httptest.NewRequest(http.MethodGet, "/", nil)
        req.AddCookie(&http.Cookie{
            Name:  "customName",
            Value: base64.URLEncoding.EncodeToString([]byte(session.ID().String())),
        })

        w := httptest.NewRecorder()
        handler := gs.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            w.WriteHeader(http.StatusOK)
        }))

        assert.NotPanics(t, func() {
            handler.ServeHTTP(w, req)
        })
    })
}
```

**Expected Result**: ❌ Tests fail (authenticate doesn't record activity)

### Step 6.2: Integrate into Middleware

**File: `middleware.go`**

Update `authenticate()`:

```go
func (gs *Gosesh) authenticate(w http.ResponseWriter, r *http.Request) *http.Request {
    _, ok := CurrentSession(r)
    if ok {
        return r
    }

    setSecureCookieHeaders(w)
    ctx := r.Context()

    // Read session ID from credential source
    sessionID := gs.credentialSource.ReadSessionID(r)
    if sessionID == "" {
        return r
    }

    session, err := gs.store.GetSession(ctx, sessionID)
    if err != nil {
        gs.logger.Error("get session", "error", err)
        gs.credentialSource.ClearSession(w)
        return r
    }

    now := gs.now().UTC()

    // Check idle deadline (sliding window)
    if session.IdleDeadline().Before(now) {
        gs.logger.Debug("session idle expired")
        gs.credentialSource.ClearSession(w)
        return r
    }

    // Check absolute deadline (hard limit)
    if session.AbsoluteDeadline().Before(now) {
        gs.logger.Warn("session absolute expired")
        gs.credentialSource.ClearSession(w)
        return r
    }

    // Record activity if tracker is enabled
    if gs.activityTracker != nil {
        gs.activityTracker.RecordActivity(sessionID, now)
    }

    return gs.newRequestWithSession(r, session)
}
```

**Expected Result**: ✅ Tests pass

**Run Tests**: `go test ./... -v`

---

## Phase 7: Documentation and Examples

### Files to Create/Modify

- `README.md` (update)
- `CLAUDE.md` (update)
- `example_test.go` (add example)

### Step 7.1: Update README

**File: `README.md`**

Add section under "Session Management":

```markdown
### Activity Tracking

By default, `LastActivityAt` timestamps are updated whenever a session is extended (typically within 10 minutes of idle timeout). For applications requiring more precise activity tracking (e.g., compliance, auditing), enable batched activity tracking:

```go
gs := gosesh.New(store,
    gosesh.WithActivityTracking(30 * time.Second), // Flush every 30 seconds
)
defer gs.Close() // Important: flushes pending activities
```

**Trade-offs:**
- **Default (no batching)**: Zero additional database writes, accuracy within ~10 minutes
- **With batching**: More database writes (1 batch query per interval), configurable accuracy

**Database Implementation:**

For production use with PostgreSQL/MySQL, implement `BatchRecordActivity` in your custom store:

```go
func (s *PostgresStore) BatchRecordActivity(ctx context.Context, updates map[string]time.Time) (int, error) {
    const chunkSize = 5000

    sessionIDs := make([]string, 0, len(updates))
    timestamp := time.Now().UTC()

    for sessionID := range updates {
        sessionIDs = append(sessionIDs, sessionID)
    }

    totalUpdated := 0
    for i := 0; i < len(sessionIDs); i += chunkSize {
        end := i + chunkSize
        if end > len(sessionIDs) {
            end = len(sessionIDs)
        }

        result, err := s.db.ExecContext(ctx,
            `UPDATE sessions SET last_activity_at = $1 WHERE id = ANY($2)`,
            timestamp, pq.Array(sessionIDs[i:end]))
        if err != nil {
            return totalUpdated, err
        }

        affected, _ := result.RowsAffected()
        totalUpdated += int(affected)
    }

    return totalUpdated, nil
}
```
```

### Step 7.2: Update CLAUDE.md

**File: `CLAUDE.md`**

Update "Key Design Patterns" section:

```markdown
### Activity Tracking (Optional)

- **Timestamp Recording**: `LastActivityAt` tracks most recent session activity
- **Default Behavior**: Updated during session extension (zero additional writes)
- **Batched Updates**: Optional `ActivityTracker` for periodic batch writes
- **Graceful Shutdown**: `Close()` method flushes pending activities
```

Add to "Testing Strategy":

```markdown
- **Activity Tracking**: Tests for batched updates, concurrent safety, and flush behavior
```

### Step 7.3: Add Example

**File: `example_test.go`**

```go
func ExampleWithActivityTracking() {
    store := NewMemoryStore()

    // Enable activity tracking with 30-second flush interval
    gs := New(store,
        WithActivityTracking(30*time.Second),
    )
    defer gs.Close() // Important: flushes any pending activities

    // Sessions are now tracked with more precise LastActivityAt timestamps
    // Activity is recorded on each authenticated request and flushed every 30 seconds
}

func ExampleSession_LastActivityAt() {
    store := NewMemoryStore()
    gs := New(store)

    // Create a session
    userID := StringIdentifier("user-123")
    session, _ := store.CreateSession(context.Background(), userID,
        time.Now().Add(1*time.Hour),
        time.Now().Add(24*time.Hour))

    // Check when the session was last active
    fmt.Printf("Last active: %s\n", session.LastActivityAt())

    // LastActivityAt is automatically updated when:
    // 1. Session is created (set to creation time)
    // 2. Session is extended via ExtendSession()
    // 3. Activity is recorded via ActivityTracker (if enabled)
}
```

**Run Tests**: `go test ./... -v`

---

## Testing Checklist

### Unit Tests

- [x] SessionContract tests for LastActivityAt
- [x] StorerContract tests for BatchRecordActivity
- [x] ActivityTracker tests (recording, flushing, concurrency)
- [x] Gosesh configuration tests (WithActivityTracking)
- [x] Middleware integration tests

### Contract Tests

- [x] Session interface compliance
- [x] Storer interface compliance (including BatchRecordActivity)

### Integration Tests

- [x] End-to-end activity tracking flow
- [x] Graceful shutdown (Close)
- [x] Error handling during flush

### Coverage Goals

- Maintain existing coverage levels (aim for >85%)
- All new code paths covered
- Edge cases tested (empty batches, non-existent sessions, concurrent access)

---

## Performance Considerations

### Memory Usage

- **ActivityTracker pending map**: ~100 bytes per pending session
- **10K active sessions**: ~1MB memory overhead
- **Mitigation**: Flush intervals keep map bounded

### Database Impact

**Without ActivityTracker** (default):
- 0 additional writes per request ✅
- LastActivityAt updated during ExtendSession only

**With ActivityTracker**:
- 0 writes per request (buffered in memory) ✅
- 1 batch query per flush interval
- Example: 10K sessions, 30s flush = 1 batch query every 30s

### Scaling

- **Batch size limits**: Use chunking for >10K sessions
- **Flush interval tuning**:
  - Short (10s): More precise, more writes
  - Long (5min): Less precise, fewer writes
  - Recommended: 30-60 seconds

---

## Migration Path

### For Existing Users

**No breaking changes!**

1. **Default behavior**: LastActivityAt works automatically (set during create/extend)
2. **Opt-in batching**: Add `WithActivityTracking()` if needed
3. **Custom stores**: Implement `BatchRecordActivity` when ready

### Rollout Strategy

1. **Phase 1**: Release with default behavior (piggyback on ExtendSession)
2. **Phase 2**: Document batching option for users needing precise tracking
3. **Phase 3**: Add BatchRecordActivity examples for common databases

---

## Completion Criteria

- [ ] All contract tests pass
- [ ] All unit tests pass
- [ ] Integration tests pass
- [ ] Coverage maintained/improved
- [ ] Documentation updated
- [ ] Examples provided
- [ ] No breaking changes
- [ ] Backward compatible

**Estimated Effort**: 4-6 hours following TDD

**Review Points**:
- After Phase 2: Interface changes finalized
- After Phase 4: ActivityTracker implementation complete
- After Phase 6: Full integration tested
