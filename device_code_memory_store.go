package gosesh

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// MemoryDeviceCodeStore is an in-memory implementation of DeviceCodeStore.
// It is thread-safe and suitable for testing and development.
// For production use, implement a persistent store (e.g., Redis, database).
type MemoryDeviceCodeStore struct {
	mu sync.RWMutex
	// byDeviceCode maps device codes to entries
	byDeviceCode map[string]*DeviceCodeEntry
	// byUserCode maps user codes to device codes for quick lookup
	byUserCode map[string]string
}

// NewMemoryDeviceCodeStore creates a new in-memory device code store.
func NewMemoryDeviceCodeStore() *MemoryDeviceCodeStore {
	return &MemoryDeviceCodeStore{
		byDeviceCode: make(map[string]*DeviceCodeEntry),
		byUserCode:   make(map[string]string),
	}
}

// CreateDeviceCode creates a new pending authorization.
func (m *MemoryDeviceCodeStore) CreateDeviceCode(ctx context.Context, userCode string, expiresAt time.Time) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Generate device code: 32 random bytes, hex encoded
	deviceCodeBytes := make([]byte, 32)
	if _, err := rand.Read(deviceCodeBytes); err != nil {
		return "", err
	}
	deviceCode := hex.EncodeToString(deviceCodeBytes)

	entry := &DeviceCodeEntry{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ExpiresAt:  expiresAt,
		Interval:   5 * time.Second,
		Completed:  false,
		LastPoll:   time.Time{}, // Zero time
	}

	m.byDeviceCode[deviceCode] = entry
	m.byUserCode[userCode] = deviceCode

	return deviceCode, nil
}

// GetDeviceCode retrieves a pending authorization by device code.
func (m *MemoryDeviceCodeStore) GetDeviceCode(ctx context.Context, deviceCode string) (DeviceCodeEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, ok := m.byDeviceCode[deviceCode]
	if !ok {
		return DeviceCodeEntry{}, ErrDeviceCodeNotFound
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		return DeviceCodeEntry{}, ErrDeviceCodeExpired
	}

	return *entry, nil
}

// GetByUserCode retrieves a pending authorization by user code.
func (m *MemoryDeviceCodeStore) GetByUserCode(ctx context.Context, userCode string) (DeviceCodeEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	deviceCode, ok := m.byUserCode[userCode]
	if !ok {
		return DeviceCodeEntry{}, ErrDeviceCodeNotFound
	}

	entry, ok := m.byDeviceCode[deviceCode]
	if !ok {
		return DeviceCodeEntry{}, ErrDeviceCodeNotFound
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		return DeviceCodeEntry{}, ErrDeviceCodeExpired
	}

	return *entry, nil
}

// CompleteDeviceCode marks an authorization as complete.
func (m *MemoryDeviceCodeStore) CompleteDeviceCode(ctx context.Context, deviceCode string, sessionID Identifier) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, ok := m.byDeviceCode[deviceCode]
	if !ok {
		return ErrDeviceCodeNotFound
	}

	// Check if already completed
	if entry.Completed {
		return ErrDeviceCodeAlreadyComplete
	}

	entry.Completed = true
	entry.SessionID = sessionID

	return nil
}

// UpdateLastPoll updates the last poll time for rate limiting.
func (m *MemoryDeviceCodeStore) UpdateLastPoll(ctx context.Context, deviceCode string, pollTime time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, ok := m.byDeviceCode[deviceCode]
	if !ok {
		return ErrDeviceCodeNotFound
	}

	entry.LastPoll = pollTime

	return nil
}

// DeleteDeviceCode removes an authorization.
func (m *MemoryDeviceCodeStore) DeleteDeviceCode(ctx context.Context, deviceCode string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, ok := m.byDeviceCode[deviceCode]
	if !ok {
		// Idempotent - deleting non-existent code is not an error
		return nil
	}

	// Remove from both maps
	delete(m.byDeviceCode, deviceCode)
	delete(m.byUserCode, entry.UserCode)

	return nil
}

// CleanupExpired removes expired entries.
func (m *MemoryDeviceCodeStore) CleanupExpired(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	var expiredDeviceCodes []string

	// Find expired entries
	for deviceCode, entry := range m.byDeviceCode {
		if now.After(entry.ExpiresAt) {
			expiredDeviceCodes = append(expiredDeviceCodes, deviceCode)
		}
	}

	// Remove expired entries
	for _, deviceCode := range expiredDeviceCodes {
		entry := m.byDeviceCode[deviceCode]
		delete(m.byDeviceCode, deviceCode)
		delete(m.byUserCode, entry.UserCode)
	}

	return nil
}

// Reset clears all device codes.
// This is useful for testing to isolate state between test cases.
func (m *MemoryDeviceCodeStore) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.byDeviceCode = make(map[string]*DeviceCodeEntry)
	m.byUserCode = make(map[string]string)
}

// Ensure MemoryDeviceCodeStore implements DeviceCodeStore
var _ DeviceCodeStore = (*MemoryDeviceCodeStore)(nil)
