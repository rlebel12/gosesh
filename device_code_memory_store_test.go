package gosesh

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryDeviceCodeStore(t *testing.T) {
	contract := DeviceCodeStoreContract{
		NewStore: func() DeviceCodeStore {
			return NewMemoryDeviceCodeStore()
		},
	}
	contract.Test(t)
}

// TestMemoryDeviceCodeStore_CompleteAcceptsRawSessionID verifies CompleteDeviceCode accepts RawSessionID
func TestMemoryDeviceCodeStore_CompleteAcceptsRawSessionID(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryDeviceCodeStore()

	// Create a device code entry
	deviceCode, err := store.CreateDeviceCode(ctx, "ABC123", time.Now().Add(10*time.Minute))
	require.NoError(t, err)

	// Complete with RawSessionID
	rawID := RawSessionID("raw-session-id-12345")
	err = store.CompleteDeviceCode(ctx, deviceCode, rawID)
	require.NoError(t, err)

	// Retrieve and verify SessionID was stored
	entry, err := store.GetDeviceCode(ctx, deviceCode)
	require.NoError(t, err)
	assert.True(t, entry.Completed)
	assert.Equal(t, rawID, entry.SessionID)

	// Type assertion to ensure SessionID is RawSessionID
	var _ RawSessionID = entry.SessionID
}

// TestMemoryDeviceCodeStore_SessionIDType verifies entry.SessionID is RawSessionID type
func TestMemoryDeviceCodeStore_SessionIDType(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryDeviceCodeStore()

	deviceCode, err := store.CreateDeviceCode(ctx, "XYZ789", time.Now().Add(10*time.Minute))
	require.NoError(t, err)

	testRawID := RawSessionID("test-raw-id")
	err = store.CompleteDeviceCode(ctx, deviceCode, testRawID)
	require.NoError(t, err)

	entry, err := store.GetDeviceCode(ctx, deviceCode)
	require.NoError(t, err)

	// Verify type and value
	assert.Equal(t, testRawID, entry.SessionID)
	assert.IsType(t, RawSessionID(""), entry.SessionID)
}
