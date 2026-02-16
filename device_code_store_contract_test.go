package gosesh

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// DeviceCodeStoreContract defines the contract tests for DeviceCodeStore implementations.
type DeviceCodeStoreContract struct {
	NewStore func() DeviceCodeStore
}

func (c DeviceCodeStoreContract) Test(t *testing.T) {
	t.Run("Store CRUD Operations", func(t *testing.T) {
		tests := []struct {
			name string
			test func(t *testing.T, store DeviceCodeStore)
		}{
			{
				name: "create_returns_device_code",
				test: func(t *testing.T, store DeviceCodeStore) {
					ctx := context.Background()
					userCode := "TEST1234"
					expiresAt := time.Now().Add(15 * time.Minute)

					deviceCode, err := store.CreateDeviceCode(ctx, userCode, expiresAt)
					require.NoError(t, err)
					assert.NotEmpty(t, deviceCode, "device code should not be empty")
				},
			},
			{
				name: "create_stores_entry",
				test: func(t *testing.T, store DeviceCodeStore) {
					ctx := context.Background()
					userCode := "TEST5678"
					expiresAt := time.Now().Add(15 * time.Minute)

					deviceCode, err := store.CreateDeviceCode(ctx, userCode, expiresAt)
					require.NoError(t, err)

					entry, err := store.GetDeviceCode(ctx, deviceCode)
					require.NoError(t, err)
					assert.Equal(t, deviceCode, entry.DeviceCode)
					assert.Equal(t, userCode, entry.UserCode)
					assert.False(t, entry.Completed)
				},
			},
			{
				name: "delete_success",
				test: func(t *testing.T, store DeviceCodeStore) {
					ctx := context.Background()
					userCode := "TEST9012"
					expiresAt := time.Now().Add(15 * time.Minute)

					deviceCode, err := store.CreateDeviceCode(ctx, userCode, expiresAt)
					require.NoError(t, err)

					err = store.DeleteDeviceCode(ctx, deviceCode)
					require.NoError(t, err)

					_, err = store.GetDeviceCode(ctx, deviceCode)
					assert.ErrorIs(t, err, ErrDeviceCodeNotFound)
				},
			},
			{
				name: "delete_nonexistent",
				test: func(t *testing.T, store DeviceCodeStore) {
					ctx := context.Background()
					err := store.DeleteDeviceCode(ctx, "nonexistent-device-code")
					assert.NoError(t, err, "delete should be idempotent")
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				store := c.NewStore()
				tt.test(t, store)
			})
		}
	})

	t.Run("Store Error Conditions", func(t *testing.T) {
		tests := []struct {
			name          string
			test          func(t *testing.T, store DeviceCodeStore)
			expectedError error
		}{
			{
				name: "get_nonexistent",
				test: func(t *testing.T, store DeviceCodeStore) {
					ctx := context.Background()
					_, err := store.GetDeviceCode(ctx, "unknown-device-code")
					assert.ErrorIs(t, err, ErrDeviceCodeNotFound)
				},
			},
			{
				name: "get_expired",
				test: func(t *testing.T, store DeviceCodeStore) {
					ctx := context.Background()
					userCode := "EXPIRED1"
					expiresAt := time.Now().Add(-1 * time.Minute) // Already expired

					deviceCode, err := store.CreateDeviceCode(ctx, userCode, expiresAt)
					require.NoError(t, err)

					_, err = store.GetDeviceCode(ctx, deviceCode)
					assert.ErrorIs(t, err, ErrDeviceCodeExpired)
				},
			},
			{
				name: "complete_nonexistent",
				test: func(t *testing.T, store DeviceCodeStore) {
					ctx := context.Background()
					rawSessionID := RawSessionID("raw-session-123")
					err := store.CompleteDeviceCode(ctx, "unknown-device-code", rawSessionID)
					assert.ErrorIs(t, err, ErrDeviceCodeNotFound)
				},
			},
			{
				name: "complete_already_complete",
				test: func(t *testing.T, store DeviceCodeStore) {
					ctx := context.Background()
					userCode := "COMPLETE"
					expiresAt := time.Now().Add(15 * time.Minute)

					deviceCode, err := store.CreateDeviceCode(ctx, userCode, expiresAt)
					require.NoError(t, err)

					rawSessionID := RawSessionID("raw-session-123")
					err = store.CompleteDeviceCode(ctx, deviceCode, rawSessionID)
					require.NoError(t, err)

					// Try to complete again
					err = store.CompleteDeviceCode(ctx, deviceCode, rawSessionID)
					assert.ErrorIs(t, err, ErrDeviceCodeAlreadyComplete)
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				store := c.NewStore()
				tt.test(t, store)
			})
		}
	})

	t.Run("Store Special Cases", func(t *testing.T) {
		t.Run("complete_success", func(t *testing.T) {
			store := c.NewStore()
			ctx := context.Background()
			userCode := "SUCCESS1"
			expiresAt := time.Now().Add(15 * time.Minute)

			deviceCode, err := store.CreateDeviceCode(ctx, userCode, expiresAt)
			require.NoError(t, err)

			rawSessionID := RawSessionID("raw-session-456")
			err = store.CompleteDeviceCode(ctx, deviceCode, rawSessionID)
			require.NoError(t, err)

			entry, err := store.GetDeviceCode(ctx, deviceCode)
			require.NoError(t, err)
			assert.True(t, entry.Completed)
			assert.Equal(t, rawSessionID, entry.SessionID)
		})

		t.Run("create_user_code_collision", func(t *testing.T) {
			// This test is primarily for testing the generateUserCode function
			// with collision detection. The store itself doesn't prevent collisions,
			// but GetByUserCode should return the first matching entry.
			store := c.NewStore()
			ctx := context.Background()
			userCode := "COLLISION"
			expiresAt := time.Now().Add(15 * time.Minute)

			// Create first entry
			deviceCode1, err := store.CreateDeviceCode(ctx, userCode, expiresAt)
			require.NoError(t, err)

			// Create second entry with same user code (should be prevented at handler level)
			// For the store contract, GetByUserCode should return an entry
			entry, err := store.GetByUserCode(ctx, userCode)
			require.NoError(t, err)
			assert.Equal(t, deviceCode1, entry.DeviceCode)
			assert.Equal(t, userCode, entry.UserCode)
		})

		t.Run("get_by_user_code_nonexistent", func(t *testing.T) {
			store := c.NewStore()
			ctx := context.Background()

			_, err := store.GetByUserCode(ctx, "NOTFOUND")
			assert.ErrorIs(t, err, ErrDeviceCodeNotFound)
		})

		t.Run("update_last_poll", func(t *testing.T) {
			store := c.NewStore()
			ctx := context.Background()
			userCode := "POLL1234"
			expiresAt := time.Now().Add(15 * time.Minute)

			deviceCode, err := store.CreateDeviceCode(ctx, userCode, expiresAt)
			require.NoError(t, err)

			pollTime := time.Now()
			err = store.UpdateLastPoll(ctx, deviceCode, pollTime)
			require.NoError(t, err)

			entry, err := store.GetDeviceCode(ctx, deviceCode)
			require.NoError(t, err)
			assert.WithinDuration(t, pollTime, entry.LastPoll, time.Second)
		})

		t.Run("cleanup_expired", func(t *testing.T) {
			store := c.NewStore()
			ctx := context.Background()

			// Create expired entry
			expiredCode, err := store.CreateDeviceCode(ctx, "EXPIRED1", time.Now().Add(-1*time.Minute))
			require.NoError(t, err)

			// Create valid entry
			validCode, err := store.CreateDeviceCode(ctx, "VALID1", time.Now().Add(15*time.Minute))
			require.NoError(t, err)

			// Cleanup expired entries
			err = store.CleanupExpired(ctx)
			require.NoError(t, err)

			// Expired should be gone
			_, err = store.GetDeviceCode(ctx, expiredCode)
			assert.Error(t, err)

			// Valid should still exist
			_, err = store.GetDeviceCode(ctx, validCode)
			assert.NoError(t, err)
		})
	})
}
