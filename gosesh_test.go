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

func TestDefaultSessionIDGenerator(t *testing.T) {
	tests := []struct {
		name      string
		assertion func(t *testing.T, rawID RawSessionID, err error)
	}{
		{
			name: "output_is_url_safe",
			assertion: func(t *testing.T, rawID RawSessionID, err error) {
				t.Helper()
				assert.NoError(t, err)
				assert.Regexp(t, "^[A-Za-z0-9_-]+$", rawID.String())
			},
		},
		{
			name: "output_length",
			assertion: func(t *testing.T, rawID RawSessionID, err error) {
				t.Helper()
				assert.NoError(t, err)
				assert.Equal(t, 43, len(rawID.String()))
			},
		},
		{
			name: "uniqueness",
			assertion: func(t *testing.T, rawID RawSessionID, err error) {
				t.Helper()
				seen := make(map[string]bool)
				for i := 0; i < 100; i++ {
					id, err := defaultSessionIDGenerator()
					assert.NoError(t, err)
					idStr := id.String()
					assert.False(t, seen[idStr], "duplicate ID generated: %s", idStr)
					seen[idStr] = true
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawID, err := defaultSessionIDGenerator()
			tt.assertion(t, rawID, err)
		})
	}
}

func TestDefaultSessionIDGeneratorErrorHandling(t *testing.T) {
	gs := New(nil, WithSessionIDGenerator(func() (RawSessionID, error) {
		return "", assert.AnError
	}))
	_, err := gs.idGenerator()
	assert.Error(t, err)
	assert.Equal(t, assert.AnError, err)
}

func TestDefaultSessionIDHasher(t *testing.T) {
	tests := []struct {
		name      string
		input     RawSessionID
		expected  string
		assertion func(t *testing.T, input RawSessionID, expected string, result HashedSessionID)
	}{
		{
			name:     "known_vector",
			input:    "test-session-id",
			expected: "08001f8fa6f5dbb9a20ddf1e8366af93a76815f84035cfd2e93233475c968279",
			assertion: func(t *testing.T, input RawSessionID, expected string, result HashedSessionID) {
				t.Helper()
				assert.Equal(t, expected, result.String())
			},
		},
		{
			name:  "output_length",
			input: "any-input",
			assertion: func(t *testing.T, input RawSessionID, expected string, result HashedSessionID) {
				t.Helper()
				assert.Equal(t, 64, len(result.String()))
			},
		},
		{
			name:  "different_inputs_different_outputs",
			input: "input-a",
			assertion: func(t *testing.T, input RawSessionID, expected string, result HashedSessionID) {
				t.Helper()
				resultA := defaultSessionIDHasher("input-a")
				resultB := defaultSessionIDHasher("input-b")
				assert.NotEqual(t, resultA.String(), resultB.String())
			},
		},
		{
			name:  "deterministic",
			input: "same-input",
			assertion: func(t *testing.T, input RawSessionID, expected string, result HashedSessionID) {
				t.Helper()
				result1 := defaultSessionIDHasher("same-input")
				result2 := defaultSessionIDHasher("same-input")
				assert.Equal(t, result1.String(), result2.String())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := defaultSessionIDHasher(tt.input)
			tt.assertion(t, tt.input, tt.expected, result)
		})
	}
}

func TestHMACSessionIDHasher(t *testing.T) {
	tests := []struct {
		name      string
		input     RawSessionID
		secret    []byte
		expected  string
		assertion func(t *testing.T, input RawSessionID, secret []byte, expected string, result HashedSessionID)
	}{
		{
			name:     "known_vector",
			input:    "test-session-id",
			secret:   []byte("secret-key"),
			expected: "2a6250f226463d825710253fbb7193171f464afa9a608b9a6d712f46585aba3f",
			assertion: func(t *testing.T, input RawSessionID, secret []byte, expected string, result HashedSessionID) {
				t.Helper()
				assert.Equal(t, expected, result.String())
			},
		},
		{
			name:     "rfc4231_test_case_2",
			input:    RawSessionID("what do ya want for nothing?"),
			secret:   []byte("Jefe"),
			expected: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
			assertion: func(t *testing.T, input RawSessionID, secret []byte, expected string, result HashedSessionID) {
				t.Helper()
				assert.Equal(t, expected, result.String())
			},
		},
		{
			name:   "output_length",
			input:  "any-input",
			secret: []byte("key"),
			assertion: func(t *testing.T, input RawSessionID, secret []byte, expected string, result HashedSessionID) {
				t.Helper()
				assert.Equal(t, 64, len(result.String()))
			},
		},
		{
			name:   "different_secrets_different_outputs",
			input:  "same-input",
			secret: []byte("key-a"),
			assertion: func(t *testing.T, input RawSessionID, secret []byte, expected string, result HashedSessionID) {
				t.Helper()
				hasher1 := newHMACSessionIDHasher([]byte("key-a"))
				hasher2 := newHMACSessionIDHasher([]byte("key-b"))
				result1 := hasher1("same-input")
				result2 := hasher2("same-input")
				assert.NotEqual(t, result1.String(), result2.String())
			},
		},
		{
			name:   "different_from_sha256",
			input:  "same-input",
			secret: []byte("key"),
			assertion: func(t *testing.T, input RawSessionID, secret []byte, expected string, result HashedSessionID) {
				t.Helper()
				hmacResult := newHMACSessionIDHasher([]byte("key"))("same-input")
				sha256Result := defaultSessionIDHasher("same-input")
				assert.NotEqual(t, hmacResult.String(), sha256Result.String())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := newHMACSessionIDHasher(tt.secret)
			result := hasher(tt.input)
			tt.assertion(t, tt.input, tt.secret, tt.expected, result)
		})
	}
}

func TestWithSessionIDGenerator(t *testing.T) {
	customGen := func() (RawSessionID, error) {
		return "custom-id", nil
	}
	gs := New(nil, WithSessionIDGenerator(customGen))
	assert.NotNil(t, gs.idGenerator)

	// Verify the generator is the custom one
	id, err := gs.idGenerator()
	assert.NoError(t, err)
	assert.Equal(t, "custom-id", id.String())
}

func TestWithHMACSessionIDHasher(t *testing.T) {
	secret := []byte("test-secret")
	gs := New(nil, WithHMACSessionIDHasher(secret))

	// Verify hasher is set and uses HMAC (output differs from SHA-256)
	assert.NotNil(t, gs.idHasher)
	hmacResult := gs.idHasher("test-input")
	sha256Result := defaultSessionIDHasher("test-input")
	assert.NotEqual(t, hmacResult.String(), sha256Result.String())
}

func TestDefaultGeneratorAndHasherInNew(t *testing.T) {
	gs := New(nil)
	assert.NotNil(t, gs.idGenerator)
	assert.NotNil(t, gs.idHasher)

	// Verify they work
	id, err := gs.idGenerator()
	assert.NoError(t, err)
	assert.NotEmpty(t, id.String())

	hashed := gs.idHasher(id)
	assert.NotEmpty(t, hashed.String())
}

func TestRawSessionIDType(t *testing.T) {
	tests := []struct {
		name           string
		input          RawSessionID
		expectedString string
		expectedIsZero bool
	}{
		{
			name:           "non_empty",
			input:          RawSessionID("abc123"),
			expectedString: "abc123",
			expectedIsZero: false,
		},
		{
			name:           "empty",
			input:          RawSessionID(""),
			expectedString: "",
			expectedIsZero: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedString, tt.input.String())
			assert.Equal(t, tt.expectedIsZero, tt.input.IsZero())
		})
	}
}

func TestHashedSessionIDType(t *testing.T) {
	tests := []struct {
		name           string
		input          HashedSessionID
		expectedString string
		expectedIsZero bool
	}{
		{
			name:           "non_empty",
			input:          HashedSessionID("deadbeef"),
			expectedString: "deadbeef",
			expectedIsZero: false,
		},
		{
			name:           "empty",
			input:          HashedSessionID(""),
			expectedString: "",
			expectedIsZero: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedString, tt.input.String())
			assert.Equal(t, tt.expectedIsZero, tt.input.IsZero())
		})
	}
}

func TestRawSessionIDFromContext(t *testing.T) {
	t.Run("with value present", func(t *testing.T) {
		ctx := context.WithValue(t.Context(), rawSessionIDKey, RawSessionID("test-id"))
		id, ok := RawSessionIDFromContext(ctx)
		assert.True(t, ok)
		assert.Equal(t, "test-id", id.String())
	})

	t.Run("with no value", func(t *testing.T) {
		id, ok := RawSessionIDFromContext(t.Context())
		assert.False(t, ok)
		assert.Equal(t, "", id.String())
	})
}
