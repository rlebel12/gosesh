package gosesh

import (
	"context"
	"log/slog"
	"testing"

	"github.com/rlebel12/gosesh/internal"
	"github.com/stretchr/testify/assert"
)

func TestNoopMonitor(t *testing.T) {
	contract := MonitorContract{
		NewMonitor: func() Monitor {
			return &NoopMonitor{}
		},
	}
	contract.Test(t)
}

func TestLoggerMonitor(t *testing.T) {
	contract := MonitorContract{
		NewMonitor: func() Monitor {
			return NewLoggerMonitor(slog.Default())
		},
	}
	contract.Test(t)
}

func TestLoggerMonitor_ErrorHandling(t *testing.T) {
	t.Run("returns error for nil user ID in success case", func(t *testing.T) {
		monitor := NewLoggerMonitor(slog.Default())
		err := monitor.AuditAuthenticationSuccess(context.Background(), nil, nil)
		assert.Error(t, err)
	})

	t.Run("returns error for nil session ID", func(t *testing.T) {
		monitor := NewLoggerMonitor(slog.Default())
		userID := internal.NewFakeIdentifier("user-id")

		err := monitor.AuditSessionCreated(context.Background(), nil, userID, nil)
		assert.Error(t, err)

		err = monitor.AuditSessionDestroyed(context.Background(), nil, userID, "test", nil)
		assert.Error(t, err)

		err = monitor.AuditSessionRefreshed(context.Background(), nil, userID, userID, nil)
		assert.Error(t, err)

		err = monitor.AuditSessionRefreshed(context.Background(), userID, nil, userID, nil)
		assert.Error(t, err)
	})

	t.Run("returns error for nil user ID in session methods", func(t *testing.T) {
		monitor := NewLoggerMonitor(slog.Default())
		sessionID := internal.NewFakeIdentifier("session-id")

		err := monitor.AuditSessionCreated(context.Background(), sessionID, nil, nil)
		assert.Error(t, err)

		err = monitor.AuditSessionDestroyed(context.Background(), sessionID, nil, "test", nil)
		assert.Error(t, err)

		err = monitor.AuditSessionRefreshed(context.Background(), sessionID, sessionID, nil, nil)
		assert.Error(t, err)
	})
}
