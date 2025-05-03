package gosesh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
)

// Monitor defines the interface for activity monitoring
type Monitor interface {
	// Authentication events
	AuditAuthenticationSuccess(ctx context.Context, userID Identifier, metadata map[string]string) error
	AuditAuthenticationFailure(ctx context.Context, userID Identifier, reason string, metadata map[string]string) error

	// Session events
	AuditSessionCreated(ctx context.Context, sessionID, userID Identifier, metadata map[string]string) error
	AuditSessionDestroyed(ctx context.Context, sessionID, userID Identifier, reason string, metadata map[string]string) error
	AuditSessionRefreshed(ctx context.Context, oldSessionID, newSessionID, userID Identifier, metadata map[string]string) error

	// Provider events
	AuditProviderTokenExchange(ctx context.Context, provider string, success bool, metadata map[string]string) error
	AuditProviderError(ctx context.Context, provider string, err error, metadata map[string]string) error
}

// NoopMonitor is a monitor that does nothing
type NoopMonitor struct{}

func (n *NoopMonitor) AuditAuthenticationSuccess(ctx context.Context, userID Identifier, metadata map[string]string) error {
	return nil
}

func (n *NoopMonitor) AuditAuthenticationFailure(ctx context.Context, userID Identifier, reason string, metadata map[string]string) error {
	return nil
}

func (n *NoopMonitor) AuditSessionCreated(ctx context.Context, sessionID, userID Identifier, metadata map[string]string) error {
	return nil
}

func (n *NoopMonitor) AuditSessionDestroyed(ctx context.Context, sessionID, userID Identifier, reason string, metadata map[string]string) error {
	return nil
}

func (n *NoopMonitor) AuditSessionRefreshed(ctx context.Context, oldSessionID, newSessionID, userID Identifier, metadata map[string]string) error {
	return nil
}

func (n *NoopMonitor) AuditProviderTokenExchange(ctx context.Context, provider string, success bool, metadata map[string]string) error {
	return nil
}

func (n *NoopMonitor) AuditProviderError(ctx context.Context, provider string, err error, metadata map[string]string) error {
	return nil
}

// Ensure NoopMonitor implements Monitor
var _ Monitor = &NoopMonitor{}

// LoggerMonitor is a monitor that logs events to a standard logger
type LoggerMonitor struct {
	logger *slog.Logger
}

// NewLoggerMonitor creates a new LoggerMonitor
func NewLoggerMonitor(logger *slog.Logger) *LoggerMonitor {
	return &LoggerMonitor{
		logger: logger,
	}
}

// hashIdentifier creates a secure hash of an identifier for logging purposes.
// This ensures we don't log the actual identifier values.
func (l *LoggerMonitor) hashIdentifier(id Identifier) string {
	hash := sha256.Sum256([]byte(id.String()))
	return hex.EncodeToString(hash[:8]) // Use first 8 bytes for readability
}

func (l *LoggerMonitor) AuditAuthenticationSuccess(ctx context.Context, userID Identifier, metadata map[string]string) error {
	if userID == nil {
		return fmt.Errorf("user ID cannot be nil for successful authentication")
	}
	l.logger.InfoContext(ctx, "Authentication success", "user_id", userID.String(), "metadata", metadata)
	return nil
}

func (l *LoggerMonitor) AuditAuthenticationFailure(ctx context.Context, userID Identifier, reason string, metadata map[string]string) error {
	userIDStr := "unknown"
	if userID != nil {
		userIDStr = userID.String()
	}
	l.logger.WarnContext(ctx, "Authentication failure", "user_id", userIDStr, "reason", reason, "metadata", metadata)
	return nil
}

func (l *LoggerMonitor) AuditSessionCreated(ctx context.Context, sessionID, userID Identifier, metadata map[string]string) error {
	if sessionID == nil {
		return fmt.Errorf("session ID cannot be nil")
	}
	if userID == nil {
		return fmt.Errorf("user ID cannot be nil")
	}
	l.logger.InfoContext(ctx, "Session created", "session_id", l.hashIdentifier(sessionID), "user_id", userID.String(), "metadata", metadata)
	return nil
}

func (l *LoggerMonitor) AuditSessionDestroyed(ctx context.Context, sessionID, userID Identifier, reason string, metadata map[string]string) error {
	if sessionID == nil {
		return fmt.Errorf("session ID cannot be nil")
	}
	if userID == nil {
		return fmt.Errorf("user ID cannot be nil")
	}
	sessionIDStr := sessionID.String()
	if sessionIDStr != "all" {
		sessionIDStr = l.hashIdentifier(sessionID)
	}
	l.logger.InfoContext(ctx, "Session destroyed", "session_id", sessionIDStr, "user_id", userID.String(), "reason", reason, "metadata", metadata)
	return nil
}

func (l *LoggerMonitor) AuditSessionRefreshed(ctx context.Context, oldSessionID, newSessionID, userID Identifier, metadata map[string]string) error {
	if oldSessionID == nil {
		return fmt.Errorf("old session ID cannot be nil")
	}
	if newSessionID == nil {
		return fmt.Errorf("new session ID cannot be nil")
	}
	if userID == nil {
		return fmt.Errorf("user ID cannot be nil")
	}
	l.logger.InfoContext(ctx, "Session refreshed",
		"old_session_id", l.hashIdentifier(oldSessionID),
		"new_session_id", l.hashIdentifier(newSessionID),
		"user_id", userID.String(),
		"metadata", metadata)
	return nil
}

func (l *LoggerMonitor) AuditProviderTokenExchange(ctx context.Context, provider string, success bool, metadata map[string]string) error {
	status := "failed"
	if success {
		status = "successful"
	}
	l.logger.InfoContext(ctx, "Token exchange", "provider", provider, "status", status, "metadata", metadata)
	return nil
}

func (l *LoggerMonitor) AuditProviderError(ctx context.Context, provider string, err error, metadata map[string]string) error {
	l.logger.ErrorContext(ctx, "Provider error", "provider", provider, "error", err, "metadata", metadata)
	return nil
}

// Ensure LoggerMonitor implements Monitor
var _ Monitor = &LoggerMonitor{}

// ErrorMonitor is a monitor that always returns errors.
// This is used for testing error handling in the Gosesh package.
type ErrorMonitor struct{}

func (e *ErrorMonitor) AuditAuthenticationSuccess(ctx context.Context, userID Identifier, metadata map[string]string) error {
	return fmt.Errorf("fake error: authentication success")
}

func (e *ErrorMonitor) AuditAuthenticationFailure(ctx context.Context, userID Identifier, reason string, metadata map[string]string) error {
	return fmt.Errorf("fake error: authentication failure")
}

func (e *ErrorMonitor) AuditSessionCreated(ctx context.Context, sessionID, userID Identifier, metadata map[string]string) error {
	return fmt.Errorf("fake error: session created")
}

func (e *ErrorMonitor) AuditSessionDestroyed(ctx context.Context, sessionID, userID Identifier, reason string, metadata map[string]string) error {
	return fmt.Errorf("fake error: session destroyed")
}

func (e *ErrorMonitor) AuditSessionRefreshed(ctx context.Context, oldSessionID, newSessionID, userID Identifier, metadata map[string]string) error {
	return fmt.Errorf("fake error: session refreshed")
}

func (e *ErrorMonitor) AuditProviderTokenExchange(ctx context.Context, provider string, success bool, metadata map[string]string) error {
	return fmt.Errorf("fake error: provider token exchange")
}

func (e *ErrorMonitor) AuditProviderError(ctx context.Context, provider string, err error, metadata map[string]string) error {
	return fmt.Errorf("fake error: provider error")
}

// Ensure ErrorMonitor implements Monitor
var _ Monitor = &ErrorMonitor{}
