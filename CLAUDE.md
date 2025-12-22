# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Testing and Coverage

- `make coverage` - Run tests with coverage report (generates HTML coverage report in ./tmp/coverage.html)
- `go test ./...` - Run all tests
- `go test -v ./providers/` - Run provider tests with verbose output

## Project Architecture

### Core Components

**Gosesh Struct** - Main orchestrator with configurable options:

- Session management (active/idle durations)
- Cookie configuration (names, domains, security)
- Origin and allowed hosts for redirects
- Pluggable storage backend via `Storer` interface

**Storer Interface** - Clean abstraction for persistence:

- `UpsertUser()` - Create/update users from OAuth2 provider data
- `CreateSession()` - Create new user sessions
- `GetSession()` - Retrieve sessions by ID
- `DeleteSession()` - Remove individual sessions
- `DeleteUserSessions()` - Remove all user sessions

**Provider System** - Pluggable OAuth2 provider support:

- Base `Provider` struct with common OAuth2 flow handling
- Built-in providers: Google, Discord, Twitch (in providers/ package)
- Generic type system for type-safe user data handling
- Easy to extend for custom providers

**Middleware Stack** - Multiple authentication middleware options:

- `Authenticate()` - Basic session validation
- `AuthenticateAndRefresh()` - Automatic session refresh
- `RequireAuthentication()` - Require valid session or 401
- `RedirectUnauthenticated()` - Redirect to login page

### Package Organization

- **Root package** (`gosesh.go`, `store.go`, `handlers.go`, `middleware.go`, `cookies.go`, `errors.go`)
- **Providers package** (`providers/`) - OAuth2 provider implementations
- **Internal package** (`internal/`) - Test utilities and shared code
- **Dev package** (`dev/`) - Development example applications

### Security Features

- **Secure Cookie Handling**: HttpOnly, Secure, SameSite protection
- **CSRF Protection**: OAuth2 state parameter validation
- **Session Management**: Configurable idle/active timeouts
- **Host Validation**: Prevents open redirect vulnerabilities
- **Base64 Encoding**: For cookie values and redirect paths

### Key Design Patterns

1. **Interface-Based Design**: Clean separation between storage, providers, and core logic
2. **Functional Options**: Flexible configuration via option functions (`WithLogger`, `WithSessionCookieName`, etc.)
3. **Middleware Pattern**: Composable authentication layers
4. **Generic Provider System**: Type-safe user data handling with Go generics

### Testing Strategy

- **High Test Coverage**: Comprehensive unit tests for all components
- **Contract Testing**: Interface compliance verification (`contract_test.go`)
- **Integration Testing**: End-to-end OAuth2 flow testing
- **Mock/Fake Implementations**: For testing without external dependencies (`fake_test.go`)

## Development Notes

- Memory store (`NewMemoryStore()`) is thread-safe with mutex protection
- OAuth2 flows handle state validation and callback processing automatically
- Session cookies are encrypted and base64 encoded
- All providers follow the same interface pattern for consistency
- Error handling uses predefined error types (`ErrUnauthorized`, `ErrSessionExpired`, etc.)
