# Architecture: Audience Validation for External Token Exchange

**Related Issues:** [audience-validation-external-token](../issues/audience-validation-external-token/index.md)
**Related Plans:** _(to be created after architecture approval)_

## Architecture Overview

This document defines the architecture for adding optional audience (`aud`) claim validation to the `ExchangeExternalToken()` handler. This prevents cross-client token reuse attacks where tokens obtained from unrelated OAuth clients can be used to authenticate.

**Architectural Pattern:** Functional options extension to existing handler

The existing `ExchangeExternalToken()` handler follows gosesh's established patterns. This design extends it using the functional options pattern already used throughout the library, maintaining backward compatibility while adding security capabilities.

**Technology Stack:**

- **Language:** Go 1.21+ (existing)
- **Key Libraries:** `golang.org/x/oauth2` (existing), standard library `net/http`

**Integration Points:**

- OAuth2 provider token introspection endpoints (e.g., Google's tokeninfo)
- Existing `RequestFunc` callback pattern for provider-specific implementations

## System Components

### Component 1: ExchangeOption Functional Options

**Purpose:** Provide extensible configuration for the `ExchangeExternalToken()` handler without breaking existing API.

**Technology:** Go functional options pattern (same as `NewOpts` in gosesh.go)

**Dependencies:** None - pure configuration

**Key Interfaces:** `ExchangeOption` function type applied during handler construction

**Data Flow:** Options collected at handler construction time, stored in handler closure, applied during request processing

### Component 2: AudienceValidator Interface

**Purpose:** Abstract audience validation logic to support different OAuth providers' token introspection mechanisms.

**Technology:** Go interface with provider-specific implementations

**Dependencies:** `context.Context`, HTTP client for provider API calls

**Key Interfaces:** `AudienceValidator` interface - validates token and returns audience claim

**Data Flow:** Token received -> Validator calls provider API -> Returns audience string -> Handler compares against expected audiences

### Component 3: Google TokenInfo Validator (Reference Implementation)

**Purpose:** Concrete implementation of `AudienceValidator` for Google OAuth tokens using Google's tokeninfo endpoint.

**Technology:** HTTP client calling `https://www.googleapis.com/oauth2/v1/tokeninfo`

**Dependencies:** `http.Client`, Google's tokeninfo API

**Key Interfaces:** Implements `AudienceValidator`

**Data Flow:** Access token -> HTTP GET to tokeninfo -> Parse JSON response -> Extract `audience` field

## Interface Definitions

### ExchangeOption Type

```go
// ExchangeOption configures optional behavior for ExchangeExternalToken.
type ExchangeOption func(*exchangeConfig)

// exchangeConfig holds optional configuration for token exchange.
type exchangeConfig struct {
    audienceValidator AudienceValidator
    expectedAudiences []string
}
```

### AudienceValidator Interface

```go
// AudienceValidator validates an OAuth2 access token and returns the audience claim.
// Implementations call provider-specific token introspection endpoints.
type AudienceValidator interface {
    // ValidateAudience validates the token and returns the audience (aud) claim.
    // Returns an error if the token is invalid or the audience cannot be determined.
    ValidateAudience(ctx context.Context, accessToken string) (audience string, err error)
}
```

### Functional Option Functions

```go
// WithAudienceValidator sets a validator for checking token audience claims.
// When set, the handler will validate that tokens were issued for an expected client.
func WithAudienceValidator(v AudienceValidator) ExchangeOption {
    return func(cfg *exchangeConfig) {
        cfg.audienceValidator = v
    }
}

// WithExpectedAudiences sets the allowed audience values for token validation.
// Tokens with audiences not in this list will be rejected.
// Multiple audiences support scenarios where a backend accepts tokens from multiple clients.
func WithExpectedAudiences(audiences ...string) ExchangeOption {
    return func(cfg *exchangeConfig) {
        cfg.expectedAudiences = audiences
    }
}
```

### Error Types

```go
// AudienceValidationError indicates a token's audience didn't match expected values.
type AudienceValidationError struct {
    Expected []string
    Actual   string
}

func (e *AudienceValidationError) Error() string {
    return fmt.Sprintf("validate audience: want=%v got=%q", e.Expected, e.Actual)
}

// ErrFailedValidatingAudience is a sentinel for audience validation failures.
var ErrFailedValidatingAudience = errors.New("failed validating audience")
```

### Google TokenInfo Validator

```go
// GoogleTokenInfoValidator validates Google OAuth tokens using the tokeninfo endpoint.
type GoogleTokenInfoValidator struct {
    client *http.Client
}

// NewGoogleTokenInfoValidator creates a validator for Google access tokens.
func NewGoogleTokenInfoValidator(client *http.Client) *GoogleTokenInfoValidator {
    if client == nil {
        client = http.DefaultClient
    }
    return &GoogleTokenInfoValidator{client: client}
}

func (v *GoogleTokenInfoValidator) ValidateAudience(ctx context.Context, accessToken string) (string, error) {
    // Implementation calls https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=...
    // Returns the "audience" field from the response
    //
    // IMPORTANT: Must use context for timeout control. Create HTTP request with ctx
    // using http.NewRequestWithContext(ctx, ...) to ensure the request respects
    // context cancellation and deadlines. Callers should set appropriate timeouts
    // via context.WithTimeout() before calling this method.
}
```

### Updated ExchangeExternalToken Signature

```go
// ExchangeExternalToken creates a handler that exchanges an external OAuth2 access token
// for a gosesh session. This is used by native app clients (desktop, mobile, CLI) that
// handle OAuth2/PKCE directly with the identity provider and then exchange the access
// token for a session.
//
// Options:
//   - WithAudienceValidator: Set a validator to check token audience claims
//   - WithExpectedAudiences: Specify allowed audience values
func (gs *Gosesh) ExchangeExternalToken(
    request RequestFunc,
    unmarshal UnmarshalFunc,
    done HandlerDoneFunc,
    opts ...ExchangeOption,
) http.HandlerFunc
```

## Data Architecture

**Data Models:**

- `exchangeConfig`: Internal struct holding validation options
- `tokenInfoResponse`: Google-specific response from tokeninfo endpoint

**Data Flow:**

```
POST /api/auth/token {"access_token": "..."}
    |
    v
Parse request body
    |
    v
[If validator configured]
    |
    +-> Call AudienceValidator.ValidateAudience(ctx, token)
    |       |
    |       +-> Provider API (e.g., Google tokeninfo)
    |       |
    |       +-> Return audience string
    |
    +-> Compare against expectedAudiences
    |       |
    |       +-> Match: Continue
    |       +-> No match: Return AudienceValidationError
    |
    v
Call RequestFunc to get user data (existing flow)
    |
    v
Create session (existing flow)
```

## Technical Decisions

### Decision 1: Functional Options vs. Handler Wrapper

**Context:** How should audience validation be integrated into ExchangeExternalToken?

**Options Considered:**

- **Functional Options:** Add `...ExchangeOption` parameter to existing handler
- **Handler Wrapper:** Create separate `ExchangeExternalTokenWithAudienceValidation()` function
- **Middleware:** Create validation middleware that wraps any handler

**Decision:** Functional Options

**Rationale:**
- Matches existing gosesh patterns (`NewOpts` for Gosesh constructor)
- Single handler function, no proliferation of handler variants
- Backward compatible - existing code continues to work unchanged
- Extensible for future options without API changes

**Tradeoffs:**
- **Benefits:** Clean API, familiar pattern, extensible, backward compatible
- **Costs:** Slightly more complex internal handler logic

### Decision 2: Separate Validator Interface vs. Inline Validation

**Context:** Should audience validation be abstracted behind an interface or implemented inline?

**Options Considered:**

- **Interface:** Define `AudienceValidator` interface with provider implementations
- **Inline Function:** Accept a validation function directly
- **Built-in Only:** Only support known providers (Google, Discord, etc.)

**Decision:** Interface with provider implementations

**Rationale:**
- Different OAuth providers have different token introspection mechanisms
- Google uses tokeninfo endpoint; others may use JWT introspection or different APIs
- Allows users to implement custom validators for unsupported providers
- Provider package can offer ready-made validators

**Tradeoffs:**
- **Benefits:** Flexible, supports any OAuth provider, testable
- **Costs:** Users need to provide/configure validator rather than "just working"

### Decision 3: Error Handling Strategy

**Context:** How should audience validation failures be reported?

**Options Considered:**

- **Sentinel Error:** Add `ErrAudienceValidationFailed` to errors.go
- **Structured Error:** Create `AudienceValidationError` struct with context
- **HTTP Status Only:** Return 401/403 without detailed error

**Decision:** Both sentinel and structured error

**Rationale:**
- Structured error provides debugging context (expected vs. actual audience)
- Sentinel error enables `errors.Is()` checks in done handlers
- Follows existing gosesh pattern (sentinel errors in errors.go)

**Tradeoffs:**
- **Benefits:** Rich error context, consistent with library patterns
- **Costs:** Two error types to maintain

### Decision 4: Google TokenInfo vs. Requiring ID Token

**Context:** For Google specifically, should we use tokeninfo endpoint or require ID tokens?

**Options Considered:**

- **TokenInfo Endpoint:** Call `/oauth2/v1/tokeninfo` with access token
- **ID Token Validation:** Require and validate JWT ID token's `aud` claim
- **Both:** Support either approach

**Decision:** TokenInfo endpoint for reference implementation

**Rationale:**
- Access tokens are what `ExchangeExternalToken` currently receives
- TokenInfo is a simple HTTP call, no JWT parsing complexity
- ID tokens would require API change (new field in request body)
- Can add ID token support later if needed

**Tradeoffs:**
- **Benefits:** Works with existing API, simpler implementation
- **Costs:** Extra network call to Google; ID tokens would be more efficient

### Decision 5: Behavior When Expected Audiences Empty

**Context:** What should happen when a validator is configured but no expected audiences are set?

**Options Considered:**

- **Permissive:** Skip audience comparison, only validate token is valid
- **Strict:** Return error indicating misconfiguration
- **Warn:** Log warning but allow request to proceed

**Decision:** Permissive - skip audience comparison

**Rationale:**
- Matches existing gosesh philosophy (e.g., nil done handler gets default)
- Allows gradual adoption: configure validator first, add audiences later
- Avoids breaking requests due to configuration oversight
- Token is still validated (via validator call), just not audience-checked

**Tradeoffs:**
- **Benefits:** Graceful degradation, easier adoption path
- **Costs:** Silent acceptance when audiences forgotten; could log warning

## Testing Strategy

**Unit Testing:**

- Test `exchangeConfig` option application
- Test `AudienceValidationError` formatting
- Test handler with mock `AudienceValidator`
- Test audience matching logic (single, multiple, no match)

**Integration Testing:**

- Test `GoogleTokenInfoValidator` with mock HTTP responses
- Test full `ExchangeExternalToken` flow with audience validation

**Test Cases:**

| Scenario | Expected Outcome |
|----------|------------------|
| No validator configured | Existing behavior, no audience check |
| Validator configured, audience matches | Session created |
| Validator configured, audience mismatch | `AudienceValidationError` returned |
| Validator configured, no expected audiences set | Validation skipped (permissive - see Decision 5) |
| Validator returns error | Error propagated to done handler |
| Multiple expected audiences, one matches | Session created |

## Security Considerations

**Authentication:** This feature enhances authentication by preventing cross-client token reuse.

**Authorization:** No authorization changes - audience validation occurs before session creation.

**Data Protection:** Access tokens are passed to external APIs (tokeninfo) - ensure HTTPS.

**Vulnerability Mitigation:**

- **Cross-client token reuse (main threat):** Prevented by audience validation
- **Time-of-check/time-of-use:** Minimal window; audience is static for token lifetime
- **Token replay:** Not addressed by this feature (out of scope)

## Backward Compatibility

This design maintains full backward compatibility:

1. Existing `ExchangeExternalToken(request, unmarshal, done)` calls continue to work
2. New optional `...ExchangeOption` parameter is variadic (zero options = existing behavior)
3. No changes to `ExchangeTokenRequest` or `ExchangeTokenResponse` types
4. Existing providers unchanged; new validators are additive

## Known Limitations

**ID Token Validation Not Supported (Future Enhancement)**

The current design uses access token introspection (tokeninfo endpoint) which requires an extra network call. ID token validation would be more efficient since ID tokens are JWTs with the `aud` claim embedded, eliminating the extra API call.

Future enhancement path:
- Add `id_token` field to `ExchangeTokenRequest`
- Create `IDTokenValidator` interface for JWT-based validation
- Support both access token and ID token validation modes

This is deferred because:
1. Access tokens are what the current API receives
2. TokenInfo approach is simpler (no JWT parsing/verification)
3. ID token support requires API change (new request field)

---

_This is a living document. Update as the system evolves, architectural decisions change, or new components are added._
