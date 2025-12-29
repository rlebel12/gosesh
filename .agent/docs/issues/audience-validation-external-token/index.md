# Issue: ExchangeExternalToken Missing Audience (aud) Claim Validation

---

title: "ExchangeExternalToken missing audience validation allows cross-client token reuse"
type: security
priority: high
complexity: moderate
estimated_effort: half-day
context:
  files_involved:
    - handlers.go (ExchangeExternalToken)
    - providers/google.go (requestUser)
  conversation_extract: "Discovered during scribe desktop app integration - tokens from any Google OAuth client can authenticate"

---

## Executive Summary

The `ExchangeExternalToken()` handler validates Google access tokens by calling the userinfo endpoint, but does not verify that the token was issued for the expected OAuth client (audience/`aud` claim). This allows an attacker with any valid Google access token (from a game, another app, etc.) to authenticate as that Google user on backends using gosesh, bypassing the intended client restriction.

---

## Reproduction Instructions

### Steps to Reproduce

1. Register two Google OAuth clients: `client-a` (your app) and `client-b` (attacker's app)
2. Configure gosesh backend to expect tokens from `client-a`
3. User authenticates with `client-b` and obtains a Google access token
4. Attacker sends that token to backend: `POST /api/auth/token {"access_token": "<token-from-client-b>"}`
5. Backend accepts token and creates session for user

**Expected outcome:** Backend rejects token because `aud` doesn't match expected client ID

**Actual outcome:** Backend accepts any valid Google access token and creates session

**Error messages/symptoms:**

```
No error - token is accepted and session created successfully
```

---

## Investigation Roadmap

### Primary Hypothesis: No Audience Validation in Token Exchange Flow

The `ExchangeExternalToken()` handler calls `RequestFunc` (provider's userinfo endpoint) to validate the token, but Google's userinfo endpoint only validates that the token is valid - it doesn't return or check the audience claim.

**Investigation steps:**

1. Review `handlers.go` `ExchangeExternalToken()` implementation
2. Check what data Google's userinfo endpoint returns
3. Verify no `aud` check exists in the flow
4. Compare with Google's tokeninfo endpoint which does return `aud`

**Expected findings:** No audience validation anywhere in the token exchange flow

**If confirmed, resolution approach:**
- Option A: Add optional `AudienceValidator` callback to `ExchangeExternalToken()`
- Option B: Use Google's tokeninfo endpoint instead of/in addition to userinfo
- Option C: Require ID token (JWT) instead of access token, validate `aud` from JWT claims

### Alternative Hypotheses

#### Hypothesis 2: Userinfo Endpoint Returns Client Info

- **Investigation steps:** Call Google userinfo with access token, examine full response
- **Expected findings:** Response does not include `aud` or `azp` claims
- **If confirmed, resolution approach:** Must use tokeninfo endpoint or ID token

#### Hypothesis 3: Provider-Level Validation Exists

- **Investigation steps:** Check if Google provider has any client validation in `requestUser()`
- **Expected findings:** No client validation exists
- **If confirmed, resolution approach:** Add validation at provider or handler level

---

## Technical Context

### Relevant Files

- `handlers.go` (lines 156-220) - `ExchangeExternalToken()` handler, no audience check
- `providers/google.go` - `requestUser()` calls userinfo endpoint, returns email only
- `providers/provider.go` - Base provider interface

### Related Commands/Functions

- `ExchangeExternalToken(request, unmarshal, done)` - Main handler, delegates to provider
- `requestUser(ctx, accessToken)` - Calls `https://www.googleapis.com/oauth2/v2/userinfo`

### Google Endpoints Reference

| Endpoint | Returns `aud`? | Use Case |
|----------|----------------|----------|
| `/oauth2/v2/userinfo` | No | Get user info only |
| `/oauth2/v1/tokeninfo` | Yes | Validate token + get audience |
| ID Token (JWT) | Yes (in claims) | Self-contained validation |

### Dependencies & Constraints

- Must maintain backward compatibility with existing integrations
- Cannot require ID token if some providers only issue access tokens
- Solution should work for providers beyond Google

---

## Success Criteria

- [ ] `ExchangeExternalToken()` can optionally validate token audience
- [ ] Tokens from non-matching OAuth clients are rejected with clear error
- [ ] Backward compatible: existing integrations without audience validation continue working
- [ ] Documentation updated with security recommendations
- [ ] Test coverage for audience validation scenarios

---

## Conversation Context

Discovered during integration work for scribe desktop app:

The desktop app uses PKCE OAuth flow directly with Google, then exchanges the access token with the Go backend for a session. Investigation revealed that gosesh's `ExchangeExternalToken()` validates the token by calling Google's userinfo endpoint, but doesn't verify the `aud` claim.

Security impact: An attacker could obtain a Google access token from any app (game, social app, etc.) and use it to authenticate as that user on any gosesh-backed service, since the backend has no way to verify the token was issued for the expected OAuth client.

The recommended fix is to add optional audience validation, allowing backends to specify expected client ID(s) and reject tokens issued for other clients.

---

## Proposed Solution Sketch

```go
// Option: Add AudienceValidator to ExchangeExternalToken
type AudienceValidatorFunc func(ctx context.Context, accessToken string) (string, error)

func (gs *Gosesh) ExchangeExternalToken(
    request RequestFunc,
    unmarshal UnmarshalFunc,
    done HandlerDoneFunc,
    opts ...ExchangeOption,  // New: optional validators
) http.HandlerFunc

// Usage:
googleProvider.ExchangeExternalToken(
    WithAudienceValidator(googleTokenInfoValidator),
    WithExpectedAudience("desktop-client-id"),
)
```

---

_When issue resolves: Delete this issue directory._
