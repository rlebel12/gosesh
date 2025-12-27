# Issue: CLI OAuth Flow Exposes Session Token in Redirect URL

---

title: "CLI OAuth flow exposes session token in redirect URL"
type: security
priority: high
complexity: moderate
estimated_effort: half-day
context:
  files_involved:
    - handlers_cli.go
  conversation_extract: "Security review identified that OAuth2CallbackCLI passes session ID directly in localhost redirect URL, contrary to OAuth best practices"

---

## Executive Summary

The `OAuth2CallbackCLI` handler passes the session token directly in the localhost callback URL (`?token=<session_id>`), exposing long-lived credentials in browser history, potentially to browser extensions, and in any URL logging. While RFC 8252 permits HTTP for loopback redirects, major CLI tools like `gcloud` and GitHub CLI avoid this pattern entirely. This represents a deviation from OAuth security best practices where tokens should be returned in HTTP response bodies, not URL parameters.

---

## Problem Analysis

### Current Flow (handlers_cli.go:115-260)

```
1. Desktop opens browser → Our backend → Google OAuth
2. User authenticates with Google
3. Google redirects to our backend with ?code=<google_auth_code>
4. Backend exchanges code with Google (server-side)
5. Backend creates session
6. Backend redirects to localhost with ?token=<session_id>  ← Problem
```

At line 255, the session ID is placed directly in the URL:
```go
q.Set("token", session.ID().String())
```

### Security Concerns

1. **Browser History**: Session ID visible in browser history
2. **Browser Extensions**: Extensions with URL access can capture the token
3. **Referer Leakage**: Could leak via referer headers if page loads external resources
4. **Logging**: May be captured by security software or browser telemetry

### Comparison with Industry Tools

| Tool | Flow | What's in URL? | How token arrives |
|------|------|----------------|-------------------|
| **GitHub CLI** | Device code | Nothing | Polling response body |
| **gcloud** | Localhost + PKCE | Authorization code (short-lived) | POST exchange response |
| **gosesh CLI flow** | Localhost | Session ID (long-lived) | Directly in URL |

Neither `gcloud` nor GitHub CLI pass the actual token/session in the URL.

---

## Recommended Resolution

### Option A: Native PKCE Flow + Token Exchange (Recommended)

Remove the CLI flow entirely. Have desktop clients:

1. Perform OAuth with the identity provider directly (using PKCE)
2. Receive the **authorization code** on localhost (this is fine - PKCE protected, short-lived)
3. Exchange code with provider for access token (locally)
4. POST access token to a new backend endpoint to get a session
5. Session ID returned in response body

**Changes Required:**

**Remove from gosesh:**
- `OAuth2BeginCLI` (lines 42-113)
- `OAuth2CallbackCLI` (lines 115-260)
- `CLIStateData` struct
- `isLocalhostURL` helper

**Add to gosesh:**
```go
// ExchangeExternalToken creates a session from a validated external access token.
func (gs *Gosesh) ExchangeExternalToken(
    request RequestFunc,
    unmarshal UnmarshalFunc,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Parse access token from request body
        // Validate token with identity provider (fetch user info)
        // Create session
        // Return session ID in response body (JSON)
    }
}
```

**Net change**: ~220 lines removed, ~60 lines added. Simpler.

### Option B: Add Code Exchange Step

If removing CLI flow is too disruptive, modify it to:

1. Generate a short-lived, single-use authorization code (not session)
2. Pass code in redirect URL: `?code=<auth_code>`
3. Desktop exchanges code for session via POST
4. Session ID returned in response body

This requires new store methods for temporary codes but keeps the existing flow structure.

### Why Option A is Preferred

1. **Aligns with gcloud's pattern** - proven approach from Google
2. **Simpler backend** - no CLI-specific OAuth handlers needed
3. **Better separation** - desktop handles OAuth, backend handles sessions
4. **Leverages PKCE** - authorization code interception is mitigated by PKCE
5. **Device code flow remains** - headless environments still supported

---

## Impact on Device Code Flow

The device code flow is **unaffected** and remains valuable:

- Device code flow returns tokens in poll response bodies (no URL exposure)
- It serves a different use case: headless environments without browsers
- Complements native PKCE for desktop apps

After changes:
- **Has browser**: Native PKCE → `ExchangeExternalToken`
- **No browser**: Device code flow (unchanged)

---

## Technical Context

### Relevant Files

- `handlers_cli.go` - Contains `OAuth2BeginCLI` and `OAuth2CallbackCLI` to be removed/replaced
- `gosesh.go` - Core types, may need new handler method
- `handlers.go` - Reference for existing handler patterns

### Security References

- [RFC 8252: OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252)
- [RFC 7636: PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [OWASP: Information Exposure Through Query Strings](https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url)

---

## Success Criteria

- [ ] Session tokens never appear in redirect URLs
- [ ] Desktop clients can still authenticate via browser-based OAuth
- [ ] Headless clients can still authenticate via device code flow
- [ ] Existing tests updated or removed as appropriate
- [ ] New token exchange endpoint has test coverage
- [ ] Documentation updated to reflect new authentication pattern

---

## Migration Notes

For consumers of gosesh's CLI flow:

1. Update desktop clients to perform OAuth directly with identity provider (using PKCE)
2. Implement localhost callback server to receive authorization code
3. Exchange authorization code with provider for access token
4. Call new `ExchangeExternalToken` endpoint with access token
5. Store returned session ID securely (e.g., OS keychain)

The device code flow remains unchanged for headless environments.

---

_When issue resolves: Delete this issue directory._
