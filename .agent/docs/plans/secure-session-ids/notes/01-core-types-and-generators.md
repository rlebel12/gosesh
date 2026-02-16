# Phase 01: Core Types and Generators

## Summary

Implemented core session ID types (RawSessionID, HashedSessionID) with generator and hasher functions. Added default crypto/rand-based generator producing 256-bit IDs, default SHA-256 hasher, and optional HMAC-SHA256 hasher. Functional options allow customization. Context helpers enable raw ID propagation through request handling.

## Files

- `/home/rob/code/gosesh/gosesh.go` - Added RawSessionID and HashedSessionID types with String() and IsZero() methods, SessionIDGenerator and SessionIDHasher function types, defaultSessionIDGenerator and defaultSessionIDHasher functions, newHMACSessionIDHasher factory, WithSessionIDGenerator and WithHMACSessionIDHasher options, context key and RawSessionIDFromContext helper, and idGenerator/idHasher fields on Gosesh struct
- `/home/rob/code/gosesh/gosesh_test.go` - Added comprehensive test suite for all new types and functions

## Tests

Added tests to `/home/rob/code/gosesh/gosesh_test.go`:
- 10 test functions covering all specified test cases
- Default generator: 3 parameterized cases + 1 discrete error handling case
- SHA-256 hasher: 4 parameterized cases (known vector, output length, different inputs, deterministic)
- HMAC-SHA256 hasher: 5 parameterized cases (known vector, RFC 4231 test case, output length, different secrets, different from SHA-256)
- Functional options: 3 discrete tests (WithSessionIDGenerator, WithHMACSessionIDHasher, default setup)
- RawSessionID type: 2 parameterized cases (non-empty, empty)
- HashedSessionID type: 2 parameterized cases (non-empty, empty)
- Context helpers: 2 discrete tests (value present, no value)
- All tests passing

## Implementation Notes

- Used base64.RawURLEncoding (no padding) for session ID generation as specified in the phase plan
- Error wrapping follows Go conventions with concise format: "generate session ID: %w"
- HMAC hasher implemented as closure factory to capture secret at creation time
- Context key uses empty struct type for zero memory overhead
- Default generator and hasher set in New() before applying options, allowing options to override

## Issues

None encountered. Implementation followed plan exactly.
