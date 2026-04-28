# Errors

`nythos-core` uses a single error enum: `AuthError`.

## Purpose

`AuthError` is the common failure type for domain and application-level auth logic inside the core.

It exists to:

- keep error handling consistent across modules
- express expected auth and authorization failures in domain terms
- avoid leaking transport or infrastructure concerns into the core API

The standard result alias is:

```rust
pub type NythosResult<T> = Result<T, AuthError>;
```

## Variants

## `UserNotFound`

Return when the requested user does not exist in the relevant tenant scope.

Typical cases:

- lookup by ID fails
- login flow cannot find the user

Whether login surfaces `UserNotFound` directly or collapses it into `InvalidCredentials` is a flow-level policy choice.

## `InvalidCredentials`

Return when credentials do not authenticate successfully.

Typical cases:

- wrong password
- invalid refresh token presented to a refresh flow
- login attempt should avoid revealing whether the user exists

## `AccountLocked`

Return when the user exists but authentication is blocked because the account is locked.

Typical cases:

- lockout policy triggered after repeated failures
- account was locked by an admin or domain rule

## `SessionRevoked`

Return when a session or refresh credential is no longer valid because it was revoked.

Typical cases:

- logout already revoked the session
- revoke-all invalidated the session
- previous refresh token is used after rotation

## `SessionExpired`

Return when session lifetime is over and refresh or session-based continuation is no longer allowed.

Typical cases:

- refresh attempted after session expiry
- outer layer checks session state and sees it is expired

## `TenantNotFound`

Return when a required tenant context does not exist.

Typical cases:

- tenant-scoped operation references an unknown tenant
- registration or login is requested for a missing tenant

## `PermissionDenied`

Return when an authenticated actor lacks the required permission in the current tenant scope.

Typical cases:

- role and permission evaluation fails authorization
- user attempts tenant action without required assignment

## `ValidationError(String)`

Return when input fails domain validation.

Typical cases:

- malformed email
- invalid password input shape
- invalid slug or role name format

The message should be practical and implementation-useful, not transport-formatted.

## `Internal(String)`

Return when a failure occurs that the core cannot classify as an expected domain error.

Typical cases:

- hasher implementation failure
- signer failure
- repository or store failure that does not map to a known domain condition

Use this sparingly. Prefer a specific domain variant when the failure is expected and meaningful to callers.

## Expected Failures vs Internal Failures

Expected domain failures are part of normal auth behavior.

Examples:

- wrong password
- revoked session
- missing tenant
- permission denied

Internal failures indicate that a required dependency or operation failed in a way the core does not model directly.

Examples:

- token signing backend failed
- password hasher returned an unexpected error
- persistence layer failed unexpectedly

This distinction matters because outer layers may log, retry, alert, or map these cases differently.

## HTTP Mapping Stays Outside The Core

`nythos-core` never maps `AuthError` to:

- HTTP status codes
- gRPC status codes
- REST error envelopes
- framework exceptions

That mapping belongs in outer layers.
