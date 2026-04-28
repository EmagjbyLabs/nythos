# Errors

`nythos-core` uses a single error enum: `AuthError`.

## Purpose

`AuthError` is the common failure type for domain and application-level auth
logic inside the core.

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

Current flow note:

- login does not currently return `UserNotFound`; it collapses missing-user login into `InvalidCredentials`

## `InvalidCredentials`

Return when credentials do not authenticate successfully.

Typical cases:

- login flow cannot find the user
- wrong password
- unknown refresh token presented to refresh
- reuse of a rotated refresh token during refresh

## `AccountLocked`

Return when the user exists but authentication is blocked because the account is locked.

Typical cases:

- lockout policy triggered after repeated failures
- account was locked by an admin or domain rule
- disabled account currently maps here in the login flow as well

## `SessionRevoked`

Return when a session or refresh credential is no longer valid because it was revoked.

Typical cases:

- refresh sees a returned session marked revoked
- refresh sees external revocation through `RevocationChecker`
- revoke-one currently surfaces this error when the target session does not exist in the store contract

## `SessionExpired`

Return when session lifetime is over and refresh or session-based continuation is no longer allowed.

Typical cases:

- refresh attempted after session expiry
- outer layer checks session state and sees it is expired

## `TenantNotFound`

Return when a required tenant context does not exist.

Typical cases:

- tenant-scoped operation references an unknown tenant
- a repository or service maps missing tenant state into a core error

## `PermissionDenied`

Return when an authenticated actor lacks the required permission in the current tenant scope.

Typical cases:

- role and permission evaluation fails authorization
- user attempts tenant action without the required assignment

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

Use this sparingly. Prefer a specific domain variant when the failure is expected
and meaningful to callers.

## Expected Failures vs Internal Failures

Expected domain failures are part of normal auth behavior.

Examples:

- wrong password
- revoked session
- missing tenant
- permission denied

Internal failures indicate that a required dependency or operation failed in a
way the core does not model directly.

Examples:

- token-signing backend failed
- password hasher returned an unexpected error
- persistence layer failed unexpectedly

This distinction matters because outer layers may log, retry, alert, or map
these cases differently.

## Current Flow Semantics

The current implementation uses the variants above with the following concrete
auth-flow semantics.

## Login

- missing-user login returns `AuthError::InvalidCredentials`
- wrong-password login returns `AuthError::InvalidCredentials`
- locked user login returns `AuthError::AccountLocked`
- disabled user login currently returns `AuthError::AccountLocked`

## Refresh

- unknown refresh token returns `AuthError::InvalidCredentials`
- reuse of a rotated refresh token returns `AuthError::InvalidCredentials`
- externally revoked refresh session returns `AuthError::SessionRevoked`
- expired session refresh returns `AuthError::SessionExpired`

## Revocation

- revoke-one for a missing session currently surfaces `AuthError::SessionRevoked`
- revoke-all currently returns success from the service even when no sessions match, as long as the store call itself succeeds

## HTTP Mapping Stays Outside The Core

`nythos-core` never maps `AuthError` to:

- HTTP status codes
- gRPC status codes
- REST error envelopes
- framework exceptions

That mapping belongs in outer layers.
