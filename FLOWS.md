# Flows

This document defines the core auth orchestration rules for `nythos-core`.

The steps below describe domain flow order, not HTTP endpoints.

## Register

### Inputs

- `TenantId`
- email input
- raw password input
- any minimum user creation fields required by the domain

### Ordered Steps

1. Validate and construct `Email`.
2. Validate and construct `Password` input type.
3. Check whether a user with that email already exists in the tenant.
4. Hash the password through `PasswordHasher`.
5. Persist the new user through `UserRepository`.
6. Create a new session and opaque refresh token.
7. Build claims for the new session.
8. Sign a short-lived access token through `TokenSigner`.
9. Persist the session and refresh token through `SessionStore`.
10. Return the created user plus issued auth material if registration is defined to auto-sign-in.

### Ports Used

- `UserRepository`
- `PasswordHasher`
- `SessionStore`
- `TokenSigner`

### Outputs

- created `User`
- `Session`
- short-lived `AccessToken`
- opaque `RefreshToken`

If the chosen service API does not auto-sign-in on registration, the session and tokens can be omitted. The rule should be explicit in code.

### Failure Cases

- invalid email -> `ValidationError`
- invalid password input -> `ValidationError`
- duplicate user in tenant -> `ValidationError` or a more specific future variant if added
- tenant not found -> `TenantNotFound`
- hashing or persistence failure -> `Internal` unless mapped to a known domain failure

### Security Notes

- duplicate detection must be tenant-scoped
- password is hashed before storage
- raw password must never be persisted as-is

## Login

### Inputs

- `TenantId`
- email input
- raw password input

### Ordered Steps

1. Validate and construct `Email`.
2. Validate and construct `Password` input type.
3. Look up the user by email within the tenant.
4. Check user status and any lockout state.
5. Verify password through `PasswordHasher`.
6. Load tenant-scoped roles through `RoleRepository`.
7. Create a new `Session`.
8. Create an opaque `RefreshToken`.
9. Build claims from user, tenant, session, and role context.
10. Sign a short-lived JWT access token through `TokenSigner`.
11. Persist the session and refresh token through `SessionStore`.
12. Return session and tokens.

### Ports Used

- `UserRepository`
- `PasswordHasher`
- `RoleRepository`
- `SessionStore`
- `TokenSigner`

### Outputs

- `Session`
- `AccessToken`
- `RefreshToken`
- optionally user and role context if the service API chooses to return them

### Failure Cases

- user not found -> `UserNotFound` or `InvalidCredentials`, depending on the anti-enumeration policy chosen by the core API
- account locked -> `AccountLocked`
- password mismatch -> `InvalidCredentials`
- tenant not found -> `TenantNotFound`
- role load failure -> `Internal` unless mapped to a known domain failure

### Security Notes

- lockout checks happen before issuing new credentials
- RBAC load is tenant-scoped only
- access token must be short-lived
- refresh token must be opaque

## Token Refresh

### Inputs

- opaque `RefreshToken`

### Ordered Steps

1. Find the session record by refresh token through `SessionStore`.
2. Check whether the session is revoked.
3. Check whether the session is expired.
4. Load the current user and confirm status if required by the service design.
5. Load current tenant-scoped roles if claims need fresh RBAC state.
6. Create a new opaque refresh token.
7. Rotate refresh token storage so the previous token becomes invalid.
8. Build fresh claims.
9. Sign a new short-lived access token.
10. Return the new access token and new refresh token.

### Ports Used

- `SessionStore`
- `UserRepository`
- `RoleRepository`
- `TokenSigner`

### Outputs

- new `AccessToken`
- new `RefreshToken`

### Failure Cases

- refresh token not found -> `InvalidCredentials` or `SessionRevoked`, depending on exact API choice
- session revoked -> `SessionRevoked`
- session expired -> `SessionExpired`
- user no longer valid -> `UserNotFound`, `AccountLocked`, or other applicable status error
- rotation failure -> `Internal`

### Security Notes

- refresh token rotation is mandatory
- successful refresh invalidates the previous refresh token
- refresh token is not self-describing and must not be treated like an access token

## Revocation / Logout / Revoke-All

### Inputs

- target `SessionId` for single-session logout, or
- `TenantId` + `UserId` for revoke-all

### Ordered Steps

1. Receive a revocation trigger.
2. Revoke the target session or all sessions for the user in the tenant through `SessionStore`.
3. Future authenticated requests verify token claims, then fail revocation checks through `RevocationChecker` or equivalent session-state lookup.

### Possible Triggers

- user logout
- admin action
- account ban or disable
- user deletion

### Ports Used

- `SessionStore`
- `RevocationChecker`

### Outputs

- success acknowledgment only; no transport semantics in the core

### Failure Cases

- session not found -> implementation may treat as idempotent success or surface a domain error, but the choice should be explicit
- tenant not found -> `TenantNotFound`
- persistence failure -> `Internal`

### Security Notes

- revoke-all is tenant-scoped
- revocation must affect future requests even if an access token has not yet expired, if the outer layer checks revocation on authenticated requests
- the core defines the revocation rule; outer layers enforce it at request boundaries
