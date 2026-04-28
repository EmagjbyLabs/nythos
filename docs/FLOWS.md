# Flows

This document defines the implemented auth orchestration rules for `nythos-core`.

The steps below describe domain flow order, not HTTP endpoints.

## Register

`RegisterService::register` orchestrates tenant-scoped registration and can
optionally return signed auth material.

### Inputs

- `RegisterInput`
- tenant ID
- email input
- raw password input
- issue time plus access-token and session TTLs
- `auto_sign_in` flag

### Ordered Steps

1. Validate and construct `Email`.
2. Validate and construct `Password`.
3. Check whether a user with that email already exists in the tenant through `UserRepository::find_by_email`.
4. Hash the password through `PasswordHasher`.
5. Persist the new user through `UserRepository::create` using `NewUser` and `PasswordHash`.
6. If `auto_sign_in` is disabled, return `RegisterResult` with the created user and no auth material.
7. If `auto_sign_in` is enabled, create a new `Session`, opaque `RefreshToken`, and access `Claims`.
8. Sign a short-lived access token through `TokenSigner`.
9. Persist the session and refresh token through `SessionStore::create_session` using `SessionRecord`.
10. Return `RegisterResult` with the created user plus `RegisterAuthMaterial`.

### Ports Used

- `UserRepository`
- `PasswordHasher`
- `SessionStore`
- `TokenSigner`

### Outputs

- `RegisterResult`
- always includes the created `User`
- includes `RegisterAuthMaterial` only when auto-sign-in is enabled

### Failure Cases

- invalid email -> `ValidationError`
- invalid password input -> `ValidationError`
- duplicate user in tenant -> `ValidationError`
- hashing, signing, or persistence failures -> propagated core error from the dependency

### Security Notes

- duplicate detection must be tenant-scoped
- password is hashed before storage
- raw password must never be persisted as-is
- refresh tokens are opaque
- access tokens are signed

## Login

`LoginService::login` authenticates credentials, loads current tenant-scoped
roles, and issues fresh session auth material.

### Inputs

- `LoginInput`
- tenant ID
- email input
- raw password input
- issue time plus access-token and session TTLs

### Ordered Steps

1. Validate and construct `Email`.
2. Validate and construct `Password`.
3. Look up credentials by email within the tenant through `UserRepository::find_credentials_by_email`.
4. Check whether the returned user can authenticate.
5. Verify the password through `PasswordHasher`.
6. Load tenant-scoped roles through `RoleRepository::get_roles_for_user`.
7. Create a new `Session`.
8. Create an opaque `RefreshToken`.
9. Build access `Claims` from the authenticated user and tenant.
10. Sign a short-lived access token through `TokenSigner`.
11. Persist the session and refresh token through `SessionStore::create_session` using `SessionRecord`.
12. Return `LoginAuthMaterial`.

### Ports Used

- `UserRepository`
- `PasswordHasher`
- `RoleRepository`
- `SessionStore`
- `TokenSigner`

### Outputs

- `LoginAuthMaterial`
- authenticated `User`
- tenant-scoped `Role` list
- `Session`
- `AccessToken`
- opaque `RefreshToken`
- `Claims`

### Failure Cases

- user not found -> `InvalidCredentials`
- account locked -> `AccountLocked`
- disabled account -> `AccountLocked`
- password mismatch -> `InvalidCredentials`
- role load, signing, or persistence failure -> propagated core error from the dependency

### Security Notes

- missing-user and wrong-password cases both collapse to `InvalidCredentials`
- lockout checks happen before issuing new credentials
- role loading is tenant-scoped only
- access tokens are short-lived and signed
- refresh tokens are opaque

## Token Refresh

`RefreshService::refresh` resolves an opaque refresh token into session context,
checks revocation and expiry, reloads tenant-scoped roles, and rotates the
refresh token.

### Inputs

- `RefreshInput`
- opaque refresh-token string
- issue time plus access-token TTL

### Ordered Steps

1. Parse the provided string into `RefreshToken`.
2. Find the session record by refresh token through `SessionStore::find_by_refresh_token`.
3. If no record matches, return `AuthError::InvalidCredentials`.
4. Check whether the session is revoked locally or through `RevocationChecker`.
5. Check whether the session is expired.
6. Load current tenant-scoped roles through `RoleRepository::get_roles_for_user`.
7. Build fresh access `Claims` from the session user and tenant.
8. Sign a new short-lived access token through `TokenSigner`.
9. Create a new opaque refresh token.
10. Rotate refresh-token storage through `SessionStore::rotate_refresh_token` using `RefreshTokenRotation`.
11. Return `RefreshAuthMaterial` with the same session and the newly issued tokens.

### Ports Used

- `SessionStore`
- `RoleRepository`
- `TokenSigner`
- `RevocationChecker`

### Outputs

- `RefreshAuthMaterial`
- existing `Session`
- freshly loaded tenant-scoped `Role` list
- new `AccessToken`
- new opaque `RefreshToken`
- new `Claims`

### Failure Cases

- refresh token not found -> `InvalidCredentials`
- reuse of a rotated refresh token -> `InvalidCredentials`
- session marked revoked in the returned record -> `SessionRevoked`
- externally revoked session -> `SessionRevoked`
- session expired -> `SessionExpired`
- role load, signing, or rotation failure -> propagated core error from the dependency

### Security Notes

- refresh token rotation is mandatory
- successful refresh invalidates the previous refresh token
- refresh tokens are opaque and resolved through `SessionStore`
- access tokens are signed
- refresh does not currently use `UserRepository`
- role loading is tenant-scoped

## Revoke Single Session

`RevokeSessionService::revoke` revokes one session ID or short-circuits if the
session is already known as revoked.

### Inputs

- `RevokeSessionInput`
- target `SessionId`

### Ordered Steps

1. Check `RevocationChecker::is_revoked` for the target session ID.
2. If the session is already revoked, return `RevokeResult { revoked: false }`.
3. Otherwise revoke the session through `SessionStore::revoke_session`.
4. Return `RevokeResult { revoked: true }`.

### Ports Used

- `SessionStore`
- `RevocationChecker`

### Outputs

- `RevokeResult`
- `revoked = false` when revocation is short-circuited by `RevocationChecker`
- `revoked = true` when the store call succeeds

### Failure Cases

- missing session in the current store contract -> `SessionRevoked`
- persistence failure -> propagated core error from the dependency

### Security Notes

- revocation must affect future requests even if an access token has not yet expired, once outer layers enforce revocation checks
- the core defines the revocation rule; outer layers enforce it at request boundaries

## Revoke All Sessions

`RevokeAllSessionsService::revoke_all` revokes all sessions for one user inside
one tenant.

### Inputs

- `RevokeAllSessionsInput`
- `TenantId`
- `UserId`

### Ordered Steps

1. Receive the tenant-scoped revoke-all request.
2. Revoke all sessions for that user and tenant through `SessionStore::revoke_all_for_user`.
3. Return `RevokeResult { revoked: true }` when the store call succeeds.

### Ports Used

- `SessionStore`

### Outputs

- `RevokeResult`
- `revoked = true` after a successful store call

### Failure Cases

- persistence failure -> propagated core error from the dependency
- no matching sessions -> success from the service when the store call succeeds

### Security Notes

- revoke-all is tenant-scoped
- future authenticated requests must fail once outer layers enforce revocation checks
