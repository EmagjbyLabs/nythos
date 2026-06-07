# Flows

This document defines the implemented auth orchestration rules for `nythos-core`.

The steps below describe domain flow order, not HTTP endpoints.

## Register

`RegisterService::register` is async and orchestrates tenant-scoped registration and can
optionally return signed auth material.

### Inputs

- `RegisterInput`
- tenant ID
- email input
- raw password input
- optional raw username input
- optional raw display-name input
- issue time plus access-token and session TTLs
- `auto_sign_in` flag

### Ordered Steps

1. Validate and construct `Email`.
2. Validate and construct `Password`.
3. Load tenant auth policy through `TenantPolicyPort::load_auth_policy`.
4. If raw username is present, reject with `ValidationError` when username registration is disabled.
5. If raw username is present and allowed, validate and construct `Username`.
6. If raw display name is present, reject with `ValidationError` when display-name registration is disabled.
7. If raw display name is present and allowed, validate and construct `DisplayName`.
8. Check whether a user with that email already exists in the tenant through `UserRepository::find_by_email`.
9. If username is present, check whether that username already exists in the tenant through `UserRepository::find_by_username`.
10. Hash the password through `PasswordHasher`.
11. Persist the new user through `UserRepository::create` using `NewUser::with_profile` and `PasswordHash`.
12. If `auto_sign_in` is disabled, return `RegisterResult` with the created user and no auth material.
13. If `auto_sign_in` is enabled, create a new `Session`, opaque `RefreshToken`, and access `Claims`.
14. Sign a short-lived access token through `TokenSigner`.
15. Persist the session and refresh token through `SessionStore::create_session` using `SessionRecord`.
16. Return `RegisterResult` with the created user plus `RegisterAuthMaterial`.

### Ports Used

- `UserRepository`
- `TenantPolicyPort`
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
- invalid username input -> `ValidationError`
- invalid display-name input -> `ValidationError`
- username supplied while username registration is disabled -> `ValidationError`
- display name supplied while display-name registration is disabled -> `ValidationError`
- duplicate email in tenant -> `ValidationError`
- duplicate username in tenant -> `ValidationError`
- hashing, signing, or persistence failures -> propagated core error from the dependency

### Security Notes

- duplicate detection must be tenant-scoped
- optional profile fields are accepted only after typed tenant auth policy allows them
- repositories do not enforce tenant auth policy; services enforce it before lookup and create calls
- password is hashed before storage
- raw password must never be persisted as-is
- refresh tokens are opaque
- access tokens are signed

## Login

`LoginService::login` is async, authenticates credentials, loads current tenant-scoped
roles, and issues fresh session auth material.

### Inputs

- `LoginInput`
- tenant ID
- raw login identifier input
- raw password input
- issue time plus access-token and session TTLs

### Ordered Steps

1. Parse `LoginIdentifier` from the raw identifier string.
2. Validate and construct `Password`.
3. Load tenant auth policy through `TenantPolicyPort::load_auth_policy`.
4. If the identifier is `Email`, look up credentials through `UserRepository::find_credentials_by_email`.
5. If the identifier is `Username` and username login is disabled, return `AuthError::InvalidCredentials` without calling username credential lookup.
6. If the identifier is `Username` and username login is enabled, look up credentials through `UserRepository::find_credentials_by_username`.
7. Check whether the returned user can authenticate.
8. Verify the password through `PasswordHasher`.
9. Load tenant-scoped roles through `RoleRepository::get_roles_for_user`.
10. Create a new `Session`.
11. Create an opaque `RefreshToken`.
12. Build access `Claims` from the authenticated user and tenant.
13. Sign a short-lived access token through `TokenSigner`.
14. Persist the session and refresh token through `SessionStore::create_session` using `SessionRecord`.
15. Return `LoginAuthMaterial`.

### Ports Used

- `UserRepository`
- `TenantPolicyPort`
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

- invalid login identifier -> `ValidationError`
- user not found by email or username -> `InvalidCredentials`
- username login disabled -> `InvalidCredentials`
- account locked -> `AccountLocked`
- disabled account -> `AccountLocked`
- password mismatch -> `InvalidCredentials`
- role load, signing, or persistence failure -> propagated core error from the dependency

### Security Notes

- missing-user, disabled username login, and wrong-password cases all collapse to `InvalidCredentials`
- disabled username login does not call `UserRepository::find_credentials_by_username`
- login branches on `LoginIdentifier`; there is no generic credentials-by-identifier repository method
- lockout checks happen before issuing new credentials
- role loading is tenant-scoped only
- access tokens are short-lived and signed
- refresh tokens are opaque

## Token Refresh

`RefreshService::refresh` is async, resolves an opaque refresh token into session context,
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
- refresh at the exact expiry boundary -> `SessionExpired` because session expiry uses `expires_at <= now`
- role load, signing, or rotation failure -> propagated core error from the dependency

### Security Notes

- refresh token rotation is mandatory
- successful refresh invalidates the previous refresh token
- refresh tokens are opaque and resolved through `SessionStore`
- access tokens are signed
- refresh does not currently use `UserRepository`
- role loading is tenant-scoped

## Revoke Single Session

`RevokeSessionService::revoke` is async, revokes one session ID or short-circuits if the
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
- request-time revocation checks need session identity
- `Claims` do not currently carry `SessionId`, so verified claims alone are not enough to call `RevocationChecker`; outer layers currently need another way to recover or track session identity

## OAuth Resolve Login

`OAuthLoginService::resolve_login` is async and resolves the domain outcome for
an OAuth login attempt after gateway/provider adapters have verified the provider
data.

### Inputs

- tenant ID
- `VerifiedExternalProfile`
- current time for last-seen updates

### Ordered Steps

1. Read the provider kind from the verified profile.
2. Load tenant provider config through `TenantOAuthProviderConfigPort::load_provider_config`.
3. If config is missing, return `OAuthLoginOutcome::ProviderDisabled`.
4. If config is disabled, return `OAuthLoginOutcome::ProviderDisabled`.
5. Look up an existing external identity by tenant, provider kind, and provider subject.
6. If an identity exists, load the linked user by tenant and user ID.
7. If the linked user cannot authenticate, return `AuthError::UserNotFoundOrInactive`.
8. Touch the external identity last-seen timestamp.
9. Return `OAuthLoginOutcome::ExistingIdentityLogin`.
10. If no identity exists, read `VerifiedExternalProfile::verified_email()`.
11. If a verified email exists and matches an active user, return `OAuthLoginOutcome::LinkRequired`.
12. Otherwise return `OAuthLoginOutcome::RegistrationRequired` with the tenant provider registration policy.

### Ports Used

- `ExternalIdentityRepository`
- `UserRepository`
- `TenantOAuthProviderConfigPort`

### Outputs

- `OAuthLoginOutcome::ProviderDisabled`
- `OAuthLoginOutcome::ExistingIdentityLogin`
- `OAuthLoginOutcome::LinkRequired`
- `OAuthLoginOutcome::RegistrationRequired`

### Non-goals

- no user creation
- no identity linking
- no session issuance
- no OAuth token validation
- no provider HTTP calls
- no provider redirects or callback handling
- no cookies or framework behavior

### Security Notes

- gateway verifies OAuth provider data before core receives `VerifiedExternalProfile`
- core trusts `VerifiedExternalProfile` as already verified
- core uses only `verified_email()` for account matching decisions
- unverified email must not be used for auto-linking or account matching
- user status is checked before existing-identity login and link-required decisions

## OAuth Link Identity

`OAuthLoginService::link_identity` is async and explicitly links a verified
external profile to an existing active user after gateway obtains user consent.

### Inputs

- tenant ID
- target user ID
- `VerifiedExternalProfile`
- current time for link and last-seen timestamps

### Ordered Steps

1. Load the target user by tenant and user ID.
2. If the user cannot authenticate, return `AuthError::UserNotFoundOrInactive`.
3. Look up an existing external identity by tenant, provider kind, and provider subject.
4. If the identity is already linked to the same user, return `AuthError::OAuthIdentityAlreadyLinkedToSelf`.
5. If the identity is linked to another user, return `AuthError::OAuthIdentityAlreadyLinked`.
6. Create `ExternalIdentity` from the verified profile metadata.
7. Persist the identity through `ExternalIdentityRepository::link`.
8. Return the linked `ExternalIdentity`.

### Ports Used

- `ExternalIdentityRepository`
- `UserRepository`

### Non-goals

- no session issuance
- no user creation
- no provider verification
- no provider enablement re-check
- no provider HTTP calls

### Security Notes

- callers should invoke this only after explicit user consent
- duplicate identity linkage is rejected before persistence
- storage adapters must enforce tenant/provider/subject uniqueness too

## Revoke All Sessions

`RevokeAllSessionsService::revoke_all` is async and revokes all sessions for one user inside
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
- that request-time revocation enforcement still needs session identity outside verified `Claims`, because `Claims` do not currently carry `SessionId`
