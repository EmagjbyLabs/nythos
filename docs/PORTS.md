# Ports

Ports are pure async trait contracts required by the implemented `nythos-core`.

They exist so the core can express what it needs without taking a dependency on
infrastructure.

Rules for all ports:

- traits belong in `nythos-core`
- implementations belong outside `nythos-core`
- ports stay focused on domain needs, not transport or storage details
- ports must not expose HTTP types, SQL types, framework types, or driver-specific errors

## Boundary Helper Structs

The core currently uses small helper structs at the port boundary. These are
domain-facing payloads, not storage rows, transport DTOs, or framework request
objects.

## `NewUser`

Used by:

- `UserRepository::create`
- `RegisterService`

Why it exists:

- keeps user-creation input focused on validated core data
- avoids repository contracts that depend on storage-specific creation payloads
- keeps password-hash transport separate from the user identity payload
- carries optional `Username` and `DisplayName` profile fields after service-side validation and policy checks

Current shape:

```rust
pub struct NewUser { /* email, optional username, optional display name */ }

impl NewUser {
    pub fn new(email: Email) -> Self;
    pub fn with_profile(
        email: Email,
        username: Option<Username>,
        display_name: Option<DisplayName>,
    ) -> Self;
}
```

## `UserCredentials`

Used by:

- `UserRepository::find_credentials_by_email`
- `UserRepository::find_credentials_by_username`
- `LoginService`

Why it exists:

- returns the authenticated `User` together with the stored `PasswordHash`
- lets password verification happen in the core service instead of inside the repository
- avoids leaking persistence layout details into login orchestration

## `RoleAssignmentInput`

Used by:

- `RoleRepository::assign_role`
- `RoleRepository::revoke_role`

Why it exists:

- keeps tenant, user, and role scope explicit in one value
- avoids ambiguous multi-argument role-mutation calls at the boundary
- stays domain-oriented instead of mirroring a join row or API payload

## `SessionRecord`

Used by:

- `SessionStore::create_session`
- `SessionStore::find_by_refresh_token`
- register and login session issuance
- refresh-token lookup before rotation

Why it exists:

- keeps a `Session` and its current opaque `RefreshToken` together at the boundary
- matches the core need to create and reload refresh-capable session state
- avoids coupling the core to token-table, cache, or cookie-specific shapes

## `RefreshTokenRotation`

Used by:

- `SessionStore::rotate_refresh_token`
- `RefreshService`

Why it exists:

- makes one-time refresh-token rotation explicit at the contract boundary
- carries the session identity plus both the previous and next opaque refresh tokens
- keeps refresh rotation domain-facing instead of storage-operation-specific

## `UserRepository`

Responsibility:

- find a user by email within a tenant
- find a user by username within a tenant
- find a user by ID within a tenant
- find login credentials by email within a tenant
- find login credentials by username within a tenant
- create a user
- update user status

Must not do:

- password hashing
- token issuance
- tenant-agnostic lookups when tenant scope is required
- tenant auth policy decisions
- lookup by raw login identifier
- HTTP or database error translation

Core assumptions:

- email lookup is tenant-aware
- username lookup is tenant-aware
- duplicate detection can be enforced reliably enough for registration flows
- returned users reflect current status
- repositories resolve explicit keys only; services parse `LoginIdentifier` and enforce policy

Implemented contract:

```rust
trait UserRepository {
    async fn find_by_email(&self, tenant_id: TenantId, email: &Email) -> NythosResult<Option<User>>;
    async fn find_by_username(
        &self,
        tenant_id: TenantId,
        username: &Username,
    ) -> NythosResult<Option<User>>;
    async fn find_by_id(&self, tenant_id: TenantId, user_id: UserId) -> NythosResult<Option<User>>;
    async fn find_credentials_by_email(
        &self,
        tenant_id: TenantId,
        email: &Email,
    ) -> NythosResult<Option<UserCredentials>>;
    async fn find_credentials_by_username(
        &self,
        tenant_id: TenantId,
        username: &Username,
    ) -> NythosResult<Option<UserCredentials>>;
    async fn create(
        &self,
        tenant_id: TenantId,
        new_user: NewUser,
        password_hash: PasswordHash,
    ) -> NythosResult<User>;
    async fn update_status(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        status: UserStatus,
    ) -> NythosResult<()>;
}
```

Flow notes:

- registration uses `find_by_email` and, when username is present, `find_by_username` for tenant-scoped duplicate checks
- login uses `find_credentials_by_email` or `find_credentials_by_username` so password verification stays in the core service
- services enforce tenant auth policy before calling username lookup methods
- `create` accepts `NewUser` plus `PasswordHash`, not raw persistence fields
- there is intentionally no `find_credentials_by_identifier`; parsing, branching, and policy checks stay in services

## `TenantPolicyPort`

Responsibility:

- load typed tenant auth policy for auth services

Must not do:

- parse HTTP requests or transport payloads
- return untyped string settings for auth decisions
- enforce repository lookups or password verification

Core assumptions:

- all policy loading is tenant-scoped
- absent or default policy disables username registration, display-name registration, and username login
- services, not repositories, enforce policy

Implemented contract:

```rust
trait TenantPolicyPort {
    async fn load_auth_policy(&self, tenant_id: TenantId) -> NythosResult<TenantAuthPolicy>;
}
```

Flow notes:

- register loads this policy before accepting optional username or display name input
- login loads this policy before username credential lookup
- `TenantSettings` must not be used for auth policy decisions

## `RoleRepository`

Responsibility:

- assign a role to a user within a tenant
- revoke a role from a user within a tenant
- get roles for a user within a tenant

Must not do:

- cross-tenant role resolution
- policy decisions outside role membership and retrieval
- global-admin shortcuts

Core assumptions:

- all operations are tenant-scoped
- returned roles belong to the same tenant that was requested

Implemented contract:

```rust
trait RoleRepository {
    async fn assign_role(&self, input: RoleAssignmentInput) -> NythosResult<()>;
    async fn revoke_role(&self, input: RoleAssignmentInput) -> NythosResult<()>;
    async fn get_roles_for_user(&self, tenant_id: TenantId, user_id: UserId) -> NythosResult<Vec<Role>>;
}
```

Flow notes:

- login loads tenant-scoped roles through `get_roles_for_user`
- refresh reloads tenant-scoped roles through `get_roles_for_user`
- assignment and revocation stay explicit through `RoleAssignmentInput`

## `SessionStore`

Responsibility:

- create a session
- find a session by refresh token
- rotate a refresh token for a session
- revoke a session by session ID
- revoke all sessions for a user in a tenant

Must not do:

- JWT signing
- HTTP cookie handling
- transport-specific logout semantics

Core assumptions:

- refresh-token lookup returns the owning session context
- refresh-token rotation invalidates the previous token
- revoke-all is tenant-scoped

Implemented contract:

```rust
trait SessionStore {
    async fn create_session(&self, record: SessionRecord) -> NythosResult<()>;
    async fn find_by_refresh_token(
        &self,
        refresh_token: &RefreshToken,
    ) -> NythosResult<Option<SessionRecord>>;
    async fn rotate_refresh_token(&self, rotation: RefreshTokenRotation) -> NythosResult<()>;
    async fn revoke_session(&self, session_id: SessionId) -> NythosResult<()>;
    async fn revoke_all_for_user(&self, tenant_id: TenantId, user_id: UserId) -> NythosResult<()>;
}
```

Flow notes:

- register and login persist newly issued session state through `create_session`
- refresh resolves the current session through `find_by_refresh_token`
- refresh rotates opaque refresh tokens through `rotate_refresh_token`
- revoke-one and revoke-all use the revoke methods directly

## `PasswordHasher`

Responsibility:

- hash `Password` into `PasswordHash`
- verify raw password against a stored hash

Must not do:

- user lookup
- session management
- expose concrete library types to the core API

Core assumptions:

- implementation uses Argon2id semantics
- verification is constant-time where relevant to the underlying library
- failures are surfaced as core errors, not library-specific types

Implemented contract:

```rust
trait PasswordHasher {
    async fn hash(&self, password: &Password) -> NythosResult<PasswordHash>;
    async fn verify(&self, password: &Password, hash: &PasswordHash) -> NythosResult<bool>;
}
```

`nythos-core` expects Argon2id. The abstraction exists for deployment
separation, not for treating weak algorithms as equivalent options.

## `TokenSigner`

Responsibility:

- sign claims into an access token
- verify an access token into claims

Must not do:

- HTTP header parsing
- session-store lookups
- revocation policy decisions by itself

Core assumptions:

- access tokens are short-lived and signed
- verification rejects invalid or expired tokens
- token-purpose checks can be enforced through claims

Implemented contract:

```rust
trait TokenSigner {
    async fn sign(&self, claims: &Claims) -> NythosResult<AccessToken>;
    async fn verify(&self, token: &AccessToken) -> NythosResult<Claims>;
}
```

## `RevocationChecker`

Responsibility:

- check whether a session has been revoked

Primary use:

- outer layers call this during authenticated request handling after token verification
- `RefreshService` calls it before issuing fresh auth material

Must not do:

- parse HTTP requests
- decide authorization policy beyond revocation status

Core assumptions:

- revocation check is based on session identity or equivalent session context
- revoked sessions cause future authenticated requests to fail

Implemented contract:

```rust
trait RevocationChecker {
    async fn is_revoked(&self, session_id: SessionId) -> NythosResult<bool>;
}
```

## Notes On Port Shape

- the traits are async and accept or return domain types plus small helper payloads
- traits should accept and return domain types, not storage DTOs
- helper structs stay small and domain-oriented because they model boundary intent, not infrastructure schemas
- ports are contracts only, not adapters, mocks, or default implementations
