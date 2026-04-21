# Ports

Ports are pure trait contracts required by `nythos-core`.

They exist so the core can express what it needs without taking a dependency on infrastructure.

Rules for all ports:

- traits belong in `nythos-core`
- implementations belong outside `nythos-core`
- ports must stay focused on domain needs, not transport or storage details
- ports must not expose HTTP types, SQL types, framework types, or driver-specific errors

## `UserRepository`

Responsibility:

- find user by email within tenant
- find user by ID within tenant
- create user
- update user status

Must not do:

- password hashing
- token issuance
- tenant-agnostic lookups when tenant scope is required
- HTTP or database error translation

Core assumptions:

- email lookup is tenant-aware
- duplicate detection can be enforced reliably enough for registration flows
- returned users reflect current status

Pseudo-signature:

```rust
trait UserRepository {
    fn find_by_email(&self, tenant_id: TenantId, email: &Email) -> NythosResult<Option<User>>;
    fn find_by_id(&self, tenant_id: TenantId, user_id: UserId) -> NythosResult<Option<User>>;
    fn create(&self, tenant_id: TenantId, user: NewUser, password_hash: PasswordHash) -> NythosResult<User>;
    fn update_status(&self, tenant_id: TenantId, user_id: UserId, status: UserStatus) -> NythosResult<()>;
}
```

`NewUser` can be introduced if needed during implementation. The important part is that creation does not accept raw persistence details.

## `RoleRepository`

Responsibility:

- assign role to user within tenant
- revoke role from user within tenant
- get roles for user within tenant

Must not do:

- cross-tenant role resolution
- policy decisions outside role membership and retrieval
- global admin shortcuts

Core assumptions:

- all operations are tenant-scoped
- returned roles belong to the same tenant that was requested

Pseudo-signature:

```rust
trait RoleRepository {
    fn assign_role(&self, tenant_id: TenantId, user_id: UserId, role_id: RoleId) -> NythosResult<()>;
    fn revoke_role(&self, tenant_id: TenantId, user_id: UserId, role_id: RoleId) -> NythosResult<()>;
    fn get_roles_for_user(&self, tenant_id: TenantId, user_id: UserId) -> NythosResult<Vec<Role>>;
}
```

## `SessionStore`

Responsibility:

- create session
- find session by refresh token
- revoke session by session ID
- revoke all sessions for user in tenant
- support refresh token rotation as part of session lifecycle

Must not do:

- JWT signing
- HTTP cookie handling
- transport-specific logout semantics

Core assumptions:

- refresh token lookup returns the owning session context
- refresh token rotation invalidates the previous token
- revoke-all is tenant-scoped

Pseudo-signature:

```rust
trait SessionStore {
    fn create_session(&self, session: Session, refresh_token: RefreshToken) -> NythosResult<()>;
    fn find_by_refresh_token(&self, refresh_token: &RefreshToken) -> NythosResult<Option<SessionRecord>>;
    fn rotate_refresh_token(&self, session_id: SessionId, previous: &RefreshToken, next: RefreshToken) -> NythosResult<()>;
    fn revoke_session(&self, session_id: SessionId) -> NythosResult<()>;
    fn revoke_all_for_user(&self, tenant_id: TenantId, user_id: UserId) -> NythosResult<()>;
}
```

`SessionRecord` can include the `Session` plus whatever minimal refresh linkage the core needs.

## `PasswordHasher`

Responsibility:

- hash password into `PasswordHash`
- verify raw password against stored hash

Must not do:

- user lookup
- session management
- expose concrete library types to the core API

Core assumptions:

- implementation uses Argon2id semantics
- verification is constant-time where relevant to the underlying library
- failures are surfaced as core errors, not library-specific types

Pseudo-signature:

```rust
trait PasswordHasher {
    fn hash(&self, password: &Password) -> NythosResult<PasswordHash>;
    fn verify(&self, password: &Password, hash: &PasswordHash) -> NythosResult<bool>;
}
```

`nythos-core` expects Argon2id. The abstraction exists for deployment separation, not for treating weak algorithms as equivalent options.

## `TokenSigner`

Responsibility:

- sign claims into an access token
- verify an access token into claims

Must not do:

- HTTP header parsing
- session store lookups
- revocation policy decisions by itself

Core assumptions:

- access tokens are short-lived and signed
- verification rejects invalid or expired tokens
- token purpose checks can be enforced through claims

Pseudo-signature:

```rust
trait TokenSigner {
    fn sign(&self, claims: &Claims) -> NythosResult<AccessToken>;
    fn verify(&self, token: &AccessToken) -> NythosResult<Claims>;
}
```

## `RevocationChecker`

Responsibility:

- check whether a session has been revoked

Primary use:

- outer layers call this during authenticated request handling after token verification

Must not do:

- parse HTTP requests
- decide authorization policy beyond revocation status

Core assumptions:

- revocation check is based on session identity or equivalent session context
- revoked sessions cause future authenticated requests to fail

Pseudo-signature:

```rust
trait RevocationChecker {
    fn is_revoked(&self, session_id: SessionId) -> NythosResult<bool>;
}
```

## Notes On Port Shape

- async vs sync is an implementation detail to settle with actual crate constraints; the contract boundaries matter more than the exact keyword right now
- traits should accept and return domain types, not storage DTOs
- if helper input structs are needed, keep them small and domain-oriented
- ports are contracts only, not adapters, mocks, or default implementations
