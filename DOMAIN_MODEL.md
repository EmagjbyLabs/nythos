# Domain Model

This document defines the main nouns in `nythos-core` and the invariants they must preserve.

## Typed IDs

Use typed newtype wrappers over `Uuid` for all primary identity references:

- `UserId`
- `TenantId`
- `SessionId`
- `RoleId`

Purpose:

- prevent mixing unrelated IDs by accident
- make function signatures explicit
- keep serialization and persistence decisions outside the type identity itself

Example shape:

```rust
pub struct UserId(Uuid);
pub struct TenantId(Uuid);
```

These types should be small, copyable or cheaply cloneable, and validation-free beyond underlying UUID construction.

## Value Objects

## `Email`

Validated email value object.

Rules:

- created through validation, not raw public string assignment
- normalized consistently if the implementation chooses normalization
- stored and compared in a way that supports reliable lookup

The core only needs a practical validation boundary, not full email-provider-specific semantics.

## `Password`

Represents unverified raw password input.

Rules:

- only used at trust boundaries or during credential verification flows
- should not be confused with a stored hash
- should be handled carefully in APIs and logs

The core models raw password input and hashed password output as different types.

## Identity

## `User`

Represents an account within a tenant-aware auth system.

Required fields:

- `UserId`
- `Email`
- status
- created timestamp

Expected status examples:

- active
- locked
- disabled or banned

Invariants:

- user identity is stable through `UserId`
- auth flows must check status before issuing new sessions
- status is domain state, not an HTTP concern

## `Tenant`

Represents a tenant boundary.

Required fields:

- `TenantId`
- slug
- optional settings

Invariants:

- tenant identity is stable through `TenantId`
- RBAC is scoped to tenant
- user lookup operations in the core are expected to be tenant-aware

## Auth Concepts

## `PasswordHash`

Represents a stored password hash.

Core expectation:

- hashes use Argon2id semantics

This is still abstracted behind a port, but the intended implementation is Argon2id. The core is not designed around insecure algorithm swapping.

## `AccessToken`

Represents a short-lived signed token, expected to be a JWT.

Invariants:

- signed, not opaque
- short-lived
- derived from `Claims`
- verification happens through a port

The core treats it as a token value, not as an HTTP bearer header.

## `Claims`

Represents the identity and authorization facts embedded into an access token.

Expected contents:

- `UserId`
- `TenantId`
- token purpose
- issued/expiry timestamps
- enough role or permission context for authenticated access decisions if that is the chosen design

Claims must not weaken the tenant boundary.

## `TokenPurpose`

Represents why a token exists.

Minimum expected use:

- distinguish access tokens from any other signed token the core may later support

## Session

## `Session`

Represents a refresh-capable authenticated session.

Required fields:

- `SessionId`
- `UserId`
- `TenantId`
- `issued_at`
- `expires_at`
- revoked state

Invariants:

- a session belongs to exactly one user
- a session belongs to exactly one tenant
- revocation is explicit state, not inferred only from token expiry
- expired sessions must not refresh

`Session` is the durable unit behind refresh flows and revocation checks.

## `RefreshToken`

Represents an opaque refresh credential.

Invariants:

- opaque in the core model
- not a JWT in the core model
- linked to a session through storage, not self-describing claims
- rotated on every successful refresh

The previous refresh token becomes invalid after rotation.

## RBAC

## `Role`

Tenant-scoped authorization role.

Required fields:

- `RoleId`
- `TenantId`
- role name or key
- a permission set or permission references

Invariant:

- a role exists inside exactly one tenant scope

## `Permission`

Represents a concrete authorization capability.

Examples might be strings or typed values such as:

- `users.read`
- `users.write`
- `sessions.revoke`

The core should keep permission representation simple and explicit.

## `RoleAssignment`

Represents a relation between a user and a role within a tenant.

Minimum relationship:

- `UserId`
- `RoleId`
- `TenantId`

Invariant:

- assignment scope must match both the role tenant and the request tenant

## Tenant-Scoped Role Registry

Represents the available roles and permissions for a tenant.

Invariant:

- all role and permission lookups are tenant-scoped

There is no global admin concept in `nythos-core`.

## Relationships

- a `User` can have many `Session` records in one or more tenants, depending on the surrounding product rules
- a `Session` references exactly one `User` and one `Tenant`
- a `RoleAssignment` links a `User` to a `Role` within one `Tenant`
- an `AccessToken` is issued from `Claims`
- a `RefreshToken` is an opaque handle for session continuation

## Core Invariants

- all role lookups are tenant-scoped
- a session belongs to exactly one user and one tenant
- refresh tokens are opaque and rotatable
- access tokens are short-lived and signed
- raw passwords and stored hashes are separate types
- the core never maps these concepts to HTTP or transport details
