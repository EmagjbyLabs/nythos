# Domain Model

This document defines the main nouns in `nythos-core` and the invariants they preserve.

## Typed IDs

`nythos-core` uses typed newtype wrappers over `Uuid` for all primary identity references:

- `UserId`
- `TenantId`
- `SessionId`
- `RoleId`

Purpose:

- prevent mixing unrelated IDs by accident
- make function signatures explicit
- keep serialization and persistence decisions outside the type identity itself

Current behavior:

- each ID wraps a `Uuid`
- each ID exposes `new`, `generate`, `as_uuid`, and `into_uuid`
- each ID supports parsing, display, equality, ordering, and serde

## Value Objects

## `Email`

Validated email value object.

Rules:

- created through validation, not raw public string assignment
- normalized consistently for lookup and comparison
- stored and compared in a way that supports reliable lookup

Current normalization behavior:

- trims surrounding whitespace
- lowercases the full address
- requires a single `@`
- rejects empty local or domain parts
- rejects whitespace inside the address
- requires the domain portion to look structurally valid

## `Password`

Represents validated raw password input.

Rules:

- only used at trust boundaries or during credential verification flows
- should not be confused with a stored hash
- should be handled carefully in APIs and logs

Current validation behavior:

- must be between 8 and 1024 characters
- cannot be empty
- cannot contain newlines
- remains distinct from `PasswordHash`

## Identity

## `User`

Represents an account in the auth domain.

Current fields:

- `UserId`
- `Email`
- `UserStatus`
- `created_at`

Current status values:

- `Active`
- `Locked`
- `Disabled`

Invariants:

- user identity is stable through `UserId`
- auth flows check status before issuing new sessions
- status is domain state, not an HTTP concern

## `Tenant`

Represents a tenant boundary.

Current fields:

- `TenantId`
- slug
- optional `TenantSettings`

Current notes:

- slug validation stays lowercase ASCII plus `-`
- tenant identity is stable through `TenantId`
- RBAC is tenant-scoped
- user lookup operations in the core are tenant-aware
- `TenantSettings` is optional tenant metadata stored as a string map

## Auth Concepts

## `PasswordHash`

Represents a stored password hash.

Core expectation:

- hashes use Argon2id semantics

This stays abstracted behind `PasswordHasher`, but the intended outer
implementation is Argon2id. The core is not designed around insecure algorithm
swapping.

## `AccessToken`

Represents a short-lived signed token with JWT-like semantics.

Invariants:

- signed, not opaque
- short-lived
- derived from `Claims`
- verification happens through `TokenSigner`

The core treats it as a token value, not as an HTTP bearer header.

## `Claims`

Represents the identity facts embedded into an access token.

Current fields:

- subject `UserId`
- `TenantId`
- `TokenPurpose`
- `issued_at`
- `expires_at`

Current notes:

- claims do not currently embed roles or permissions
- login and refresh load tenant-scoped roles before signing a new access token
- claims must not weaken the tenant boundary

## `TokenPurpose`

Represents why a signed token exists.

Current variant:

- `Access`

## Session

## `Session`

Represents a refresh-capable authenticated session.

Current fields:

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

## `Permission`

Represents a concrete authorization capability.

Current representation is a lowercase ASCII string with a namespace separator `.`.

Examples:

- `users.read`
- `users.write`
- `sessions.revoke`

Permissions reject empty values, missing namespace separators, and invalid character shapes.

## `Role`

Tenant-scoped authorization role.

Current fields:

- `RoleId`
- `TenantId`
- role name
- explicit permission set

Invariant:

- a role exists inside exactly one tenant scope

## `RoleAssignment`

Represents a relation between a user and a role within a tenant.

Current fields:

- `TenantId`
- `UserId`
- `RoleId`

Invariant:

- assignment scope must match both the role tenant and the request tenant

## `RoleRegistry`

Represents the available roles for one tenant.

Current shape:

- one `TenantId`
- a list of `Role` values
- validation that every role belongs to the same tenant

Invariant:

- all role and permission lookups are tenant-scoped

There is no global admin concept in `nythos-core`.

## Relationships

- a `User` can have many `Session` records
- a `Session` references exactly one `User` and one `Tenant`
- a `RoleAssignment` links a `User` to a `Role` within one `Tenant`
- an `AccessToken` is issued from `Claims`
- a `RefreshToken` is an opaque handle for session continuation

## Core Invariants

- all role lookups are tenant-scoped
- a session belongs to exactly one user and one tenant
- refresh tokens are opaque and rotated on every successful refresh
- access tokens are short-lived and signed
- claims carry subject, tenant, purpose, and issue/expiry timestamps
- raw passwords and stored hashes are separate types
- the core never maps these concepts to HTTP or transport details
