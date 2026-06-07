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

## `Username`

Validated tenant-scoped lookup identifier.

Rules:

- normalized to lowercase ASCII
- used for username lookup and optional username login
- distinct from email and display name
- optional on `User`
- tenant-scoped uniqueness is checked by services and enforced by repositories or storage outside core

## `DisplayName`

Human-readable profile label.

Rules:

- preserves user-facing casing after trimming
- optional on `User`
- profile metadata only
- not used for login lookup

## `LoginIdentifier`

Typed login identifier used by login orchestration.

Current shape:

- `Email(Email)`
- `Username(Username)`

Parsing behavior:

- attempts email parsing first
- attempts username parsing second
- invalid input returns `AuthError::ValidationError(_)`

## Identity

## `User`

Represents an account in the auth domain.

Current fields:

- `UserId`
- `Email`
- `Option<Username>`
- `Option<DisplayName>`
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
- `TenantAuthPolicy`

Current notes:

- slug validation stays lowercase ASCII plus `-`
- tenant identity is stable through `TenantId`
- RBAC is tenant-scoped
- user lookup operations in the core are tenant-aware
- `TenantSettings` is optional tenant metadata stored as a string map
- `TenantSettings` is non-auth metadata only and must not control auth behavior
- `TenantAuthPolicy` is the typed auth policy embedded in `Tenant`

## OAuth Foundation

The OAuth foundation in core is domain-level and decision-first. Gateway/provider
adapters verify provider data before core receives it.

Core owns:

- OAuth provider/domain modeling
- tenant/provider enablement decisions
- verified-profile boundary modeling
- external identity linking decisions
- explicit login outcomes
- user-status checks before OAuth login/linking
- tenant-scoped repository contracts

Core does not own:

- OAuth redirects
- OAuth state or CSRF
- PKCE
- authorization-code exchange
- provider token exchange
- provider ID-token validation
- JWKS fetching
- provider userinfo fetching
- HTTP routes
- cookies
- client secrets or client IDs
- provider SDKs
- runtime/framework behavior
- database schema or migrations

## `OAuthProviderKind`

Supported OAuth/OIDC provider kind known to the core domain.

Current variants:

- `Google`
- `GitHub`
- `Microsoft`

Rules:

- string representation is stable lowercase text
- provider mechanics and HTTP metadata are outside this enum

## `ExternalIdentity`

Provider identity linked to a Nythos user inside one tenant.

Natural key:

- `(tenant_id, provider_kind, provider_subject)`

Rules:

- provider subject is the stable opaque provider user ID
- provider subject is the OAuth login key, not provider email or display name
- provider email and display name are link-time metadata
- storage adapters must enforce tenant/provider/subject uniqueness
- lookup and linking are tenant-scoped

## `TenantOAuthProviderConfig`

Tenant-scoped OAuth provider configuration used by core decisions.

Current fields:

- tenant ID
- provider kind
- enabled flag
- registration allowed flag

Rules:

- secrets-free by design
- contains only core-owned domain decisions
- must not contain secrets, client IDs, URLs, redirect URIs, JWKS URLs, token endpoints, or provider HTTP metadata
- separate from `TenantAuthPolicy` and `TenantPolicyPort`

## `VerifiedExternalProfile`

Normalized external profile already verified by gateway/provider adapters.

Rules:

- trust boundary between gateway/provider adapters and core
- core does not validate OAuth tokens or provider signatures
- core does not fetch JWKS documents or provider userinfo
- `email()` may expose provider metadata whether or not it is verified
- `verified_email()` is the only email accessor safe for account-linking decisions
- `verified_email()` returns `Some(&Email)` only when `email_verified == true`
- unverified email must not be used for auto-linking or account matching

## `TenantAuthPolicy`

Typed auth-relevant tenant policy.

Current flags:

- `username_registration_enabled`
- `display_name_registration_enabled`
- `username_login_enabled`

Defaults:

- all flags default to `false`

Usage:

- register and login services load auth policy through `TenantPolicyPort`
- username registration is accepted only when enabled
- display-name registration is accepted only when enabled
- username login is accepted only when enabled
- auth decisions must not read flags from `TenantSettings`

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
- claims do not currently carry `SessionId`
- this is a known design gap relative to `RevocationChecker`, which requires a `SessionId`
- request-time revocation checks therefore cannot be performed from verified `Claims` alone; outer layers currently need another way to recover or track session identity

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
- a `User` may have an optional `Username` and optional `DisplayName`
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
- tenant auth policy is typed as `TenantAuthPolicy`, not read from `TenantSettings`
- the core never maps these concepts to HTTP or transport details
