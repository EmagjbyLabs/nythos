# Architecture

This document defines what `nythos-core` contains today and what must stay out.

The crate already includes implemented domain types, auth/session/RBAC models,
orchestration services, and boundary ports. These notes describe the constraints
those modules follow.

## Boundary

`nythos-core` is the pure core of Nythos.

It owns:

- domain types and invariants
- auth, session, and RBAC business rules
- orchestration logic for core auth flows
- async trait contracts for required external capabilities
- OAuth provider/domain modeling and decision-only login/linking outcomes

It does not own:

- HTTP handlers, routers, middleware, or status codes
- SQL queries, ORM models, migrations, or database drivers
- Redis clients, cache adapters, queues, or event buses
- email, SMS, OAuth provider mechanics, or webhook integrations
- concrete signing libraries or password-hasher implementations
- product-specific admin models or deployment concerns

For OAuth specifically, gateway/adapters own redirects, OAuth state and CSRF,
PKCE, authorization-code exchange, provider token exchange, provider ID-token
validation, JWKS fetching, provider userinfo fetching, HTTP routes, cookies,
client secrets, client IDs, provider SDKs, framework/runtime behavior, and any
database schema or migrations.

Core owns only provider/domain modeling, tenant/provider enablement decisions,
verified-profile boundary modeling, external identity linking decisions, explicit
login outcomes, user-status checks before OAuth login/linking, and tenant-scoped
repository contracts.

## Five Layers

1. Domain primitives

- `AuthError`
- `NythosResult`
- typed IDs
- `Email`
- `Password`
- `Username`
- `DisplayName`
- `LoginIdentifier`

2. Identity

- `User`
- `Tenant`
- `TenantAuthPolicy`

3. Auth

- password-hash concepts
- access-token and claims concepts
- token purpose
- register, login, refresh, and revoke orchestration services

4. Session + RBAC

- `Session`
- `RefreshToken`
- `Role`
- `Permission`
- `RoleAssignment`
- `RoleRegistry`

5. Ports

- repository traits
- cryptographic service traits
- revocation-checking traits
- small domain-facing helper payloads for boundary operations

## Dependency Direction

Dependencies point inward.

- `domain` and `error` depend on nothing domain-external
- `auth`, `session`, and `rbac` depend on primitives and shared domain types
- `ports` reference domain types because they describe contracts around them
- infrastructure depends on the core, not the other way around

Practical rule: core code may call trait methods defined in `ports`, but it may
not import infrastructure implementations.

## Module Boundaries

## `error`

Contains the single core error enum `AuthError` and the standard result alias
`NythosResult`.

## `domain`

Contains foundational types and identity models shared across the rest of the crate.

Contains:

- typed ID newtypes over `Uuid`
- `UserId`, `TenantId`, `SessionId`, `RoleId`
- `Email`
- `Password`
- `User`
- `UserStatus`
- `Tenant`
- `TenantSettings`
- `TenantAuthPolicy`
- `OAuthProviderKind`
- `ExternalIdentity`
- `TenantOAuthProviderConfig`
- `VerifiedExternalProfile`

`TenantSettings` is generic tenant metadata only. Auth behavior must not read
string flags from it; services use `TenantAuthPolicy` loaded through
`TenantPolicyPort` for auth decisions.

## `auth`

Contains auth-specific concepts and orchestration logic.

Contains:

- `PasswordHash`
- `AccessToken`
- `Claims`
- `TokenPurpose`
- `RegisterService`
- `LoginService`
- `RefreshService`
- `RevokeSessionService`
- `RevokeAllSessionsService`
- `OAuthLoginOutcome`
- `OAuthLoginService`

`OAuthLoginService` is decision-only. It receives `VerifiedExternalProfile` from
gateway/adapters after provider verification, returns explicit outcomes, and does
not create users, link identities during `resolve_login`, issue sessions, or
validate provider tokens.

## `session`

Contains the session model and refresh-token concepts.

Contains:

- `Session`
- `RefreshToken`

## `rbac`

Contains tenant-scoped authorization concepts.

Contains:

- `Role`
- `Permission`
- `RoleAssignment`
- `RoleRegistry`

## `ports`

Contains pure async trait contracts only.

Contains:

- `UserRepository`
- `TenantPolicyPort`
- `RoleRepository`
- `SessionStore`
- `PasswordHasher`
- `TokenSigner`
- `RevocationChecker`
- `NewUser`
- `UserCredentials`
- `RoleAssignmentInput`
- `SessionRecord`
- `RefreshTokenRotation`
- `ExternalIdentityRepository`
- `TenantOAuthProviderConfigPort`

No default adapters belong here.

## Service-side Auth Policy Enforcement

Auth policy is enforced in services, not repositories.

- register and login services load `TenantAuthPolicy` through `TenantPolicyPort`
- register rejects submitted optional profile fields when the corresponding policy flag is disabled
- login parses `LoginIdentifier` and branches between email and username lookup
- repositories resolve explicit lookup keys such as email or username
- repositories do not infer policy from tenant settings or choose a lookup strategy from a raw identifier

`UserRepository` intentionally has explicit credential methods such as
`find_credentials_by_email` and `find_credentials_by_username`. A generic
`find_credentials_by_identifier` is intentionally not part of the port shape,
because parsing, branching, and policy gating belong in the core service layer.

## Role Of Ports

Ports are async runtime-agnostic contracts for capabilities the core needs but must not implement directly.

Examples:

- loading and persisting users
- hashing and verifying passwords
- signing and verifying access tokens
- storing, rotating, and revoking sessions
- resolving tenant-scoped OAuth provider config
- finding, linking, and touching tenant-scoped external identities

OAuth configuration ports are secrets-free. `TenantOAuthProviderConfig` contains
only whether a provider is enabled and whether registration through it is
allowed. It must not contain secrets, client IDs, URLs, redirect URIs, JWKS URLs,
token endpoints, or provider HTTP metadata.

Ports are not extension points for arbitrary plugin systems. They exist because
the core must remain deployment-agnostic.

## Current Design Gap

Verified `Claims` and `RevocationChecker` do not line up completely today.

- `Claims` currently carry subject, tenant, purpose, and issue/expiry timestamps
- `Claims` do not currently carry `SessionId`
- `RevocationChecker` requires `SessionId`
- request-time revocation after token verification therefore cannot be driven by verified `Claims` alone

This is a documented current design gap, not a behavior change request in this
issue.

## Why One Crate

`nythos-core` is kept as a single library crate with internal modules because:

- the current scope is small enough to keep in one crate
- the boundaries are logical, not packaging-driven
- splitting now would add maintenance cost without solving a real problem
- internal module boundaries are enough to keep the architecture clean

A split can still happen later if compile-time, ownership, or public API pressure
makes it useful. Until then, keep it flat.
