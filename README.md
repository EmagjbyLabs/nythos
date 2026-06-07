# nythos-core

`nythos-core` is the public Rust OSS core library for Nythos.
Nythos is the authentication and authorization system in the Emagjby ecosystem.

## Package

- crate: `nythos-core`
- version: `0.2.0`
- license: `MIT`
- docs: `https://docs.rs/nythos-core`
- repository: `https://github.com/EmagjbyLabs/nythos`
- boundary: core-only, infrastructure-free, with no HTTP or storage adapters in this crate

## Scope

`nythos-core` owns:

- domain primitives and validation
- identity, auth, OAuth foundation, session, and RBAC models
- core auth orchestration rules
- pure trait contracts for infrastructure dependencies
- typed tenant auth policy for profile-field and username-login decisions
- tenant OAuth provider enablement and registration decisions
- external identity linking decisions and explicit OAuth login outcomes

`nythos-core` does not own:

- HTTP or API frameworks
- database drivers or persistence adapters
- Redis, queues, email delivery, or external integrations
- OAuth redirects, state/CSRF, PKCE, token exchange, provider validation, provider SDKs, cookies, or HTTP routes
- product-specific operational behavior

## Core Rule

This crate is intentionally core-only and infrastructure-free.

Everything that touches I/O, transport, storage, external services, or concrete crypto libraries lives outside this crate and is exposed here only through async ports.

## Architecture

The core is organized into five layers:

1. Domain primitives
2. Identity
3. Auth
4. Session + RBAC
5. Ports

Dependency direction is inward toward the domain. Ports define contracts at the boundary. Implementations are provided by outer layers.

## Modules

- `domain`: shared types, typed IDs, value objects, identity entities
- `auth`: credentials, password hash concepts, claims, token concepts, auth services
- `session`: session and refresh token models
- `rbac`: roles, permissions, assignments, tenant-scoped RBAC rules
- `ports`: repository and service traits implemented outside the core
- `error`: `AuthError` and `NythosResult`

## Current State

`nythos-core` already includes implemented core domain types, auth/session/RBAC models,
boundary ports, and orchestration services.

The identity profile and login identifier work includes:

- `Username`, `DisplayName`, and `LoginIdentifier` value objects
- `TenantAuthPolicy` with username registration, display-name registration, and username-login flags defaulting to disabled
- `TenantPolicyPort` for loading auth policy before register and login decisions
- optional username and display-name fields on `User`, `NewUser`, and `RegisterInput`
- tenant-policy-gated username registration, display-name registration, and username login

Email/password registration continues to work with the default policy when no optional profile fields are supplied.

The OAuth foundation work includes:

- `OAuthProviderKind`
- `ExternalIdentity`
- `TenantOAuthProviderConfig`
- `VerifiedExternalProfile`
- `ExternalIdentityRepository`
- `TenantOAuthProviderConfigPort`
- `OAuthLoginOutcome`
- `OAuthLoginService::resolve_login`
- `OAuthLoginService::link_identity`

OAuth in `nythos-core` is decision-first and infrastructure-free. Gateway/provider adapters verify OAuth data first and pass only `VerifiedExternalProfile` into core. Core returns `OAuthLoginOutcome` values, checks user status before OAuth login or linking, and keeps tenant-scoped repository contracts. Core does not validate OAuth tokens, perform provider HTTP calls, issue OAuth sessions, create users through OAuth registration, store secrets, or own provider metadata.

The reference docs under `docs/` describe the architecture and contracts that the
current implementation follows.

See:

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/DOMAIN_MODEL.md`](docs/DOMAIN_MODEL.md)
- [`docs/PORTS.md`](docs/PORTS.md)
- [`docs/FLOWS.md`](docs/FLOWS.md)
- [`docs/ERRORS.md`](docs/ERRORS.md)
- [`docs/adr/`](docs/adr/)
