# nythos-core

`nythos-core` is the public Rust OSS core library for Nythos.
Nythos is the authentication and authorization system in the Emagjby ecosystem.

## Package

- crate: `nythos-core`
- version: `0.1.2`
- license: `MIT`
- docs: `https://docs.rs/nythos-core`
- repository: `https://github.com/EmagjbyLabs/nythos`
- boundary: core-only, infrastructure-free, with no HTTP or storage adapters in this crate

## Scope

`nythos-core` owns:

- domain primitives and validation
- identity, auth, session, and RBAC models
- core auth orchestration rules
- pure trait contracts for infrastructure dependencies

`nythos-core` does not own:

- HTTP or API frameworks
- database drivers or persistence adapters
- Redis, queues, email delivery, or external integrations
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

The reference docs under `docs/` describe the architecture and contracts that the
current implementation follows.

See:

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/DOMAIN_MODEL.md`](docs/DOMAIN_MODEL.md)
- [`docs/PORTS.md`](docs/PORTS.md)
- [`docs/FLOWS.md`](docs/FLOWS.md)
- [`docs/ERRORS.md`](docs/ERRORS.md)
- [`docs/adr/`](docs/adr/)
