# nythos-core

`nythos-core` is the public Rust OSS core library for Nythos.
Nythos is the authentication and authorization system in the Emagjby ecosystem.

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

Everything that touches I/O, transport, storage, external services, or concrete crypto libraries lives outside this crate and is exposed here only through ports.

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

This repo is documentation-first so implementation can start with stable boundaries.

See:

- `docs/ARCHITECTURE.md`
- `docs/DOMAIN_MODEL.md`
- `docs/PORTS.md`
- `docs/FLOWS.md`
- `docs/ERRORS.md`
- `docs/docs/adr/`
