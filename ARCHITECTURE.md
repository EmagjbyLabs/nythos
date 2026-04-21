# Architecture

This document defines what `nythos-core` is allowed to contain and what must stay out.

## Boundary

`nythos-core` is the pure core of Nythos.

It owns:

- domain types and invariants
- auth, session, and RBAC business rules
- orchestration logic for core auth flows
- trait contracts for required external capabilities

It does not own:

- HTTP handlers, routers, middleware, or status codes
- SQL queries, ORM models, migrations, or database drivers
- Redis clients, cache adapters, queues, or event buses
- email, SMS, OAuth provider, or webhook integrations
- concrete signing libraries or password hasher implementations
- product-specific admin models or deployment concerns

## Five Layers

1. Domain primitives

- `AuthError`
- `NythosResult`
- typed IDs
- `Email`
- `Password`

2. Identity

- `User`
- `Tenant`

3. Auth

- password hash concepts
- credentials and login state concepts
- access token and claims concepts
- token purpose

4. Session + RBAC

- `Session`
- `RefreshToken`
- `Role`
- `Permission`
- `RoleAssignment`
- tenant-scoped role registry

5. Ports

- repository traits
- cryptographic service traits
- revocation checking traits

## Dependency Direction

Dependencies point inward.

- `domain`, `error` should depend on nothing domain-external
- `auth`, `session`, and `rbac` can depend on primitives and shared domain types
- `ports` can reference domain types because they describe contracts around them
- infrastructure must depend on the core, not the other way around

Practical rule: core code may call trait methods defined in `ports`, but it may not import infrastructure implementations.

## Module Boundaries

## `error`

Contains the single core error enum and the standard result alias.

## `domain`

Contains foundational types and identity models that are shared across the rest of the crate.

Expected contents:

- typed ID newtypes over `Uuid`
- `Email`
- `Password`
- `User`
- `Tenant`
- shared status enums or small supporting value objects

## `auth`

Contains auth-specific concepts and orchestration logic.

Expected contents:

- `PasswordHash`
- login attempt or lockout state concepts
- `AccessToken`
- `Claims`
- `TokenPurpose`
- register, login, and refresh services or use-case functions

## `session`

Contains the session model and refresh token concepts.

Expected contents:

- `Session`
- `RefreshToken`
- session lifecycle rules

## `rbac`

Contains tenant-scoped authorization concepts.

Expected contents:

- `Role`
- `Permission`
- `RoleAssignment`
- tenant role registry logic or supporting types

## `ports`

Contains pure trait contracts only.

Expected contents:

- `UserRepository`
- `RoleRepository`
- `SessionStore`
- `PasswordHasher`
- `TokenSigner`
- `RevocationChecker`

No default adapters belong here.

## Role Of Ports

Ports are contracts for capabilities the core needs but must not implement directly.

Examples:

- loading and persisting users
- hashing and verifying passwords
- signing and verifying tokens
- storing and revoking sessions

Ports are not extension points for arbitrary plugin systems. They exist because the core must remain deployment-agnostic.

## Why One Crate

`nythos-core` starts as a single library crate with internal modules because:

- the current scope is small enough to keep in one crate
- the boundaries are logical, not packaging-driven
- early splitting would add maintenance cost without solving a real problem
- internal module boundaries are enough to keep architecture clean at this stage

This can change later if compile-time, ownership, or public API pressure makes a split useful. Until then, keep it flat.
