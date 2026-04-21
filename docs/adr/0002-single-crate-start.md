# ADR 0002: Single Crate Start

## Status

Accepted

## Context

`nythos-core` has clear internal boundaries, but the initial scope is still small:

- primitives and errors
- identity models
- auth concepts and services
- session models
- RBAC models
- ports

Splitting this into multiple crates immediately would add package management overhead, more public API surfaces, and more refactoring cost before real pressure exists.

## Decision

`nythos-core` starts as one Rust library crate with internal modules:

- `domain`
- `auth`
- `session`
- `rbac`
- `ports`
- `error`

No workspace split and no feature flags are introduced at the start.

## Consequences

- iteration is faster while the model is still settling
- internal refactors stay cheap
- architectural boundaries are enforced by modules and code review first
- crate splitting remains available later if complexity justifies it
