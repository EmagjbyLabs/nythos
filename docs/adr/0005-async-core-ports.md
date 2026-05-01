# ADR 0005: Async Core Ports

## Status

Accepted.

## Context

`nythos-core` originally exposed synchronous ports and synchronous auth flow
methods.

That shape blocked natural adapter implementations for Cloudflare Workers D1.
D1 APIs are async, so gateway adapters could not implement
`UserRepository` or `SessionStore` over D1 without introducing fake blocking or
other unnatural bridging behavior.

The core must stay infrastructure-free. It must not pull in Cloudflare, HTTP,
database, or runtime dependencies just to support async storage adapters.

## Decision

Convert the core boundary ports and auth orchestration flow methods to native
Rust `async fn`.

This change includes:

- async port methods for repositories, hashing, signing, and revocation checks
- async auth services for register, login, refresh, revoke-one, and revoke-all
- async internal helpers where core orchestration calls async ports
- `#![allow(async_fn_in_trait)]` at the crate root because this crate
  intentionally exposes runtime-agnostic async contracts and does not want to
  force `Send` futures on adapters

This change explicitly does not introduce `async-trait`, blocking shims, or any
runtime-specific dependency.

## Consequences

- gateway adapters can await D1 calls naturally
- `nythos-core` remains infrastructure-free and runtime-agnostic
- service structs remain borrow-oriented and continue taking dependencies by
  reference
- domain models and value objects remain unchanged
- this is a public API shape change and is released as `v0.1.2`
