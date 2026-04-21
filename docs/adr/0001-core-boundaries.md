# ADR 0001: Core Boundaries

## Status

Accepted

## Context

Nythos is split into a public core library and a private implementation layer.

The public piece must be reusable and stable enough to carry domain rules without taking a dependency on any specific transport, storage, or deployment model.

Without a strict boundary, core code would quickly absorb HTTP details, persistence assumptions, and product-specific behavior. That would make the shared library harder to reuse and harder to test.

## Decision

`nythos-core` will contain only:

- domain types and invariants
- auth, session, and RBAC business logic
- trait contracts for required external capabilities

`nythos-core` will not contain:

- HTTP APIs
- database drivers or storage adapters
- cache or queue implementations
- external provider integrations
- deployment-specific behavior

These concerns are represented in the core only as ports.

## Consequences

- the core stays testable with in-memory fakes
- the public crate stays deployment-agnostic
- infrastructure can change without rewriting domain rules
- transport-specific error mapping stays outside the core
- some behaviors require more trait design discipline up front, which is acceptable
