# ADR 0004: Refresh Token Rotation

## Status

Accepted

## Context

Refresh tokens are long-lived credentials compared with access tokens. Reusing the same refresh token for the full lifetime of a session increases the blast radius of token theft and makes replay handling weaker.

The core needs a clear rule here so implementations do not diverge.

## Decision

Refresh token rotation is mandatory in `nythos-core`.

On every successful refresh:

- the presented refresh token is invalidated
- a new refresh token is issued
- a new access token is issued

Refresh tokens are opaque in the core model and are not modeled as JWTs.

## Consequences

- refresh replay becomes easier to detect and reject
- session storage must support token replacement
- implementations must treat old refresh tokens as invalid immediately after successful rotation
