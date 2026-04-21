# ADR 0003: Tenant-Scoped RBAC

## Status

Accepted

## Context

Nythos serves multi-tenant authorization use cases.

If roles or permissions are allowed to float outside tenant boundaries in the core, it becomes easy to leak privileges across tenants or to hard-code product-specific global access rules into the shared library.

The core should define the safe default boundary.

## Decision

RBAC in `nythos-core` is tenant-scoped.

- roles belong to a `TenantId`
- permissions are evaluated within tenant context
- role assignment is a user-to-role relation within a tenant

There is no global admin concept in the core.

If a product needs cross-tenant administrative behavior, it must be designed in an outer layer.

## Consequences

- authorization lookups stay explicit and local to a tenant
- the core avoids hidden cross-tenant privilege models
- product-specific super-admin behavior cannot accidentally become part of the shared domain
