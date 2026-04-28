# Public API Audit

This document inventories the current public surface of `nythos-core` ahead of a future `v0.1` crates.io publish.

It records what looks intentionally public today and what should be revisited only in a later explicit API cleanup window.

This issue does not change visibility, remove exports, rename public types, or change runtime behavior.

## High-level Summary

- The crate root already provides a coherent ergonomic surface through `src/lib.rs` re-exports.
- The `auth`, `domain`, and `ports` module roots also expose curated re-export surfaces.
- The strongest accidental exposure risk is deeper implementation-shaped module paths and a few public constructors on output/result wrappers, not the crate-root export list itself.

## Path Layering Today

- `nythos_core::*` exposes selected crate-root re-exports from `src/lib.rs`.
- `nythos_core::auth::*`, `nythos_core::domain::*`, and `nythos_core::ports::*` expose additional module-root re-exports.
- Because several internal files are also declared with `pub mod`, deeper paths are public today too. Example: `nythos_core::auth::register::RegisterService`.
- `nythos_core::rbac`, `nythos_core::session`, and `nythos_core::error` are direct public modules without another re-export layer inside them.

## Crate-root Exports

Unless noted otherwise, each item below is available at `nythos_core::<Item>` and also through its area-specific module root.

### auth

| Item                       | Assessment                  | Notes                                                                                                                                                  |
| -------------------------- | --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `AccessToken`              | intentionally public        | Core signed-token value used by `TokenSigner`, auth flow outputs, and callers inspecting issued auth material.                                         |
| `Claims`                   | intentionally public        | Structured claim set used by signing and verification boundaries.                                                                                      |
| `LoginAuthMaterial`        | intentionally public        | Direct login-flow output returned to callers.                                                                                                          |
| `LoginInput`               | intentionally public        | Callers construct this to run login orchestration.                                                                                                     |
| `LoginService`             | intentionally public        | Main login orchestration entry point.                                                                                                                  |
| `PasswordHash`             | intentionally public        | Required by `PasswordHasher`, `UserRepository`, and credential-loading boundaries.                                                                     |
| `RefreshAuthMaterial`      | intentionally public        | Direct refresh-flow output returned to callers.                                                                                                        |
| `RefreshInput`             | intentionally public        | Callers construct this to run refresh orchestration.                                                                                                   |
| `RefreshService`           | intentionally public        | Main refresh orchestration entry point.                                                                                                                |
| `RegisterAuthMaterial`     | intentionally public        | Returned from `RegisterResult` when auto-sign-in is enabled.                                                                                           |
| `RegisterInput`            | intentionally public        | Callers construct this to run registration orchestration.                                                                                              |
| `RegisterResult`           | intentionally public        | Register-flow return type exposed directly to callers.                                                                                                 |
| `RegisterService`          | intentionally public        | Main registration orchestration entry point.                                                                                                           |
| `RevokeAllSessionsInput`   | intentionally public        | Callers construct this to revoke all sessions for a tenant-scoped user.                                                                                |
| `RevokeAllSessionsService` | intentionally public        | Main revoke-all orchestration entry point.                                                                                                             |
| `RevokeResult`             | likely intentionally public | Service return wrapper is part of the public flow API, even if its constructor may be broader than needed.                                             |
| `RevokeSessionInput`       | intentionally public        | Callers construct this to revoke one session.                                                                                                          |
| `RevokeSessionService`     | intentionally public        | Main revoke-one orchestration entry point.                                                                                                             |
| `TokenPurpose`             | likely intentionally public | Exposed through `Claims` and token verification, but currently has only one variant and lower direct usage pressure than the rest of the auth surface. |

### domain

| Item             | Assessment                  | Notes                                                                                                        |
| ---------------- | --------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `Email`          | intentionally public        | Core validated value object used by callers and port implementations.                                        |
| `Password`       | intentionally public        | Required by the public `PasswordHasher` boundary.                                                            |
| `RoleId`         | intentionally public        | Tenant-scoped RBAC identity used in public domain and port APIs.                                             |
| `SessionId`      | intentionally public        | Required by session, revocation, and port APIs.                                                              |
| `Tenant`         | likely intentionally public | Public identity model, though not currently used by the main auth service orchestration paths.               |
| `TenantId`       | intentionally public        | Required by domain models, services, and port traits.                                                        |
| `TenantSettings` | likely intentionally public | Public because `Tenant` exposes it directly, but it is lower-pressure than the auth/session/RBAC core types. |
| `User`           | intentionally public        | Central domain identity returned by flows and used by repositories.                                          |
| `UserId`         | intentionally public        | Required across domain models, services, and repositories.                                                   |
| `UserStatus`     | intentionally public        | Returned by `User` and used by `UserRepository::update_status`.                                              |

### error

| Item           | Assessment           | Notes                                                         |
| -------------- | -------------------- | ------------------------------------------------------------- |
| `AuthError`    | intentionally public | Shared failure type for the entire public API.                |
| `NythosResult` | intentionally public | Standard result alias used across the crate's public surface. |

### ports

| Item                   | Assessment           | Notes                                                                        |
| ---------------------- | -------------------- | ---------------------------------------------------------------------------- |
| `NewUser`              | intentionally public | Helper payload required by `UserRepository::create`.                         |
| `PasswordHasher`       | intentionally public | Adapter-facing trait implemented outside the crate.                          |
| `RefreshTokenRotation` | intentionally public | Helper payload required by `SessionStore::rotate_refresh_token`.             |
| `RevocationChecker`    | intentionally public | Adapter-facing trait used by refresh and request-time enforcement.           |
| `RoleAssignmentInput`  | intentionally public | Helper payload required by `RoleRepository` assignment methods.              |
| `RoleRepository`       | intentionally public | Adapter-facing trait implemented outside the crate.                          |
| `SessionRecord`        | intentionally public | Helper payload required by `SessionStore` session create and lookup methods. |
| `SessionStore`         | intentionally public | Adapter-facing trait implemented outside the crate.                          |
| `TokenSigner`          | intentionally public | Adapter-facing trait implemented outside the crate.                          |
| `UserCredentials`      | intentionally public | Helper payload required by `UserRepository::find_credentials_by_email`.      |
| `UserRepository`       | intentionally public | Adapter-facing trait implemented outside the crate.                          |

### RBAC

| Item             | Assessment                  | Notes                                                                                                                              |
| ---------------- | --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `Permission`     | intentionally public        | Core authorization value object used by roles and policy checks.                                                                   |
| `Role`           | intentionally public        | Tenant-scoped RBAC model returned by repositories and flows.                                                                       |
| `RoleAssignment` | likely intentionally public | Public domain relation type; current flow and port use is lighter than `Role`, but the type is coherent as part of the RBAC model. |
| `RoleRegistry`   | likely intentionally public | Public tenant-scoped role container, though not used by current service orchestration or port signatures.                          |

### session

| Item           | Assessment           | Notes                                                                   |
| -------------- | -------------------- | ----------------------------------------------------------------------- |
| `RefreshToken` | intentionally public | Opaque refresh credential used by services and the `SessionStore` port. |
| `Session`      | intentionally public | Core session model used by services and the `SessionStore` port.        |

## Module Exports

### `nythos_core::auth`

Module-root re-exports:

- `AccessToken`
- `Claims`
- `PasswordHash`
- `TokenPurpose`
- `LoginAuthMaterial`
- `LoginInput`
- `LoginService`
- `RefreshAuthMaterial`
- `RefreshInput`
- `RefreshService`
- `RegisterAuthMaterial`
- `RegisterInput`
- `RegisterResult`
- `RegisterService`
- `RevokeAllSessionsInput`
- `RevokeAllSessionsService`
- `RevokeResult`
- `RevokeSessionInput`
- `RevokeSessionService`

Public submodules:

- `login`
- `refresh`
- `register`
- `revoke`
- `tokens`

Assessment:

- The module-root re-export surface looks intentionally curated and useful.
- The deeper paths under `login`, `refresh`, `register`, and `revoke` look more like implementation file layout than a separately designed stable public namespace.

### `nythos_core::domain`

Module-root re-exports:

- typed IDs: `UserId`, `TenantId`, `SessionId`, `RoleId`
- value objects: `Email`, `Password`
- identity models: `User`, `UserStatus`, `Tenant`, `TenantSettings`

Public submodules:

- `identity`
- `ids`
- `value_objects`

Assessment:

- The submodules map to meaningful domain categories rather than flow implementation details.
- These public submodules are easier to justify as stable than the deeper `auth` flow submodules.

### `nythos_core::ports`

Module-root re-exports:

- traits: `UserRepository`, `RoleRepository`, `SessionStore`, `PasswordHasher`, `TokenSigner`, `RevocationChecker`
- helper payloads: `NewUser`, `UserCredentials`, `RoleAssignmentInput`, `SessionRecord`, `RefreshTokenRotation`

Public submodules:

- `user`
- `role`
- `session`
- `security`

Assessment:

- The module-root surface is clearly adapter-facing and intentional.
- The public submodules are category-oriented and likely fine to keep public, even if callers usually prefer the `ports::*` re-exports.

### `nythos_core::rbac`

Exports:

- `Permission`
- `Role`
- `RoleAssignment`
- `RoleRegistry`

Assessment:

- Single direct module with no extra internal path layering.
- Public surface looks like a straightforward RBAC domain API.

### `nythos_core::session`

Exports:

- `Session`
- `RefreshToken`

Assessment:

- Single direct module with no extra internal path layering.
- Public surface looks intentionally domain-facing and port-facing.

### `nythos_core::error`

Exports:

- `AuthError`
- `NythosResult`

Assessment:

- Single direct module with no extra internal path layering.
- Public surface is minimal and clearly intentional.

## Intended Public Categories

### Domain API

Types users of the crate need to construct, validate, inspect, and pass around.

Current examples:

- `Email`
- `Password`
- `UserId`
- `TenantId`
- `SessionId`
- `RoleId`
- `User`
- `UserStatus`
- `Tenant`
- `TenantSettings`
- `Permission`
- `Role`
- `RoleAssignment`
- `RoleRegistry`
- `Session`
- `RefreshToken`
- `AccessToken`
- `Claims`
- `PasswordHash`

### Adapter-facing API

Types and traits outer implementations need in order to implement storage, signing, hashing, revocation, and role or user or session lookup.

Current examples:

- `UserRepository`
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

### Flow or service API

Inputs, outputs, and services needed to run register, login, refresh, and revoke orchestration.

Current examples:

- `RegisterInput`
- `RegisterAuthMaterial`
- `RegisterResult`
- `RegisterService`
- `LoginInput`
- `LoginAuthMaterial`
- `LoginService`
- `RefreshInput`
- `RefreshAuthMaterial`
- `RefreshService`
- `RevokeSessionInput`
- `RevokeAllSessionsInput`
- `RevokeResult`
- `RevokeSessionService`
- `RevokeAllSessionsService`

### Possibly accidental or internal API

Public items that may be public today because the module structure exposes them, not because external users should depend on them long-term.

Current strongest candidates:

- deeper `auth` implementation-shaped module paths such as `nythos_core::auth::register::RegisterService`
- public constructors on service output wrappers such as `LoginAuthMaterial::new`, `RefreshAuthMaterial::new`, and `RegisterAuthMaterial::new`
- public constructors on result wrappers such as `RegisterResult::new` and `RevokeResult::new`
- lower-pressure exports that may deserve a later scope decision, such as `TokenPurpose` and `TenantSettings`

## Adapter-facing Types That Look Intentionally Public

These items are strongly justified by the current implemented port boundaries and should be treated as intentionally public.

| Item                   | Why it needs to be public today                                                                  |
| ---------------------- | ------------------------------------------------------------------------------------------------ |
| `UserRepository`       | Outer storage layer implements tenant-scoped user lookup and creation.                           |
| `RoleRepository`       | Outer storage layer implements tenant-scoped role lookup and mutation.                           |
| `SessionStore`         | Outer storage layer implements session creation, refresh-token lookup, rotation, and revocation. |
| `PasswordHasher`       | Outer security layer hashes and verifies `Password` values into `PasswordHash`.                  |
| `TokenSigner`          | Outer security layer signs and verifies `Claims` into `AccessToken`.                             |
| `RevocationChecker`    | Outer request-time or refresh-time enforcement checks session revocation status.                 |
| `NewUser`              | Required input to `UserRepository::create`.                                                      |
| `UserCredentials`      | Required output from `UserRepository::find_credentials_by_email`.                                |
| `RoleAssignmentInput`  | Required input to `RoleRepository::assign_role` and `RoleRepository::revoke_role`.               |
| `SessionRecord`        | Required input and output shape around `SessionStore` create and refresh-token lookup.           |
| `RefreshTokenRotation` | Required input to `SessionStore::rotate_refresh_token`.                                          |
| `User`                 | Repository output and flow output.                                                               |
| `UserId`               | Used by repositories, sessions, RBAC, and flows.                                                 |
| `TenantId`             | Used across repository and service boundaries.                                                   |
| `SessionId`            | Used by session and revocation boundaries.                                                       |
| `RoleId`               | Used by RBAC boundaries.                                                                         |
| `Email`                | Used by repository boundaries and user identity.                                                 |
| `Password`             | Used by `PasswordHasher`.                                                                        |
| `PasswordHash`         | Used by `PasswordHasher`, `UserRepository`, and `UserCredentials`.                               |
| `AccessToken`          | Used by `TokenSigner` and flow outputs.                                                          |
| `Claims`               | Used by `TokenSigner` and auth material outputs.                                                 |
| `RefreshToken`         | Used by `SessionStore`, refresh flows, and auth material outputs.                                |
| `Session`              | Used by `SessionStore` and auth material outputs.                                                |
| `Role`                 | Used by `RoleRepository` and auth material outputs.                                              |

## Possibly Accidental Exports And Recommendations

### 1. Public `auth` implementation submodules

Current public submodules:

- `nythos_core::auth::login`
- `nythos_core::auth::refresh`
- `nythos_core::auth::register`
- `nythos_core::auth::revoke`
- `nythos_core::auth::tokens`

Recommendation:

- Keep as-is for `v0.1`.
- Treat `nythos_core::auth::*` module-root re-exports as the primary supported `auth` surface.
- In a later explicit cleanup window, consider making the flow-oriented submodules private while preserving the `auth` module-root re-exports.

### 2. Public constructors on output-only wrappers

Current examples:

- `LoginAuthMaterial::new`
- `RefreshAuthMaterial::new`
- `RegisterAuthMaterial::new`
- `RegisterResult::new`
- `RevokeResult::new`

Recommendation:

- Keep as-is for `v0.1`.
- In a later explicit cleanup window, consider narrowing constructors for output-only types if callers are expected to receive these mostly from services rather than construct them directly.

### 3. `Claims::new` plus `TokenPurpose`

Current situation:

- `Claims::access` already covers the common auth-flow issuance path.
- `TokenSigner::verify` returns `Claims`, so external callers and adapter implementations still need to inspect the claim shape.
- `TokenPurpose` currently has only one variant, `Access`.

Recommendation:

- Keep both public for `v0.1`.
- Later decide whether `Claims::new` should remain a general public constructor or whether `Claims::access` is the intended stable constructor for most callers.
- Later document whether `TokenPurpose` is expected to grow or should stay minimal.

### 4. `TenantSettings`

Current situation:

- `TenantSettings` is public because `Tenant::with_settings` and `Tenant::settings` expose it directly.
- It is not used by the current auth flow services or port traits.

Recommendation:

- Keep as-is for `v0.1`.
- Revisit only if the crate later narrows tenant metadata scope or moves plain tenant settings out of the core domain model.

### 5. Stable path ambiguity

Current situation:

- Many items are reachable through three layers today: crate root, module root, and deeper public submodule path.
- Example: `RegisterService` is currently reachable as `nythos_core::RegisterService`, `nythos_core::auth::RegisterService`, and `nythos_core::auth::register::RegisterService`.

Recommendation:

- For future docs, treat crate-root re-exports as the main ergonomic API.
- Treat `auth`, `domain`, and `ports` module-root re-exports as supported grouped access paths.
- Avoid promising that deeper implementation-shaped submodule paths are stable until an explicit API cleanup and documentation pass says so.

## Recommendations for future API cleanup

- Keep the current crate-root re-exports as the main ergonomic API for `v0.1`.
- Keep `nythos_core::auth::*`, `nythos_core::domain::*`, and `nythos_core::ports::*` module-root re-exports as the grouped public surface.
- Consider making `auth` implementation submodules private later while preserving module-root re-exports.
- Consider documenting stable paths explicitly: crate root and module-root re-exports first, deeper implementation submodule paths unspecified unless later committed.
- Consider narrowing public constructors for output-only wrappers and result wrappers in a later explicit cleanup window.
- Keep `TokenPurpose` public for `v0.1`, then revisit only if token-purpose expansion or claim-construction rules become a real API pressure point.
- Keep `TenantSettings` public for `v0.1`, then revisit only if tenant metadata scope is intentionally reduced.
- Do not add `#[doc(hidden)]` in this issue; only consider it in a later explicit compatibility cleanup if a public item must remain exported but should be deemphasized.
- Do not add a prelude for `v0.1`; only consider one later if real usage pressure shows repeated import friction.

## Conclusion

The current public surface is already close to publishable for `v0.1`.

The public crate-root items mostly look intentional and aligned with the implemented domain, adapter, and orchestration boundaries. The main future cleanup work is not removing major types, but tightening path stability and deciding whether a few constructors and implementation-shaped submodule paths should remain part of the long-term supported API.
