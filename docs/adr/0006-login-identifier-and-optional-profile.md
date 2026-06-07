# ADR 0006: Login Identifier And Optional Profile

## Status

Accepted.

## Context

Email remains the required credential identity for email/password accounts in
`nythos-core`. The core also needs to support optional user profile fields and
username-based login without turning tenant metadata into auth policy.

Username and display name are profile fields, not replacements for email.
Username can also be used as a login identifier when a tenant explicitly enables
username login. Display name is human-readable profile metadata only and is not
used for credential lookup.

The core must remain infrastructure-free. It should express policy and lookup
boundaries without adding HTTP, storage, gateway, OAuth provider, or concrete
adapter behavior.

## Decision

Add typed identity profile and login identifier concepts for `v0.2.0`.

- email remains required for email/password accounts
- username and display name are optional user profile fields
- optional profile fields are gated by typed tenant auth policy
- username registration and username login are separate tenant policy flags
- display-name registration is tenant-policy-gated in `v0.2.0`
- username login is disabled by default
- login input moves toward `LoginIdentifier`
- `LoginInput::new(..., email: String, ...)` is preserved as a compatibility constructor
- `LoginInput::new_with_identifier(...)` is added for email or username login input
- core services load tenant auth policy through `TenantPolicyPort`
- repositories do not enforce tenant auth policy
- services branch on `LoginIdentifier` and call explicit repository methods
- `find_credentials_by_identifier` is intentionally not added
- OAuth is deferred to `v0.2.1+`

## Consequences

- tenant auth policy is represented by `TenantAuthPolicy`, not by string flags in `TenantSettings`
- register and login services must load policy before profile-field or username-login decisions
- repositories stay focused on explicit tenant-scoped lookup keys such as email or username
- username login being disabled, a missing username, and a wrong password can all return `InvalidCredentials`
- adapters implementing `UserRepository` must provide the explicit username lookup methods
- callers can keep existing email-shaped login construction while new callers can pass a raw identifier
