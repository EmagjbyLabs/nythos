# ADR 0007: Keep OAuth Provider Mechanics Outside nythos-core

## Status

Accepted.

## Context

`nythos-core` now models OAuth provider kinds, external identities, tenant OAuth
provider config, verified external profiles, and login/linking outcomes.

OAuth mechanics require infrastructure concerns such as redirects, OAuth state
and CSRF, PKCE, HTTP, authorization-code exchange, provider token exchange,
ID-token validation, JWKS fetching, provider userinfo fetching, provider SDKs,
secrets, cookies, client IDs, and framework/runtime integration.

Those mechanics do not belong in the core crate. The core boundary needs to stay
domain-oriented, runtime-agnostic, and usable without HTTP, storage drivers,
provider SDKs, or concrete OAuth clients.

## Decision

Keep OAuth mechanics in `nythos-gateway` and provider adapters.

- `nythos-core` receives `VerifiedExternalProfile` after gateway/provider verification
- `nythos-core` trusts `VerifiedExternalProfile` as the provider-data trust boundary
- `nythos-core` returns explicit `OAuthLoginOutcome` values
- `nythos-core v0.2.1` does not create users during OAuth login
- `nythos-core v0.2.1` does not issue sessions during OAuth login
- `TenantOAuthProviderConfig` remains secrets-free
- `TenantOAuthProviderConfig` contains only enabled/disabled and registration allowed/disallowed decisions
- `TenantOAuthProviderConfigPort` remains separate from `TenantPolicyPort`

## Consequences

- core stays infrastructure-free and runtime-agnostic
- gateway/adapters own provider-specific behavior
- gateway/adapters own OAuth redirects, state/CSRF, PKCE, provider token exchange, provider validation, JWKS, userinfo, cookies, secrets, client IDs, and HTTP routes
- OAuth session issuance can be added later without polluting core with provider mechanics
- OAuth registration completion can be added later without making provider mechanics part of core
- implementers must treat `VerifiedExternalProfile` as a trust boundary
- storage adapters must enforce tenant/provider/subject uniqueness for external identities
