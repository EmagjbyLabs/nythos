use crate::{NythosResult, OAuthProviderKind, TenantId, TenantOAuthProviderConfig};

/// Tenant OAuth provider configuration loading port.
///
/// This port is intentionally separate from `TenantPolicyPort`.
/// Email/password auth policy and OAuth provider enablement are different
/// configuration surfaces.
///
/// Implementations live outside `nythos-core` and must not leak provider
/// secrets, client IDs, redirect URIs, endpoints, JWKS URLs, or HTTP concerns
/// through this contract.
pub trait TenantOAuthProviderConfigPort {
    /// Loads the OAuth provider configuration for one tenant/provider pair.
    ///
    /// `None` means no provider configuration exists and callers should treat
    /// the provider as disabled for that tenant.
    async fn load_provider_config(
        &self,
        tenant_id: TenantId,
        provider_kind: OAuthProviderKind,
    ) -> NythosResult<Option<TenantOAuthProviderConfig>>;
}
