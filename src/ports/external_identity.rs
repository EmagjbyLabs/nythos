use core::option::Option;
use std::time::SystemTime;

use crate::{ExternalIdentity, NythosResult, OAuthProviderKind, TenantId, UserId};

/// External identity repository contract used by OAuth login and linking flows.
///
/// Every method is explicitly tenant-scoped. Implementations must treat
/// `(tenant_id, provider_kind, provider_subject)` as the natural unique key for
/// provider identities and must not perform cross-tenant identity resolution.
pub trait ExternalIdentityRepository {
    /// Finds an external identity by its tenant-scoped provider natural key.
    async fn find_by_provider(
        &self,
        tenant_id: TenantId,
        provider_kind: OAuthProviderKind,
        provider_subject: &str,
    ) -> NythosResult<Option<ExternalIdentity>>;

    /// Finds all external identities linked to a user within one tenant.
    async fn find_by_user(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> NythosResult<Vec<ExternalIdentity>>;

    /// Links a provider identity to a user.
    ///
    /// Implementations must reject duplicate
    /// `(tenant_id, provider_kind, provider_subject)` links.
    async fn link(&self, identity: ExternalIdentity) -> NythosResult<()>;

    /// Updates the last-seen timestamp for an existing provider identity.
    async fn touch(
        &self,
        tenant_id: TenantId,
        provider_kind: OAuthProviderKind,
        provider_subject: &str,
        seen_at: SystemTime,
    ) -> NythosResult<()>;
}
