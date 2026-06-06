use crate::{NythosResult, TenantAuthPolicy, TenantId};

/// Tenant auth policy loading port.
///
/// Implementations live outside `nythos-core`. This port returns the typed
/// auth policy used by core services to decide whether optional profile fields
/// and username login are enabled for a tenant.
pub trait TenantPolicyPort {
    async fn load_auth_policy(&self, tenant_id: TenantId) -> NythosResult<TenantAuthPolicy>;
}
