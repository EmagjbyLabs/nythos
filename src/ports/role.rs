use crate::{NythosResult, Role, RoleAssignment, RoleId, TenantId, UserId};

/// Tenant-scoped role assignment command.
///
/// This keeps assignment/revocation inputs explicit and avoids ambiguous
/// multi-argument method signatures in orchestration code. It is a domain-facing
/// boundary payload, not a storage row or transport DTO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleAssignmentInput {
    tenant_id: TenantId,
    user_id: UserId,
    role_id: RoleId,
}

impl RoleAssignmentInput {
    pub const fn new(tenant_id: TenantId, user_id: UserId, role_id: RoleId) -> Self {
        Self {
            tenant_id,
            user_id,
            role_id,
        }
    }

    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    pub const fn user_id(&self) -> UserId {
        self.user_id
    }

    pub const fn role_id(&self) -> RoleId {
        self.role_id
    }

    pub const fn into_assignment(self) -> RoleAssignment {
        RoleAssignment::new(self.tenant_id, self.user_id, self.role_id)
    }
}

/// Tenant-scoped role repository contract used by login and refresh flows.
///
/// Every method is explicitly tenant-bound. Implementations must not introduce
/// global-role behavior or silently cross tenant boundaries.
///
/// This contract supports loading current RBAC state as well as assigning and
/// revoking user-role membership inside a tenant.
pub trait RoleRepository {
    /// Assigns a role to a user within the provided tenant boundary.
    fn assign_role(&self, input: RoleAssignmentInput) -> NythosResult<()>;

    /// Revokes a role from a user within the provided tenant boundary.
    fn revoke_role(&self, input: RoleAssignmentInput) -> NythosResult<()>;

    /// Loads all roles currently assigned to a user within one tenant.
    fn get_roles_for_user(&self, tenant_id: TenantId, user_id: UserId) -> NythosResult<Vec<Role>>;
}
