//! Tenant-scoped RBAC concepts.
//!
//! This module contains role, permission, and assignment models used for
//! Tenant-scoped authorization.

use std::collections::BTreeSet;

use crate::{AuthError, NythosResult, RoleId, TenantId, UserId};

/// Concrete authorization capability within a tenant scope.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct Permission(String);

impl Permission {
    pub fn new(value: impl AsRef<str>) -> NythosResult<Self> {
        let value = value.as_ref().trim();

        if value.is_empty() {
            return Err(AuthError::ValidationError(
                "permission cannot be empty".to_owned(),
            ));
        }

        if value.starts_with('.') || value.ends_with('.') || !value.contains('.') {
            return Err(AuthError::ValidationError(
                "permission must contain a namespace separator '.'".to_owned(),
            ));
        }

        if !value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_')
        {
            return Err(AuthError::ValidationError(
                "permission must contain only lowercase ASCII letters, digits, '_' or '.'"
                    .to_owned(),
            ));
        }

        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for Permission {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Tenant-scoped role with an explicit permission set.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Role {
    id: RoleId,
    tenant_id: TenantId,
    name: String,
    permissions: BTreeSet<Permission>,
}

impl Role {
    const MAX_NAME_LEN: usize = 64;

    pub fn new(
        id: RoleId,
        tenant_id: TenantId,
        name: impl AsRef<str>,
        permissions: impl IntoIterator<Item = Permission>,
    ) -> NythosResult<Self> {
        let name = Self::validate_name(name.as_ref())?;
        let permissions = permissions.into_iter().collect();

        Ok(Self {
            id,
            tenant_id,
            name,
            permissions,
        })
    }

    pub const fn id(&self) -> RoleId {
        self.id
    }

    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn permissions(&self) -> &BTreeSet<Permission> {
        &self.permissions
    }

    pub fn has_permission(&self, permission: &Permission) -> bool {
        self.permissions.contains(permission)
    }

    pub fn add_permission(&mut self, permission: Permission) {
        self.permissions.insert(permission);
    }

    pub fn remove_permission(&mut self, permission: &Permission) {
        self.permissions.remove(permission);
    }

    fn validate_name(input: &str) -> NythosResult<String> {
        let name = input.trim();

        if name.is_empty() {
            return Err(AuthError::ValidationError(
                "role name cannot be empty".to_owned(),
            ));
        }

        if name.len() > Self::MAX_NAME_LEN {
            return Err(AuthError::ValidationError(format!(
                "role name must be at most {} characters",
                Self::MAX_NAME_LEN
            )));
        }

        if !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        {
            return Err(AuthError::ValidationError(
                "role name must contain only lowercase ASCII letters, digits, '_' or '-'"
                    .to_owned(),
            ));
        }

        Ok(name.to_owned())
    }
}

/// User-to-role relation inside one tenant boundary.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RoleAssignment {
    tenant_id: TenantId,
    user_id: UserId,
    role_id: RoleId,
}

impl RoleAssignment {
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

    pub fn matches_tenant(&self, tenant_id: TenantId) -> bool {
        self.tenant_id == tenant_id
    }
}
/// Tenant-scoped role registry used to load current RBAC state.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RoleRegistry {
    tenant_id: TenantId,
    roles: Vec<Role>,
}

impl RoleRegistry {
    pub fn new(tenant_id: TenantId, roles: Vec<Role>) -> NythosResult<Self> {
        if roles.iter().any(|role| role.tenant_id() != tenant_id) {
            return Err(AuthError::ValidationError(
                "all roles in registry must belong to the same tenant".to_owned(),
            ));
        }

        Ok(Self { tenant_id, roles })
    }

    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    pub fn roles(&self) -> &[Role] {
        &self.roles
    }

    pub fn find_role(&self, role_id: RoleId) -> Option<&Role> {
        self.roles.iter().find(|role| role.id() == role_id)
    }
}

#[cfg(test)]
mod tests {
    use super::{Permission, Role, RoleAssignment, RoleRegistry};
    use crate::{AuthError, RoleId, TenantId, UserId};

    #[test]
    fn permission_accepts_namespaced_values() {
        let perm = Permission::new("shipments.read").unwrap();

        assert_eq!(perm.as_str(), "shipments.read")
    }

    #[test]
    fn permission_rejects_invalid_shapes() {
        assert!(matches!(
            Permission::new(""),
            Err(AuthError::ValidationError(_))
        ));
        assert!(matches!(
            Permission::new("shipments"),
            Err(AuthError::ValidationError(_))
        ));
        assert!(matches!(
            Permission::new(".read"),
            Err(AuthError::ValidationError(_))
        ));
        assert!(matches!(
            Permission::new("read."),
            Err(AuthError::ValidationError(_))
        ));
        assert!(matches!(
            Permission::new("Shipments.Read"),
            Err(AuthError::ValidationError(_))
        ));
    }

    #[test]
    fn role_is_tenant_scoped_and_holds_permissions() {
        let tenant_id = TenantId::generate();
        let read = Permission::new("shipments.read").unwrap();
        let write = Permission::new("shipments.write").unwrap();

        let role = Role::new(
            RoleId::generate(),
            tenant_id,
            "shipment_manager",
            vec![read.clone(), write.clone()],
        )
        .unwrap();

        assert_eq!(role.tenant_id(), tenant_id);
        assert!(role.has_permission(&read));
        assert!(role.has_permission(&write));
    }

    #[test]
    fn role_name_rejects_invalid_shapes() {
        let tenant_id = TenantId::generate();

        assert!(matches!(
            Role::new(RoleId::generate(), tenant_id, "", vec![]),
            Err(AuthError::ValidationError(_))
        ));
        assert!(matches!(
            Role::new(
                RoleId::generate(),
                tenant_id,
                "ThisIsAVeryLongRoleNameThatExceedsTheMaximumAllowedLength",
                vec![]
            ),
            Err(AuthError::ValidationError(_))
        ));
        assert!(matches!(
            Role::new(RoleId::generate(), tenant_id, "Global Admin", vec![]),
            Err(AuthError::ValidationError(_))
        ));
    }

    #[test]
    fn role_assignment_is_explicitly_tenant_scoped() {
        let tenant_id = TenantId::generate();
        let assignment = RoleAssignment::new(tenant_id, UserId::generate(), RoleId::generate());

        assert!(assignment.matches_tenant(tenant_id));
        assert!(!assignment.matches_tenant(TenantId::generate()));
    }

    #[test]
    fn role_registry_rejects_cross_tenant_roles() {
        let tenant_a = TenantId::generate();
        let tenant_b = TenantId::generate();

        let role_a = Role::new(
            RoleId::generate(),
            tenant_a,
            "operator",
            [Permission::new("shipments.read").unwrap()],
        )
        .unwrap();

        let role_b = Role::new(
            RoleId::generate(),
            tenant_b,
            "operator",
            [Permission::new("shipments.read").unwrap()],
        )
        .unwrap();

        let result = RoleRegistry::new(tenant_a, vec![role_a.clone(), role_b.clone()]);

        assert!(matches!(result, Err(AuthError::ValidationError(_))));
    }
}
