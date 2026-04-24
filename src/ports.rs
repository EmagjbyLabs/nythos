//! Pure trait contracts required by `nythos-core`.
//!
//! Implementations of these ports live outside the core crate.

use crate::{
    Email, NythosResult, PasswordHash, Role, RoleAssignment, RoleId, TenantId, User, UserId,
    UserStatus,
};

/// Domain-facing input used when creating a new user inside a tenant.
///
/// This keeps repository contracts focused on core data rather than storage
/// payloads or transport DTOs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewUser {
    email: Email,
}

impl NewUser {
    pub fn new(email: Email) -> Self {
        Self { email }
    }

    pub fn email(&self) -> &Email {
        &self.email
    }

    pub fn into_email(self) -> Email {
        self.email
    }
}

/// Tenant-scoped role assignment command.
///
/// This keeps assignment/revocation inputs explicit and avoids ambiguous
/// multi-argument method signatures in orchestration code.
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

/// Tenant-scoped user repository contract used by registration and login flows.
///
/// All lookup and mutation methods that depend on tenant context require an
/// explicit `TenantId`. Implementations must not perform cross-tenant lookups
/// behind the scenes.
///
/// Duplicate-user and not-found behavior should be expressed through the core
/// result model and return shapes, rather than leaking database-specific errors.
pub trait UserRepository {
    /// Finds a user by normalized email within a specific tenant.
    fn find_by_email(&self, tenant_id: TenantId, email: &Email) -> NythosResult<Option<User>>;

    /// Finds a user by ID within a specific tenant.
    fn find_by_id(&self, tenant_id: TenantId, user_id: UserId) -> NythosResult<Option<User>>;

    /// Creates a new user in the given tenant using an already-validated email
    /// and an already-produced password hash.
    ///
    /// Implementations should make duplicate handling explicit through the core
    /// error model.
    fn create(
        &self,
        tenant_id: TenantId,
        new_user: NewUser,
        password_hash: PasswordHash,
    ) -> NythosResult<User>;

    /// Updates a user's status within a specific tenant boundary.
    fn update_status(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        status: UserStatus,
    ) -> NythosResult<()>;
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

#[cfg(test)]
mod tests {
    use super::{NewUser, UserRepository};
    use crate::{
        AuthError, Email, PasswordHash, Permission, Role, RoleAssignment, RoleId, TenantId, User,
        UserId, UserStatus,
        ports::{RoleAssignmentInput, RoleRepository},
    };
    use std::{cell::RefCell, collections::BTreeMap, rc::Rc, time::SystemTime};

    type TestStore = BTreeMap<(TenantId, UserId), (User, PasswordHash)>;

    #[derive(Clone)]
    struct InMemoryUserRepository {
        users: Rc<RefCell<TestStore>>,
    }

    impl InMemoryUserRepository {
        fn new() -> Self {
            Self {
                users: Rc::new(RefCell::new(BTreeMap::new())),
            }
        }
    }

    impl UserRepository for InMemoryUserRepository {
        fn find_by_email(
            &self,
            tenant_id: TenantId,
            email: &Email,
        ) -> crate::NythosResult<Option<User>> {
            Ok(self
                .users
                .borrow()
                .iter()
                .find(|((stored_tenant, _), (user, _))| {
                    *stored_tenant == tenant_id && user.email() == email
                })
                .map(|(_, (user, _))| user.clone()))
        }

        fn find_by_id(
            &self,
            tenant_id: TenantId,
            user_id: UserId,
        ) -> crate::NythosResult<Option<User>> {
            Ok(self
                .users
                .borrow()
                .get(&(tenant_id, user_id))
                .map(|(user, _)| user.clone()))
        }

        fn create(
            &self,
            tenant_id: TenantId,
            new_user: NewUser,
            password_hash: PasswordHash,
        ) -> crate::NythosResult<User> {
            if self.find_by_email(tenant_id, new_user.email())?.is_some() {
                return Err(AuthError::ValidationError(
                    "user with email already exists in tenant".to_owned(),
                ));
            }

            let user = User::new(
                UserId::generate(),
                new_user.into_email(),
                SystemTime::UNIX_EPOCH,
            );

            self.users
                .borrow_mut()
                .insert((tenant_id, user.id()), (user.clone(), password_hash));

            Ok(user)
        }

        fn update_status(
            &self,
            tenant_id: TenantId,
            user_id: UserId,
            status: UserStatus,
        ) -> crate::NythosResult<()> {
            let mut users = self.users.borrow_mut();
            let (user, _) = users
                .get_mut(&(tenant_id, user_id))
                .ok_or(AuthError::UserNotFound)?;

            user.set_status(status);
            Ok(())
        }
    }

    #[test]
    fn new_user_wraps_domain_email() {
        let email = Email::parse("person@example.com").unwrap();
        let new_user = NewUser::new(email.clone());

        assert_eq!(new_user.email(), &email);
    }

    #[test]
    fn repository_lookups_are_tenant_scoped() {
        let repo = InMemoryUserRepository::new();
        let tenant_a = TenantId::generate();
        let tenant_b = TenantId::generate();
        let email = Email::parse("person@example.com").unwrap();

        let created = repo
            .create(
                tenant_a,
                NewUser::new(email.clone()),
                PasswordHash::new("hash".to_owned()).unwrap(),
            )
            .unwrap();

        assert!(repo.find_by_email(tenant_a, &email).unwrap().is_some());
        assert!(repo.find_by_email(tenant_b, &email).unwrap().is_none());
        assert!(repo.find_by_id(tenant_a, created.id()).unwrap().is_some());
    }

    #[test]
    fn duplicate_user_handling_is_expressible_through_core_errors() {
        let repo = InMemoryUserRepository::new();
        let tenant_id = TenantId::generate();
        let email = Email::parse("person@example.com").unwrap();

        repo.create(
            tenant_id,
            NewUser::new(email.clone()),
            PasswordHash::new("hash".to_owned()).unwrap(),
        )
        .unwrap();

        let result = repo.create(
            tenant_id,
            NewUser::new(email.clone()),
            PasswordHash::new("hash".to_owned()).unwrap(),
        );

        assert!(matches!(
            result,
            Err(AuthError::ValidationError(msg)) if msg.contains("already exists")
        ));
    }

    #[test]
    fn update_status_is_tenant_scoped_and_not_found_aware() {
        let repo = InMemoryUserRepository::new();
        let tenant_id = TenantId::generate();
        let other_tenant = TenantId::generate();

        let email = Email::parse("person@example.com").unwrap();
        let user = repo
            .create(
                tenant_id,
                NewUser::new(email.clone()),
                PasswordHash::new("hash".to_owned()).unwrap(),
            )
            .unwrap();

        repo.update_status(tenant_id, user.id(), UserStatus::Locked)
            .unwrap();

        let updated = repo.find_by_id(tenant_id, user.id()).unwrap().unwrap();
        assert_eq!(updated.status(), UserStatus::Locked);

        let result = repo.update_status(other_tenant, user.id(), UserStatus::Disabled);
        assert!(matches!(result, Err(AuthError::UserNotFound)));
    }

    // ROLES

    type TestRoleAssignments = BTreeMap<(TenantId, UserId), Vec<RoleAssignment>>;
    type TestRoles = BTreeMap<(TenantId, RoleId), Role>;

    #[derive(Clone)]
    struct InMemoryRoleRepository {
        assignments: Rc<RefCell<TestRoleAssignments>>,
        roles: Rc<RefCell<TestRoles>>,
    }

    impl InMemoryRoleRepository {
        fn new() -> Self {
            Self {
                assignments: Rc::new(RefCell::new(BTreeMap::new())),
                roles: Rc::new(RefCell::new(BTreeMap::new())),
            }
        }

        fn insert_role(&self, role: Role) {
            self.roles
                .borrow_mut()
                .insert((role.tenant_id(), role.id()), role);
        }
    }

    impl RoleRepository for InMemoryRoleRepository {
        fn assign_role(&self, input: RoleAssignmentInput) -> crate::NythosResult<()> {
            if !self
                .roles
                .borrow()
                .contains_key(&(input.tenant_id(), input.role_id()))
            {
                return Err(AuthError::ValidationError(
                    "role does not exist in tenant".to_owned(),
                ));
            }

            let mut assignments = self.assignments.borrow_mut();
            let entry = assignments
                .entry((input.tenant_id(), input.user_id()))
                .or_default();

            if entry.iter().any(|a| a.role_id() == input.role_id()) {
                return Err(AuthError::ValidationError(
                    "role already assigned to user in tenant".to_owned(),
                ));
            }

            entry.push(input.into_assignment());
            Ok(())
        }

        fn revoke_role(&self, input: RoleAssignmentInput) -> crate::NythosResult<()> {
            let mut assignments = self.assignments.borrow_mut();
            let entry = assignments
                .get_mut(&(input.tenant_id(), input.user_id()))
                .ok_or(AuthError::UserNotFound)?;

            let before = entry.len();
            entry.retain(|assignment| assignment.role_id() != input.role_id());

            if entry.len() == before {
                return Err(AuthError::ValidationError(
                    "role assignment not found in tenant".to_owned(),
                ));
            }

            Ok(())
        }

        fn get_roles_for_user(
            &self,
            tenant_id: TenantId,
            user_id: UserId,
        ) -> crate::NythosResult<Vec<Role>> {
            let assignments = self.assignments.borrow();
            let roles = self.roles.borrow();

            let result = assignments
                .get(&(tenant_id, user_id))
                .into_iter()
                .flat_map(|items| items.iter())
                .filter_map(|assignment| roles.get(&(tenant_id, assignment.role_id())).cloned())
                .collect();

            Ok(result)
        }
    }

    #[test]
    fn role_assignment_input_keeps_tenant_scope_explicit() {
        let input =
            RoleAssignmentInput::new(TenantId::generate(), UserId::generate(), RoleId::generate());

        let assignment = input.into_assignment();

        assert_eq!(assignment.tenant_id(), input.tenant_id());
        assert_eq!(assignment.user_id(), input.user_id());
        assert_eq!(assignment.role_id(), input.role_id());
    }

    #[test]
    fn role_repository_loads_roles_within_tenant_scope() {
        let repo = InMemoryRoleRepository::new();
        let tenant_id = TenantId::generate();
        let user_id = UserId::generate();

        let role = Role::new(
            RoleId::generate(),
            tenant_id,
            "operator",
            [Permission::new("shipments.read").unwrap()],
        )
        .unwrap();

        repo.insert_role(role.clone());
        repo.assign_role(RoleAssignmentInput::new(tenant_id, user_id, role.id()))
            .unwrap();

        let roles = repo.get_roles_for_user(tenant_id, user_id).unwrap();

        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].id(), role.id());
    }

    #[test]
    fn role_repository_rejects_cross_tenant_assignment() {
        let repo = InMemoryRoleRepository::new();
        let tenant_a = TenantId::generate();
        let tenant_b = TenantId::generate();
        let user_id = UserId::generate();

        let role = Role::new(
            RoleId::generate(),
            tenant_a,
            "operator",
            [Permission::new("shipments.read").unwrap()],
        )
        .unwrap();

        repo.insert_role(role.clone());

        let result = repo.assign_role(RoleAssignmentInput::new(tenant_b, user_id, role.id()));

        assert!(matches!(result, Err(AuthError::ValidationError(_))));
    }

    #[test]
    fn role_repository_revocation_is_testable_at_trait_boundary() {
        let repo = InMemoryRoleRepository::new();
        let tenant_id = TenantId::generate();
        let user_id = UserId::generate();

        let role = Role::new(
            RoleId::generate(),
            tenant_id,
            "operator",
            [Permission::new("shipments.read").unwrap()],
        )
        .unwrap();

        repo.insert_role(role.clone());

        let input = RoleAssignmentInput::new(tenant_id, user_id, role.id());
        repo.assign_role(input).unwrap();
        repo.revoke_role(input).unwrap();

        let roles = repo.get_roles_for_user(tenant_id, user_id).unwrap();
        assert!(roles.is_empty());
    }
}
