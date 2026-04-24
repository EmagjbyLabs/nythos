use nythos_core::{
    Permission, Role, RoleAssignment, RoleAssignmentInput, RoleId, RoleRepository, TenantId, UserId,
};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

type AssignmentStore = BTreeMap<(TenantId, UserId), Vec<RoleAssignment>>;
type RoleStore = BTreeMap<(TenantId, RoleId), Role>;

#[derive(Clone)]
struct TestRoleRepository {
    assignments: Rc<RefCell<AssignmentStore>>,
    roles: Rc<RefCell<RoleStore>>,
}

impl TestRoleRepository {
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

impl RoleRepository for TestRoleRepository {
    fn assign_role(&self, input: RoleAssignmentInput) -> nythos_core::NythosResult<()> {
        if !self
            .roles
            .borrow()
            .contains_key(&(input.tenant_id(), input.role_id()))
        {
            return Err(nythos_core::AuthError::ValidationError(
                "role does not exist in tenant".to_owned(),
            ));
        }

        self.assignments
            .borrow_mut()
            .entry((input.tenant_id(), input.user_id()))
            .or_default()
            .push(input.into_assignment());

        Ok(())
    }

    fn revoke_role(&self, input: RoleAssignmentInput) -> nythos_core::NythosResult<()> {
        let mut assignments = self.assignments.borrow_mut();
        let entries = assignments
            .get_mut(&(input.tenant_id(), input.user_id()))
            .ok_or(nythos_core::AuthError::UserNotFound)?;

        entries.retain(|assignment| assignment.role_id() != input.role_id());
        Ok(())
    }

    fn get_roles_for_user(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> nythos_core::NythosResult<Vec<Role>> {
        let assignments = self.assignments.borrow();
        let roles = self.roles.borrow();

        Ok(assignments
            .get(&(tenant_id, user_id))
            .into_iter()
            .flat_map(|items| items.iter())
            .filter_map(|assignment| roles.get(&(tenant_id, assignment.role_id())).cloned())
            .collect())
    }
}

#[test]
fn contract_supports_fresh_tenant_role_loading() {
    let repo = TestRoleRepository::new();
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
    assert_eq!(roles[0].name(), "operator");
}

#[test]
fn tenant_scope_is_explicit_across_assignment_and_loading() {
    let repo = TestRoleRepository::new();
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
    repo.assign_role(RoleAssignmentInput::new(tenant_a, user_id, role.id()))
        .unwrap();

    assert_eq!(repo.get_roles_for_user(tenant_a, user_id).unwrap().len(), 1);
    assert!(
        repo.get_roles_for_user(tenant_b, user_id)
            .unwrap()
            .is_empty()
    );
}
