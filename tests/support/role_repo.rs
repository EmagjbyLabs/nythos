use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

use nythos_core::{
    AuthError, NythosResult, Role, RoleAssignment, RoleAssignmentInput, RoleId, RoleRepository,
    TenantId, UserId,
};

type AssignmentStore = BTreeMap<(TenantId, UserId), Vec<RoleAssignment>>;
type RoleStore = BTreeMap<(TenantId, RoleId), Role>;

#[derive(Clone)]
pub struct InMemoryRoleRepository {
    assignments: Rc<RefCell<AssignmentStore>>,
    roles: Rc<RefCell<RoleStore>>,
}

impl InMemoryRoleRepository {
    pub fn new() -> Self {
        Self {
            assignments: Rc::new(RefCell::new(BTreeMap::new())),
            roles: Rc::new(RefCell::new(BTreeMap::new())),
        }
    }

    pub fn insert_role(&self, role: Role) {
        self.roles
            .borrow_mut()
            .insert((role.tenant_id(), role.id()), role);
    }
}

impl Default for InMemoryRoleRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl RoleRepository for InMemoryRoleRepository {
    fn assign_role(&self, input: RoleAssignmentInput) -> NythosResult<()> {
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

    fn revoke_role(&self, input: RoleAssignmentInput) -> NythosResult<()> {
        let mut assignments = self.assignments.borrow_mut();
        let entry = assignments
            .get_mut(&(input.tenant_id(), input.user_id()))
            .ok_or(AuthError::UserNotFound)?;

        let before = entry.len();
        entry.retain(|a| a.role_id() != input.role_id());

        if entry.len() == before {
            return Err(AuthError::ValidationError(
                "role assignment not found in tenant".to_owned(),
            ));
        }

        Ok(())
    }

    fn get_roles_for_user(&self, tenant_id: TenantId, user_id: UserId) -> NythosResult<Vec<Role>> {
        let assignments = self.assignments.borrow();
        let roles = self.roles.borrow();

        Ok(assignments
            .get(&(tenant_id, user_id))
            .into_iter()
            .flat_map(|i| i.iter())
            .filter_map(|a| roles.get(&(tenant_id, a.role_id())).cloned())
            .collect())
    }
}
