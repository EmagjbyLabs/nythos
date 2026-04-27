mod support;

use nythos_core::{RoleAssignmentInput, RoleRepository, TenantId, UserId};
use support::{InMemoryRoleRepository, fixtures};

#[test]
fn contract_supports_fresh_tenant_role_loading() {
    let repo = InMemoryRoleRepository::new();
    let tenant_id = TenantId::generate();
    let user_id = UserId::generate();

    let role = fixtures::operator_role(tenant_id);

    repo.insert_role(role.clone());
    repo.assign_role(RoleAssignmentInput::new(tenant_id, user_id, role.id()))
        .unwrap();

    let roles = repo.get_roles_for_user(tenant_id, user_id).unwrap();

    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].name(), "operator");
}

#[test]
fn tenant_scope_is_explicit_across_assignment_and_loading() {
    let repo = InMemoryRoleRepository::new();
    let tenant_a = TenantId::generate();
    let tenant_b = TenantId::generate();
    let user_id = UserId::generate();

    let role = fixtures::operator_role(tenant_a);

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
