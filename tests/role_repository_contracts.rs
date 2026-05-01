mod support;

use futures::executor::block_on;
use nythos_core::{RoleAssignmentInput, RoleId, RoleRepository, TenantId, UserId};
use support::{InMemoryRoleRepository, fixtures};

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
fn contract_supports_fresh_tenant_role_loading() {
    block_on(async {
        let repo = InMemoryRoleRepository::new();
        let tenant_id = TenantId::generate();
        let user_id = UserId::generate();

        let role = fixtures::operator_role(tenant_id);

        repo.insert_role(role.clone());
        repo.assign_role(RoleAssignmentInput::new(tenant_id, user_id, role.id()))
            .await
            .unwrap();

        let roles = repo.get_roles_for_user(tenant_id, user_id).await.unwrap();

        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].name(), "operator");
    });
}

#[test]
fn tenant_scope_is_explicit_across_assignment_and_loading() {
    block_on(async {
        let repo = InMemoryRoleRepository::new();
        let tenant_a = TenantId::generate();
        let tenant_b = TenantId::generate();
        let user_id = UserId::generate();

        let role = fixtures::operator_role(tenant_a);

        repo.insert_role(role.clone());
        repo.assign_role(RoleAssignmentInput::new(tenant_a, user_id, role.id()))
            .await
            .unwrap();

        assert_eq!(
            repo.get_roles_for_user(tenant_a, user_id)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(
            repo.get_roles_for_user(tenant_b, user_id)
                .await
                .unwrap()
                .is_empty()
        );
    });
}

#[test]
fn contract_supports_role_revocation_within_tenant_scope() {
    block_on(async {
        let repo = InMemoryRoleRepository::new();
        let tenant_id = TenantId::generate();
        let user_id = UserId::generate();
        let role = fixtures::operator_role(tenant_id);

        repo.insert_role(role.clone());
        repo.assign_role(RoleAssignmentInput::new(tenant_id, user_id, role.id()))
            .await
            .unwrap();
        repo.revoke_role(RoleAssignmentInput::new(tenant_id, user_id, role.id()))
            .await
            .unwrap();

        assert!(
            repo.get_roles_for_user(tenant_id, user_id)
                .await
                .unwrap()
                .is_empty()
        );
    });
}

#[test]
fn ports_module_role_repository_export_remains_usable() {
    fn assert_role_repository_trait<T: RoleRepository>() {}

    assert_role_repository_trait::<InMemoryRoleRepository>();
}
