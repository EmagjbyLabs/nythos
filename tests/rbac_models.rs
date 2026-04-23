use nythos_core::{Permission, Role, RoleId, RoleRegistry, TenantId};

#[test]
fn role_registry_supports_tenant_scoped_role_lookup() {
    let tenant_id = TenantId::generate();
    let role_id = RoleId::generate();
    let role = Role::new(
        role_id,
        tenant_id,
        "operator",
        [
            Permission::new("shipments.read").unwrap(),
            Permission::new("shipments.write").unwrap(),
        ],
    )
    .unwrap();

    let registry = RoleRegistry::new(tenant_id, vec![role.clone()]).unwrap();

    assert_eq!(registry.find_role(role_id).unwrap().name(), "operator");
}
