mod support;

use futures::executor::block_on;
use nythos_core::{TenantAuthPolicy, TenantId, TenantPolicyPort};
use support::FakeTenantPolicyPort;

#[test]
fn tenant_policy_port_export_is_available_from_crate_root() {
    fn assert_tenant_policy_port<T: TenantPolicyPort>() {}

    assert_tenant_policy_port::<FakeTenantPolicyPort>();
}

#[test]
fn tenant_policy_port_export_is_available_from_ports_module() {
    fn assert_tenant_policy_port<T: nythos_core::ports::TenantPolicyPort>() {}

    assert_tenant_policy_port::<FakeTenantPolicyPort>();
}

#[test]
fn fake_policy_port_returns_default_policy_when_tenant_has_no_override() {
    block_on(async {
        let port = FakeTenantPolicyPort::default();
        let policy = port.load_auth_policy(TenantId::generate()).await.unwrap();

        assert_eq!(policy, TenantAuthPolicy::default());
        assert!(!policy.username_registration_enabled());
        assert!(!policy.display_name_registration_enabled());
        assert!(!policy.username_login_enabled());
    });
}

#[test]
fn fake_policy_port_can_return_different_policies_per_tenant() {
    block_on(async {
        let port = FakeTenantPolicyPort::default();

        let tenant_a = TenantId::generate();
        let tenant_b = TenantId::generate();

        let policy_a = TenantAuthPolicy::new(true, false, true);
        let policy_b = TenantAuthPolicy::new(false, true, false);

        port.insert_policy(tenant_a, policy_a);
        port.insert_policy(tenant_b, policy_b);

        assert_eq!(port.load_auth_policy(tenant_a).await.unwrap(), policy_a);
        assert_eq!(port.load_auth_policy(tenant_b).await.unwrap(), policy_b);
    });
}
