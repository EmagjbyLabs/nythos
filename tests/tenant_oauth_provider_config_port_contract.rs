mod support;

use futures::executor::block_on;
use nythos_core::{
    OAuthProviderKind, TenantId, TenantOAuthProviderConfig, TenantOAuthProviderConfigPort,
};
use support::InMemoryTenantOAuthProviderConfigPort;

#[test]
fn missing_provider_config_returns_none() {
    block_on(async {
        let port = InMemoryTenantOAuthProviderConfigPort::new();

        let config = port
            .load_provider_config(TenantId::generate(), OAuthProviderKind::Google)
            .await
            .unwrap();

        assert!(config.is_none());
    });
}

#[test]
fn provider_config_round_trips_for_tenant_and_provider() {
    block_on(async {
        let port = InMemoryTenantOAuthProviderConfigPort::new();
        let tenant_id = TenantId::generate();

        let expected =
            TenantOAuthProviderConfig::new(tenant_id, OAuthProviderKind::Google, true, true);

        port.insert_config(expected.clone());

        let actual = port
            .load_provider_config(tenant_id, OAuthProviderKind::Google)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(actual, expected);
        assert!(actual.is_enabled());
        assert!(actual.registration_allowed());
    });
}

#[test]
fn provider_config_is_tenant_scoped() {
    block_on(async {
        let port = InMemoryTenantOAuthProviderConfigPort::new();
        let tenant_a = TenantId::generate();
        let tenant_b = TenantId::generate();

        port.insert_config(TenantOAuthProviderConfig::new(
            tenant_a,
            OAuthProviderKind::Google,
            true,
            true,
        ));

        assert!(
            port.load_provider_config(tenant_a, OAuthProviderKind::Google)
                .await
                .unwrap()
                .is_some()
        );

        assert!(
            port.load_provider_config(tenant_b, OAuthProviderKind::Google)
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn provider_config_is_provider_scoped() {
    block_on(async {
        let port = InMemoryTenantOAuthProviderConfigPort::new();
        let tenant_id = TenantId::generate();

        port.insert_config(TenantOAuthProviderConfig::new(
            tenant_id,
            OAuthProviderKind::Google,
            true,
            true,
        ));

        assert!(
            port.load_provider_config(tenant_id, OAuthProviderKind::Google)
                .await
                .unwrap()
                .is_some()
        );

        assert!(
            port.load_provider_config(tenant_id, OAuthProviderKind::GitHub)
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn disabled_provider_config_is_returned_as_disabled() {
    block_on(async {
        let port = InMemoryTenantOAuthProviderConfigPort::new();
        let tenant_id = TenantId::generate();

        port.insert_config(TenantOAuthProviderConfig::new(
            tenant_id,
            OAuthProviderKind::Microsoft,
            false,
            true,
        ));

        let config = port
            .load_provider_config(tenant_id, OAuthProviderKind::Microsoft)
            .await
            .unwrap()
            .unwrap();

        assert!(!config.is_enabled());
        assert!(config.registration_allowed());
    });
}

#[test]
fn registration_allowed_flag_round_trips() {
    block_on(async {
        let port = InMemoryTenantOAuthProviderConfigPort::new();
        let tenant_id = TenantId::generate();

        port.insert_config(TenantOAuthProviderConfig::new(
            tenant_id,
            OAuthProviderKind::GitHub,
            true,
            false,
        ));

        let config = port
            .load_provider_config(tenant_id, OAuthProviderKind::GitHub)
            .await
            .unwrap()
            .unwrap();

        assert!(config.is_enabled());
        assert!(!config.registration_allowed());
    });
}

#[test]
fn ports_module_tenant_oauth_provider_config_port_export_remains_usable() {
    fn assert_tenant_oauth_provider_config_port<T: TenantOAuthProviderConfigPort>() {}

    assert_tenant_oauth_provider_config_port::<InMemoryTenantOAuthProviderConfigPort>();
}
