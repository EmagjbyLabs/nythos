use std::collections::BTreeMap;
use std::time::SystemTime;

use nythos_core::{
    DisplayName, Email, Tenant, TenantAuthPolicy, TenantId, TenantSettings, User, UserId,
    UserStatus, Username,
};

#[test]
fn user_uses_typed_identity_and_domain_email() {
    let id = UserId::generate();
    let email = Email::parse("person@example.com").unwrap();
    let user = User::new(id, email.clone(), SystemTime::UNIX_EPOCH);

    assert_eq!(user.id(), id);
    assert_eq!(user.email(), &email);
    assert_eq!(user.status(), UserStatus::Active);
}

#[test]
fn user_new_has_no_profile_fields() {
    let user = User::new(
        UserId::generate(),
        Email::parse("person@example.com").unwrap(),
        SystemTime::UNIX_EPOCH,
    );

    assert!(user.username().is_none());
    assert!(user.display_name().is_none());
}

#[test]
fn user_with_status_has_no_profile_fields() {
    let user = User::with_status(
        UserId::generate(),
        Email::parse("person@example.com").unwrap(),
        UserStatus::Locked,
        SystemTime::UNIX_EPOCH,
    );

    assert_eq!(user.status(), UserStatus::Locked);
    assert!(user.username().is_none());
    assert!(user.display_name().is_none());
}

#[test]
fn user_with_profile_stores_profile_fields() {
    let username = Username::parse("Gencho_XD").unwrap();
    let display_name = DisplayName::parse("Gencho XD").unwrap();

    let user = User::with_profile(
        UserId::generate(),
        Email::parse("person@example.com").unwrap(),
        Some(username.clone()),
        Some(display_name.clone()),
        UserStatus::Active,
        SystemTime::UNIX_EPOCH,
    );

    assert_eq!(user.username(), Some(&username));
    assert_eq!(user.display_name(), Some(&display_name));
    assert_eq!(user.status(), UserStatus::Active);
}

#[test]
fn user_status_is_sufficient_for_auth_checks() {
    let mut user = User::new(
        UserId::generate(),
        Email::parse("person@example.com").unwrap(),
        SystemTime::UNIX_EPOCH,
    );

    assert!(user.can_authenticate());

    user.set_status(UserStatus::Locked);
    assert!(user.is_locked());
    assert!(!user.can_authenticate());

    user.set_status(UserStatus::Disabled);
    assert!(user.is_disabled());
    assert!(!user.can_authenticate());
}

#[test]
fn tenant_uses_typed_identity_and_validated_slug() {
    let tenant = Tenant::new(TenantId::generate(), "northstar").unwrap();

    assert_eq!(tenant.slug(), "northstar");
}

#[test]
fn tenant_auth_policy_default_disables_optional_auth_features() {
    let policy = TenantAuthPolicy::default();

    assert!(!policy.username_registration_enabled());
    assert!(!policy.display_name_registration_enabled());
    assert!(!policy.username_login_enabled());
}

#[test]
fn tenant_auth_policy_constructor_sets_flags() {
    let policy = TenantAuthPolicy::new(true, false, true);

    assert!(policy.username_registration_enabled());
    assert!(!policy.display_name_registration_enabled());
    assert!(policy.username_login_enabled());
}

#[test]
fn tenant_constructors_preserve_default_auth_policy() {
    let tenant = Tenant::new(TenantId::generate(), "northstar").unwrap();

    assert_eq!(tenant.auth_policy(), &TenantAuthPolicy::default());

    let settings = BTreeMap::from([("locale".to_owned(), "bg".to_owned())]);
    let tenant_with_settings = Tenant::with_settings(
        TenantId::generate(),
        "southstar",
        Some(TenantSettings::new(settings)),
    )
    .unwrap();

    assert_eq!(
        tenant_with_settings.auth_policy(),
        &TenantAuthPolicy::default()
    );
}

#[test]
fn tenant_with_auth_policy_accepts_explicit_policy() {
    let policy = TenantAuthPolicy::new(true, true, false);
    let tenant = Tenant::with_auth_policy(TenantId::generate(), "northstar", None, policy).unwrap();

    assert_eq!(tenant.auth_policy(), &policy);
}

#[test]
fn tenant_auth_policy_can_be_updated() {
    let mut tenant = Tenant::new(TenantId::generate(), "northstar").unwrap();
    let policy = TenantAuthPolicy::new(true, false, true);

    tenant.set_auth_policy(policy);

    assert_eq!(tenant.auth_policy(), &policy);
}
