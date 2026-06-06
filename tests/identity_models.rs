use std::time::SystemTime;

use nythos_core::{Email, Tenant, TenantAuthPolicy, TenantId, User, UserId, UserStatus};

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
