mod support;

use nythos_core::{NewUser, PasswordHash, TenantId, UserRepository};
use support::{InMemoryUserRepository, fixtures};

#[test]
fn contract_is_usable_for_login_and_registration_style_flows() {
    let repo = InMemoryUserRepository::new();
    let tenant_id = TenantId::generate();
    let email = fixtures::canonical_email();

    let created = repo
        .create(
            tenant_id,
            NewUser::new(email.clone()),
            PasswordHash::new("hashed-password").unwrap(),
        )
        .unwrap();

    assert_eq!(
        repo.find_by_email(tenant_id, &email).unwrap().unwrap().id(),
        created.id()
    );
    assert_eq!(
        repo.find_by_id(tenant_id, created.id())
            .unwrap()
            .unwrap()
            .email(),
        &email
    );
}

#[test]
fn tenant_context_is_explicit_on_all_lookup_paths() {
    let repo = InMemoryUserRepository::new();
    let tenant_a = TenantId::generate();
    let tenant_b = TenantId::generate();

    let created = repo
        .create(
            tenant_a,
            NewUser::new(fixtures::canonical_email()),
            PasswordHash::new("hashed-password").unwrap(),
        )
        .unwrap();

    assert!(repo.find_by_id(tenant_a, created.id()).unwrap().is_some());
    assert!(repo.find_by_id(tenant_b, created.id()).unwrap().is_none());
}
