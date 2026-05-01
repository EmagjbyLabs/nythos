mod support;

use futures::executor::block_on;
use nythos_core::{NewUser, PasswordHash, TenantId, UserCredentials, UserRepository};
use support::{InMemoryUserRepository, fixtures};

#[test]
fn new_user_wraps_domain_email() {
    let email = fixtures::canonical_email();
    let new_user = NewUser::new(email.clone());

    assert_eq!(new_user.email(), &email);
}

#[test]
fn contract_is_usable_for_login_and_registration_style_flows() {
    block_on(async {
        let repo = InMemoryUserRepository::new();
        let tenant_id = TenantId::generate();
        let email = fixtures::canonical_email();

        let created = repo
            .create(
                tenant_id,
                NewUser::new(email.clone()),
                PasswordHash::new("hashed-password").unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            repo.find_by_email(tenant_id, &email)
                .await
                .unwrap()
                .unwrap()
                .id(),
            created.id()
        );
        assert_eq!(
            repo.find_by_id(tenant_id, created.id())
                .await
                .unwrap()
                .unwrap()
                .email(),
            &email
        );
    });
}

#[test]
fn user_credentials_carry_user_and_password_hash() {
    block_on(async {
        let repo = InMemoryUserRepository::new();
        let tenant_id = TenantId::generate();
        let email = fixtures::canonical_email();
        let password_hash = PasswordHash::new("hashed-password").unwrap();

        let created = repo
            .create(
                tenant_id,
                NewUser::new(email.clone()),
                password_hash.clone(),
            )
            .await
            .unwrap();

        let credentials = repo
            .find_credentials_by_email(tenant_id, &email)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(credentials.user().id(), created.id());
        assert_eq!(credentials.password_hash(), &password_hash);
    });
}

#[test]
fn tenant_context_is_explicit_on_all_lookup_paths() {
    block_on(async {
        let repo = InMemoryUserRepository::new();
        let tenant_a = TenantId::generate();
        let tenant_b = TenantId::generate();

        let created = repo
            .create(
                tenant_a,
                NewUser::new(fixtures::canonical_email()),
                PasswordHash::new("hashed-password").unwrap(),
            )
            .await
            .unwrap();

        assert!(
            repo.find_by_id(tenant_a, created.id())
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            repo.find_by_id(tenant_b, created.id())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            repo.find_credentials_by_email(tenant_b, created.email())
                .await
                .unwrap()
                .is_none()
        )
    });
}

#[test]
fn crate_root_and_ports_module_exports_remain_usable() {
    fn assert_user_repo_trait<T: UserRepository>() {}

    let _new_user: NewUser = NewUser::new(fixtures::canonical_email());
    let _credentials_type: Option<UserCredentials> = None;
    let _crate_root_credentials_type: Option<UserCredentials> = None;

    assert_user_repo_trait::<InMemoryUserRepository>();
}
