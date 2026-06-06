mod support;

use futures::executor::block_on;
use nythos_core::{
    DisplayName, NewUser, PasswordHash, TenantId, UserCredentials, UserRepository, Username,
};
use support::{InMemoryUserRepository, fixtures};

#[test]
fn new_user_wraps_domain_email() {
    let email = fixtures::canonical_email();
    let new_user = NewUser::new(email.clone());

    assert_eq!(new_user.email(), &email);
    assert!(new_user.username().is_none());
    assert!(new_user.display_name().is_none());
}

#[test]
fn new_user_with_profile_stores_optional_profile_fields() {
    let email = fixtures::canonical_email();
    let username = Username::parse("Gencho_XD").unwrap();
    let display_name = DisplayName::parse("Gencho XD").unwrap();

    let new_user = NewUser::with_profile(
        email.clone(),
        Some(username.clone()),
        Some(display_name.clone()),
    );

    assert_eq!(new_user.email(), &email);
    assert_eq!(new_user.username(), Some(&username));
    assert_eq!(new_user.display_name(), Some(&display_name));
}

#[test]
fn new_user_into_parts_returns_creation_payload() {
    let email = fixtures::canonical_email();
    let username = Username::parse("Gencho_XD").unwrap();
    let display_name = DisplayName::parse("Gencho XD").unwrap();

    let new_user = NewUser::with_profile(
        email.clone(),
        Some(username.clone()),
        Some(display_name.clone()),
    );

    let (actual_email, actual_username, actual_display_name) = new_user.into_parts();

    assert_eq!(actual_email, email);
    assert_eq!(actual_username, Some(username));
    assert_eq!(actual_display_name, Some(display_name));
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
fn contract_preserves_optional_profile_fields_during_creation() {
    block_on(async {
        let repo = InMemoryUserRepository::new();
        let tenant_id = TenantId::generate();
        let email = fixtures::canonical_email();
        let username = Username::parse("Gencho_XD").unwrap();
        let display_name = DisplayName::parse("Gencho XD").unwrap();

        let created = repo
            .create(
                tenant_id,
                NewUser::with_profile(
                    email.clone(),
                    Some(username.clone()),
                    Some(display_name.clone()),
                ),
                PasswordHash::new("hashed-password").unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(created.email(), &email);
        assert_eq!(created.username(), Some(&username));
        assert_eq!(created.display_name(), Some(&display_name));
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
