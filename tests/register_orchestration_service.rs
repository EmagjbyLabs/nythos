mod support;

use futures::executor::block_on;
use nythos_core::{AuthError, RegisterInput, RegisterService, SessionStore, TenantId};
use support::{
    FakePasswordHasher, FakeTokenSigner, InMemorySessionStore, InMemoryUserRepository, fixtures,
};

#[test]
fn register_input_new_defaults_profile_fields_to_none() {
    let input = RegisterInput::new(
        TenantId::generate(),
        fixtures::canonical_email_string(),
        fixtures::canonical_password_string(),
        fixtures::canonical_issued_at(),
        fixtures::canonical_access_token_ttl(),
        fixtures::canonical_session_ttl(),
    );

    assert!(input.username().is_none());
    assert!(input.display_name().is_none());
    assert!(input.auto_sign_in());
}

#[test]
fn register_input_with_profile_sets_optional_profile_fields() {
    let input = RegisterInput::new(
        TenantId::generate(),
        fixtures::canonical_email_string(),
        fixtures::canonical_password_string(),
        fixtures::canonical_issued_at(),
        fixtures::canonical_access_token_ttl(),
        fixtures::canonical_session_ttl(),
    )
    .with_profile(Some("gencho_xd".to_owned()), Some("Gencho XD".to_owned()));

    assert_eq!(input.username(), Some("gencho_xd"));
    assert_eq!(input.display_name(), Some("Gencho XD"));
}

#[test]
fn register_input_with_username_sets_username_only() {
    let input = RegisterInput::new(
        TenantId::generate(),
        fixtures::canonical_email_string(),
        fixtures::canonical_password_string(),
        fixtures::canonical_issued_at(),
        fixtures::canonical_access_token_ttl(),
        fixtures::canonical_session_ttl(),
    )
    .with_username("gencho_xd");

    assert_eq!(input.username(), Some("gencho_xd"));
    assert!(input.display_name().is_none());
}

#[test]
fn register_input_with_display_name_sets_display_name_only() {
    let input = RegisterInput::new(
        TenantId::generate(),
        fixtures::canonical_email_string(),
        fixtures::canonical_password_string(),
        fixtures::canonical_issued_at(),
        fixtures::canonical_access_token_ttl(),
        fixtures::canonical_session_ttl(),
    )
    .with_display_name("Gencho XD");

    assert!(input.username().is_none());
    assert_eq!(input.display_name(), Some("Gencho XD"));
}

#[test]
fn register_input_with_auto_sign_in_preserves_existing_behavior() {
    let input = RegisterInput::new(
        TenantId::generate(),
        fixtures::canonical_email_string(),
        fixtures::canonical_password_string(),
        fixtures::canonical_issued_at(),
        fixtures::canonical_access_token_ttl(),
        fixtures::canonical_session_ttl(),
    )
    .with_auto_sign_in(false);

    assert!(!input.auto_sign_in());
}

#[test]
fn register_validates_email_and_password_through_core_value_objects() {
    block_on(async {
        let users = InMemoryUserRepository::new();
        let sessions = InMemorySessionStore::new();
        let hasher = FakePasswordHasher;
        let signer = FakeTokenSigner;
        let service = RegisterService::new(&users, &sessions, &hasher, &signer);

        let result = service
            .register(RegisterInput::new(
                TenantId::generate(),
                "not-an-email".to_owned(),
                "short".to_owned(),
                fixtures::canonical_issued_at(),
                fixtures::canonical_access_token_ttl(),
                fixtures::canonical_session_ttl(),
            ))
            .await;

        assert!(matches!(result, Err(AuthError::ValidationError(_))));
    });
}

#[test]
fn register_enforces_tenant_scoped_duplicate_email_checks() {
    block_on(async {
        let users = InMemoryUserRepository::new();
        let sessions = InMemorySessionStore::new();
        let hasher = FakePasswordHasher;
        let signer = FakeTokenSigner;
        let service = RegisterService::new(&users, &sessions, &hasher, &signer);
        let tenant_id = TenantId::generate();

        service
            .register(RegisterInput::new(
                tenant_id,
                fixtures::canonical_email_string(),
                fixtures::canonical_password_string(),
                fixtures::canonical_issued_at(),
                fixtures::canonical_access_token_ttl(),
                fixtures::canonical_session_ttl(),
            ))
            .await
            .unwrap();

        let duplicate = service
            .register(RegisterInput::new(
                tenant_id,
                fixtures::canonical_email_string(),
                "another-secret-password".to_owned(),
                fixtures::canonical_issued_at(),
                fixtures::canonical_access_token_ttl(),
                fixtures::canonical_session_ttl(),
            ))
            .await;

        assert!(matches!(duplicate, Err(AuthError::ValidationError(_))));
    });
}

#[test]
fn register_returns_signed_auth_material_when_auto_sign_in_is_enabled() {
    block_on(async {
        let users = InMemoryUserRepository::new();
        let sessions = InMemorySessionStore::new();
        let hasher = FakePasswordHasher;
        let signer = FakeTokenSigner;
        let service = RegisterService::new(&users, &sessions, &hasher, &signer);
        let tenant_id = TenantId::generate();

        let result = service
            .register(RegisterInput::new(
                tenant_id,
                fixtures::canonical_email_string(),
                fixtures::canonical_password_string(),
                fixtures::canonical_issued_at(),
                fixtures::canonical_access_token_ttl(),
                fixtures::canonical_session_ttl(),
            ))
            .await
            .unwrap();

        let auth = result.auth().unwrap();

        assert_eq!(result.user().id(), auth.user().id());
        assert_eq!(auth.session().tenant_id(), tenant_id);
        assert_eq!(auth.claims().tenant_id(), tenant_id);
        assert!(!auth.access_token().as_str().is_empty());
        assert!(!auth.refresh_token().as_str().is_empty());

        let stored = sessions
            .find_by_refresh_token(auth.refresh_token())
            .await
            .unwrap();
        assert!(stored.is_some());
    });
}

#[test]
fn register_can_return_user_without_auth_material() {
    block_on(async {
        let users = InMemoryUserRepository::new();
        let sessions = InMemorySessionStore::new();
        let hasher = FakePasswordHasher;
        let signer = FakeTokenSigner;
        let service = RegisterService::new(&users, &sessions, &hasher, &signer);

        let result = service
            .register(
                RegisterInput::new(
                    TenantId::generate(),
                    fixtures::canonical_email_string(),
                    fixtures::canonical_password_string(),
                    fixtures::canonical_issued_at(),
                    fixtures::canonical_access_token_ttl(),
                    fixtures::canonical_session_ttl(),
                )
                .with_auto_sign_in(false),
            )
            .await
            .unwrap();

        assert!(result.auth().is_none());
    });
}
