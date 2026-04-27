mod support;

use nythos_core::{
    AuthError, LoginInput, LoginService, NewUser, PasswordHasher, RoleAssignmentInput,
    RoleRepository, SessionStore, TenantId, TokenPurpose, UserRepository, UserStatus,
};
use support::{
    FakePasswordHasher, FakeTokenSigner, InMemoryRoleRepository, InMemorySessionStore,
    InMemoryUserRepository, fixtures,
};

#[test]
fn login_validates_inbound_value_objects() {
    let users = InMemoryUserRepository::new();
    let roles = InMemoryRoleRepository::new();
    let sessions = InMemorySessionStore::new();
    let hasher = FakePasswordHasher;
    let signer = FakeTokenSigner;
    let service = LoginService::new(&users, &roles, &sessions, &hasher, &signer);

    let result = service.login(LoginInput::new(
        TenantId::generate(),
        "bad-email".to_owned(),
        "short".to_owned(),
        fixtures::canonical_issued_at(),
        fixtures::canonical_access_token_ttl(),
        fixtures::canonical_session_ttl(),
    ));

    assert!(matches!(result, Err(AuthError::ValidationError(_))));
}

#[test]
fn login_rejects_invalid_credentials() {
    let users = InMemoryUserRepository::new();
    let roles = InMemoryRoleRepository::new();
    let sessions = InMemorySessionStore::new();
    let hasher = FakePasswordHasher;
    let signer = FakeTokenSigner;
    let tenant_id = TenantId::generate();

    let password_hash = hasher.hash(&fixtures::canonical_password()).unwrap();
    users
        .create(
            tenant_id,
            NewUser::new(fixtures::canonical_email()),
            password_hash,
        )
        .unwrap();

    let service = LoginService::new(&users, &roles, &sessions, &hasher, &signer);

    let result = service.login(LoginInput::new(
        tenant_id,
        fixtures::canonical_email_string(),
        "wrong-password".to_owned(),
        fixtures::canonical_issued_at(),
        fixtures::canonical_access_token_ttl(),
        fixtures::canonical_session_ttl(),
    ));

    assert!(matches!(result, Err(AuthError::InvalidCredentials)));
}

#[test]
fn login_rejects_locked_accounts_before_completion() {
    let users = InMemoryUserRepository::new();
    let roles = InMemoryRoleRepository::new();
    let sessions = InMemorySessionStore::new();
    let hasher = FakePasswordHasher;
    let signer = FakeTokenSigner;
    let tenant_id = TenantId::generate();

    let password_hash = hasher.hash(&fixtures::canonical_password()).unwrap();
    let user = users
        .create(
            tenant_id,
            NewUser::new(fixtures::canonical_email()),
            password_hash,
        )
        .unwrap();

    users
        .update_status(tenant_id, user.id(), UserStatus::Locked)
        .unwrap();

    let service = LoginService::new(&users, &roles, &sessions, &hasher, &signer);

    let result = service.login(LoginInput::new(
        tenant_id,
        fixtures::canonical_email_string(),
        fixtures::canonical_password_string(),
        fixtures::canonical_issued_at(),
        fixtures::canonical_access_token_ttl(),
        fixtures::canonical_session_ttl(),
    ));

    assert!(matches!(result, Err(AuthError::AccountLocked)));
}

#[test]
fn login_loads_tenant_scoped_roles_and_returns_auth_material() {
    let users = InMemoryUserRepository::new();
    let roles = InMemoryRoleRepository::new();
    let sessions = InMemorySessionStore::new();
    let hasher = FakePasswordHasher;
    let signer = FakeTokenSigner;
    let tenant_id = TenantId::generate();

    let password_hash = hasher.hash(&fixtures::canonical_password()).unwrap();
    let user = users
        .create(
            tenant_id,
            NewUser::new(fixtures::canonical_email()),
            password_hash,
        )
        .unwrap();

    let role = fixtures::operator_role(tenant_id);

    roles.insert_role(role.clone());
    roles
        .assign_role(RoleAssignmentInput::new(tenant_id, user.id(), role.id()))
        .unwrap();

    let service = LoginService::new(&users, &roles, &sessions, &hasher, &signer);

    let result = service
        .login(LoginInput::new(
            tenant_id,
            fixtures::canonical_email_string(),
            fixtures::canonical_password_string(),
            fixtures::canonical_issued_at(),
            fixtures::canonical_access_token_ttl(),
            fixtures::canonical_session_ttl(),
        ))
        .unwrap();

    assert_eq!(result.user().id(), user.id());
    assert_eq!(result.roles().len(), 1);
    assert_eq!(result.roles()[0].name(), "operator");
    assert_eq!(result.claims().tenant_id(), tenant_id);
    assert_eq!(result.claims().purpose(), &TokenPurpose::Access);
    assert!(!result.access_token().as_str().is_empty());
    assert!(!result.refresh_token().as_str().is_empty());

    let stored = sessions
        .find_by_refresh_token(result.refresh_token())
        .unwrap();
    assert!(stored.is_some());
}
