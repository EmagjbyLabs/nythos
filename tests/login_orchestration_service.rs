mod support;

use futures::executor::block_on;
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
    block_on(async {
        let users = InMemoryUserRepository::new();
        let roles = InMemoryRoleRepository::new();
        let sessions = InMemorySessionStore::new();
        let hasher = FakePasswordHasher;
        let signer = FakeTokenSigner;
        let service = LoginService::new(&users, &roles, &sessions, &hasher, &signer);

        let result = service
            .login(LoginInput::new(
                TenantId::generate(),
                "bad-email".to_owned(),
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
fn login_returns_invalid_credentials_for_missing_user_with_valid_input_shape() {
    block_on(async {
        let users = InMemoryUserRepository::new();
        let roles = InMemoryRoleRepository::new();
        let sessions = InMemorySessionStore::new();
        let hasher = FakePasswordHasher;
        let signer = FakeTokenSigner;
        let service = LoginService::new(&users, &roles, &sessions, &hasher, &signer);

        let result = service
            .login(LoginInput::new(
                TenantId::generate(),
                fixtures::canonical_email_string(),
                fixtures::canonical_password_string(),
                fixtures::canonical_issued_at(),
                fixtures::canonical_access_token_ttl(),
                fixtures::canonical_session_ttl(),
            ))
            .await;

        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    });
}

#[test]
fn login_rejects_invalid_credentials() {
    block_on(async {
        let users = InMemoryUserRepository::new();
        let roles = InMemoryRoleRepository::new();
        let sessions = InMemorySessionStore::new();
        let hasher = FakePasswordHasher;
        let signer = FakeTokenSigner;
        let tenant_id = TenantId::generate();

        let password_hash = hasher.hash(&fixtures::canonical_password()).await.unwrap();
        users
            .create(
                tenant_id,
                NewUser::new(fixtures::canonical_email()),
                password_hash,
            )
            .await
            .unwrap();

        let service = LoginService::new(&users, &roles, &sessions, &hasher, &signer);

        let result = service
            .login(LoginInput::new(
                tenant_id,
                fixtures::canonical_email_string(),
                "wrong-password".to_owned(),
                fixtures::canonical_issued_at(),
                fixtures::canonical_access_token_ttl(),
                fixtures::canonical_session_ttl(),
            ))
            .await;

        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    });
}

#[test]
fn login_rejects_locked_accounts_before_completion() {
    block_on(async {
        let users = InMemoryUserRepository::new();
        let roles = InMemoryRoleRepository::new();
        let sessions = InMemorySessionStore::new();
        let hasher = FakePasswordHasher;
        let signer = FakeTokenSigner;
        let tenant_id = TenantId::generate();

        let password_hash = hasher.hash(&fixtures::canonical_password()).await.unwrap();
        let user = users
            .create(
                tenant_id,
                NewUser::new(fixtures::canonical_email()),
                password_hash,
            )
            .await
            .unwrap();

        users
            .update_status(tenant_id, user.id(), UserStatus::Locked)
            .await
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
            .await;

        assert!(matches!(result, Err(AuthError::AccountLocked)));
    });
}

#[test]
fn login_rejects_disabled_accounts_as_account_locked() {
    block_on(async {
        let users = InMemoryUserRepository::new();
        let roles = InMemoryRoleRepository::new();
        let sessions = InMemorySessionStore::new();
        let hasher = FakePasswordHasher;
        let signer = FakeTokenSigner;
        let tenant_id = TenantId::generate();

        let password_hash = hasher.hash(&fixtures::canonical_password()).await.unwrap();
        let user = users
            .create(
                tenant_id,
                NewUser::new(fixtures::canonical_email()),
                password_hash,
            )
            .await
            .unwrap();

        users
            .update_status(tenant_id, user.id(), UserStatus::Disabled)
            .await
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
            .await;

        assert!(matches!(result, Err(AuthError::AccountLocked)));
    });
}

#[test]
fn login_loads_tenant_scoped_roles_and_returns_auth_material() {
    block_on(async {
        let users = InMemoryUserRepository::new();
        let roles = InMemoryRoleRepository::new();
        let sessions = InMemorySessionStore::new();
        let hasher = FakePasswordHasher;
        let signer = FakeTokenSigner;
        let tenant_id = TenantId::generate();

        let password_hash = hasher.hash(&fixtures::canonical_password()).await.unwrap();
        let user = users
            .create(
                tenant_id,
                NewUser::new(fixtures::canonical_email()),
                password_hash,
            )
            .await
            .unwrap();

        let role = fixtures::operator_role(tenant_id);

        roles.insert_role(role.clone());
        roles
            .assign_role(RoleAssignmentInput::new(tenant_id, user.id(), role.id()))
            .await
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
            .await
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
            .await
            .unwrap();
        assert!(stored.is_some());
    });
}
