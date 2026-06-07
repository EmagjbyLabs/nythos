mod support;

use futures::executor::block_on;
use nythos_core::{
    AuthError, LoginInput, LoginService, NewUser, PasswordHasher, RoleAssignmentInput,
    RoleRepository, SessionStore, TenantAuthPolicy, TenantId, TokenPurpose, UserRepository,
    UserStatus, Username,
};
use support::{
    FakePasswordHasher, FakeTenantPolicyPort, FakeTokenSigner, InMemoryRoleRepository,
    InMemorySessionStore, InMemoryUserRepository, fixtures,
};

#[test]
fn login_input_new_preserves_email_constructor_shape() {
    let input = LoginInput::new(
        TenantId::generate(),
        fixtures::canonical_email_string(),
        fixtures::canonical_password_string(),
        fixtures::canonical_issued_at(),
        fixtures::canonical_access_token_ttl(),
        fixtures::canonical_session_ttl(),
    );

    assert_eq!(input.identifier(), fixtures::canonical_email_string());
    assert_eq!(input.email(), fixtures::canonical_email_string());
    assert_eq!(input.password(), fixtures::canonical_password_string());
}

#[test]
fn login_input_new_stores_email_as_identifier_string() {
    let email = fixtures::canonical_email_string();

    let input = LoginInput::new(
        TenantId::generate(),
        email.clone(),
        fixtures::canonical_password_string(),
        fixtures::canonical_issued_at(),
        fixtures::canonical_access_token_ttl(),
        fixtures::canonical_session_ttl(),
    );

    assert_eq!(input.identifier(), email);
    assert_eq!(input.email(), email);
}

#[test]
fn login_input_new_with_identifier_stores_identifier_string() {
    let input = LoginInput::new_with_identifier(
        TenantId::generate(),
        "gencho_xd".to_owned(),
        fixtures::canonical_password_string(),
        fixtures::canonical_issued_at(),
        fixtures::canonical_access_token_ttl(),
        fixtures::canonical_session_ttl(),
    );

    assert_eq!(input.identifier(), "gencho_xd");
    assert_eq!(input.email(), "gencho_xd");
}

#[test]
fn login_input_email_getter_is_compatibility_alias() {
    let input = LoginInput::new_with_identifier(
        TenantId::generate(),
        "person_or_username".to_owned(),
        fixtures::canonical_password_string(),
        fixtures::canonical_issued_at(),
        fixtures::canonical_access_token_ttl(),
        fixtures::canonical_session_ttl(),
    );

    assert_eq!(input.email(), input.identifier());
}

#[test]
fn login_input_getters_preserve_timing_and_ttls() {
    let tenant_id = TenantId::generate();
    let issued_at = fixtures::canonical_issued_at();
    let access_token_ttl = fixtures::canonical_access_token_ttl();
    let session_ttl = fixtures::canonical_session_ttl();

    let input = LoginInput::new_with_identifier(
        tenant_id,
        "gencho_xd".to_owned(),
        fixtures::canonical_password_string(),
        issued_at,
        access_token_ttl,
        session_ttl,
    );

    assert_eq!(input.tenant_id(), tenant_id);
    assert_eq!(input.issued_at(), issued_at);
    assert_eq!(input.access_token_ttl(), access_token_ttl);
    assert_eq!(input.session_ttl(), session_ttl);
}

#[test]
fn login_validates_inbound_value_objects() {
    block_on(async {
        let users = InMemoryUserRepository::new();
        let roles = InMemoryRoleRepository::new();
        let policies = FakeTenantPolicyPort::default();
        let sessions = InMemorySessionStore::new();
        let hasher = FakePasswordHasher;
        let signer = FakeTokenSigner;
        let service = LoginService::new(&users, &roles, &policies, &sessions, &hasher, &signer);

        let result = service
            .login(LoginInput::new(
                TenantId::generate(),
                "!!bad".to_owned(),
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
        let policies = FakeTenantPolicyPort::default();
        let sessions = InMemorySessionStore::new();
        let hasher = FakePasswordHasher;
        let signer = FakeTokenSigner;
        let service = LoginService::new(&users, &roles, &policies, &sessions, &hasher, &signer);

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
        let policies = FakeTenantPolicyPort::default();
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

        let service = LoginService::new(&users, &roles, &policies, &sessions, &hasher, &signer);

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
        let policies = FakeTenantPolicyPort::default();
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

        let service = LoginService::new(&users, &roles, &policies, &sessions, &hasher, &signer);

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
        let policies = FakeTenantPolicyPort::default();
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

        let service = LoginService::new(&users, &roles, &policies, &sessions, &hasher, &signer);

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
fn login_by_email_loads_tenant_scoped_roles_and_returns_auth_material() {
    block_on(async {
        let users = InMemoryUserRepository::new();
        let roles = InMemoryRoleRepository::new();
        let policies = FakeTenantPolicyPort::default();
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

        let service = LoginService::new(&users, &roles, &policies, &sessions, &hasher, &signer);

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

#[test]
fn login_by_username_when_enabled_returns_auth_material() {
    block_on(async {
        let users = InMemoryUserRepository::new();
        let roles = InMemoryRoleRepository::new();
        let policies = FakeTenantPolicyPort::default();
        let sessions = InMemorySessionStore::new();
        let hasher = FakePasswordHasher;
        let signer = FakeTokenSigner;
        let tenant_id = TenantId::generate();
        let username = Username::parse("Gencho_XD").unwrap();

        policies.insert_policy(tenant_id, TenantAuthPolicy::new(false, false, true));

        let password_hash = hasher.hash(&fixtures::canonical_password()).await.unwrap();
        let user = users
            .create(
                tenant_id,
                NewUser::with_profile(fixtures::canonical_email(), Some(username.clone()), None),
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

        let service = LoginService::new(&users, &roles, &policies, &sessions, &hasher, &signer);

        let result = service
            .login(LoginInput::new_with_identifier(
                tenant_id,
                "Gencho_XD".to_owned(),
                fixtures::canonical_password_string(),
                fixtures::canonical_issued_at(),
                fixtures::canonical_access_token_ttl(),
                fixtures::canonical_session_ttl(),
            ))
            .await
            .unwrap();

        assert_eq!(result.user().id(), user.id());
        assert_eq!(result.user().username(), Some(&username));
        assert_eq!(result.roles().len(), 1);
        assert_eq!(result.claims().tenant_id(), tenant_id);
        assert_eq!(result.claims().purpose(), &TokenPurpose::Access);
        assert!(!result.access_token().as_str().is_empty());
        assert!(!result.refresh_token().as_str().is_empty());
    });
}

#[test]
fn login_by_username_when_disabled_returns_invalid_credentials_without_lookup() {
    block_on(async {
        let users = InMemoryUserRepository::new();
        let roles = InMemoryRoleRepository::new();
        let policies = FakeTenantPolicyPort::default();
        let sessions = InMemorySessionStore::new();
        let hasher = FakePasswordHasher;
        let signer = FakeTokenSigner;
        let tenant_id = TenantId::generate();

        let service = LoginService::new(&users, &roles, &policies, &sessions, &hasher, &signer);

        let result = service
            .login(LoginInput::new_with_identifier(
                tenant_id,
                "gencho_xd".to_owned(),
                fixtures::canonical_password_string(),
                fixtures::canonical_issued_at(),
                fixtures::canonical_access_token_ttl(),
                fixtures::canonical_session_ttl(),
            ))
            .await;

        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
        assert_eq!(users.username_credentials_lookup_count(), 0);
    });
}

#[test]
fn login_by_username_not_found_returns_invalid_credentials() {
    block_on(async {
        let users = InMemoryUserRepository::new();
        let roles = InMemoryRoleRepository::new();
        let policies = FakeTenantPolicyPort::default();
        let sessions = InMemorySessionStore::new();
        let hasher = FakePasswordHasher;
        let signer = FakeTokenSigner;
        let tenant_id = TenantId::generate();

        policies.insert_policy(tenant_id, TenantAuthPolicy::new(false, false, true));

        let service = LoginService::new(&users, &roles, &policies, &sessions, &hasher, &signer);

        let result = service
            .login(LoginInput::new_with_identifier(
                tenant_id,
                "missing_user".to_owned(),
                fixtures::canonical_password_string(),
                fixtures::canonical_issued_at(),
                fixtures::canonical_access_token_ttl(),
                fixtures::canonical_session_ttl(),
            ))
            .await;

        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
        assert_eq!(users.username_credentials_lookup_count(), 1);
    });
}

#[test]
fn login_by_username_wrong_password_returns_invalid_credentials() {
    block_on(async {
        let users = InMemoryUserRepository::new();
        let roles = InMemoryRoleRepository::new();
        let policies = FakeTenantPolicyPort::default();
        let sessions = InMemorySessionStore::new();
        let hasher = FakePasswordHasher;
        let signer = FakeTokenSigner;
        let tenant_id = TenantId::generate();

        policies.insert_policy(tenant_id, TenantAuthPolicy::new(false, false, true));

        let password_hash = hasher.hash(&fixtures::canonical_password()).await.unwrap();
        users
            .create(
                tenant_id,
                NewUser::with_profile(
                    fixtures::canonical_email(),
                    Some(Username::parse("Gencho_XD").unwrap()),
                    None,
                ),
                password_hash,
            )
            .await
            .unwrap();

        let service = LoginService::new(&users, &roles, &policies, &sessions, &hasher, &signer);

        let result = service
            .login(LoginInput::new_with_identifier(
                tenant_id,
                "Gencho_XD".to_owned(),
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
fn username_disabled_missing_user_and_wrong_password_share_invalid_credentials_shape() {
    block_on(async {
        let users = InMemoryUserRepository::new();
        let roles = InMemoryRoleRepository::new();
        let policies = FakeTenantPolicyPort::default();
        let sessions = InMemorySessionStore::new();
        let hasher = FakePasswordHasher;
        let signer = FakeTokenSigner;
        let enabled_tenant = TenantId::generate();
        let disabled_tenant = TenantId::generate();

        policies.insert_policy(enabled_tenant, TenantAuthPolicy::new(false, false, true));

        let password_hash = hasher.hash(&fixtures::canonical_password()).await.unwrap();
        users
            .create(
                enabled_tenant,
                NewUser::with_profile(
                    fixtures::canonical_email(),
                    Some(Username::parse("Gencho_XD").unwrap()),
                    None,
                ),
                password_hash,
            )
            .await
            .unwrap();

        let service = LoginService::new(&users, &roles, &policies, &sessions, &hasher, &signer);

        let disabled_username = service
            .login(LoginInput::new_with_identifier(
                disabled_tenant,
                "gencho_xd".to_owned(),
                fixtures::canonical_password_string(),
                fixtures::canonical_issued_at(),
                fixtures::canonical_access_token_ttl(),
                fixtures::canonical_session_ttl(),
            ))
            .await;

        let missing_username = service
            .login(LoginInput::new_with_identifier(
                enabled_tenant,
                "missing_user".to_owned(),
                fixtures::canonical_password_string(),
                fixtures::canonical_issued_at(),
                fixtures::canonical_access_token_ttl(),
                fixtures::canonical_session_ttl(),
            ))
            .await;

        let wrong_password = service
            .login(LoginInput::new_with_identifier(
                enabled_tenant,
                "gencho_xd".to_owned(),
                "wrong-password".to_owned(),
                fixtures::canonical_issued_at(),
                fixtures::canonical_access_token_ttl(),
                fixtures::canonical_session_ttl(),
            ))
            .await;

        assert!(matches!(
            disabled_username,
            Err(AuthError::InvalidCredentials)
        ));
        assert!(matches!(
            missing_username,
            Err(AuthError::InvalidCredentials)
        ));
        assert!(matches!(wrong_password, Err(AuthError::InvalidCredentials)));
    });
}
