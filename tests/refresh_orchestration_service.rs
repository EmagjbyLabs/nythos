mod support;

use nythos_core::{
    AuthError, RefreshInput, RefreshService, RoleAssignmentInput, RoleRepository, SessionId,
    SessionRecord, SessionStore, TenantId, TokenPurpose, UserId,
};
use std::time::Duration;
use support::{
    FakeRevocationChecker, FakeTokenSigner, InMemoryRoleRepository, InMemorySessionStore, fixtures,
};

#[test]
fn refresh_rejects_unknown_refresh_tokens() {
    let sessions = InMemorySessionStore::new();
    let roles = InMemoryRoleRepository::new();
    let signer = FakeTokenSigner;
    let checker = FakeRevocationChecker::default();
    let service = RefreshService::new(&sessions, &roles, &signer, &checker);

    let result = service.refresh(RefreshInput::new(
        "missing-refresh".to_owned(),
        fixtures::canonical_issued_at(),
        fixtures::canonical_access_token_ttl(),
    ));

    assert!(matches!(result, Err(AuthError::InvalidCredentials)));
}

#[test]
fn refresh_rejects_revoked_sessions_before_issuing_auth_material() {
    let sessions = InMemorySessionStore::new();
    let roles = InMemoryRoleRepository::new();
    let signer = FakeTokenSigner;
    let checker = FakeRevocationChecker::default();
    let service = RefreshService::new(&sessions, &roles, &signer, &checker);

    let session = fixtures::session(
        SessionId::generate(),
        UserId::generate(),
        TenantId::generate(),
        fixtures::canonical_issued_at(),
        fixtures::canonical_session_ttl(),
    );
    let refresh = fixtures::refresh_token("revoked-refresh");

    sessions
        .create_session(SessionRecord::new(session.clone(), refresh.clone()))
        .unwrap();
    sessions.revoke_session(session.id()).unwrap();

    let result = service.refresh(RefreshInput::new(
        refresh.as_str().to_owned(),
        fixtures::canonical_issued_at() + Duration::from_secs(10),
        fixtures::canonical_access_token_ttl(),
    ));

    assert!(matches!(
        result,
        Err(AuthError::InvalidCredentials | AuthError::SessionRevoked)
    ));
}

#[test]
fn refresh_rejects_expired_sessions() {
    let sessions = InMemorySessionStore::new();
    let roles = InMemoryRoleRepository::new();
    let signer = FakeTokenSigner;
    let checker = FakeRevocationChecker::default();
    let service = RefreshService::new(&sessions, &roles, &signer, &checker);

    let issued_at = fixtures::canonical_issued_at();
    let session = fixtures::session(
        SessionId::generate(),
        UserId::generate(),
        TenantId::generate(),
        issued_at,
        Duration::from_secs(60),
    );
    let refresh = fixtures::refresh_token("expired-refresh");

    sessions
        .create_session(SessionRecord::new(session, refresh.clone()))
        .unwrap();

    let result = service.refresh(RefreshInput::new(
        refresh.as_str().to_owned(),
        issued_at + Duration::from_secs(60),
        fixtures::canonical_access_token_ttl(),
    ));

    assert!(matches!(result, Err(AuthError::SessionExpired)));
}

#[test]
fn refresh_rotates_token_and_returns_fresh_auth_material() {
    let sessions = InMemorySessionStore::new();
    let roles = InMemoryRoleRepository::new();
    let signer = FakeTokenSigner;
    let checker = FakeRevocationChecker::default();
    let service = RefreshService::new(&sessions, &roles, &signer, &checker);

    let tenant_id = TenantId::generate();
    let user_id = UserId::generate();
    let role = fixtures::operator_role(tenant_id);

    roles.insert_role(role.clone());
    roles
        .assign_role(RoleAssignmentInput::new(tenant_id, user_id, role.id()))
        .unwrap();

    let issued_at = fixtures::canonical_issued_at();
    let session = fixtures::session(
        SessionId::generate(),
        user_id,
        tenant_id,
        issued_at,
        fixtures::canonical_session_ttl(),
    );
    let initial_refresh = fixtures::refresh_token("initial-refresh");

    sessions
        .create_session(SessionRecord::new(session.clone(), initial_refresh.clone()))
        .unwrap();

    let result = service
        .refresh(RefreshInput::new(
            initial_refresh.as_str().to_owned(),
            issued_at + Duration::from_secs(10),
            fixtures::canonical_access_token_ttl(),
        ))
        .unwrap();

    assert_eq!(result.session().id(), session.id());
    assert_eq!(result.roles().len(), 1);
    assert_eq!(result.roles()[0].name(), "operator");
    assert_eq!(result.claims().tenant_id(), tenant_id);
    assert_eq!(result.claims().purpose(), &TokenPurpose::Access);
    assert!(!result.access_token().as_str().is_empty());
    assert_ne!(result.refresh_token().as_str(), initial_refresh.as_str());

    assert!(
        sessions
            .find_by_refresh_token(&initial_refresh)
            .unwrap()
            .is_none()
    );
    assert!(
        sessions
            .find_by_refresh_token(result.refresh_token())
            .unwrap()
            .is_some()
    );
}

#[test]
fn refresh_honors_external_revocation_checker() {
    let sessions = InMemorySessionStore::new();
    let roles = InMemoryRoleRepository::new();
    let signer = FakeTokenSigner;
    let checker = FakeRevocationChecker::default();
    let service = RefreshService::new(&sessions, &roles, &signer, &checker);

    let session = fixtures::session(
        SessionId::generate(),
        UserId::generate(),
        TenantId::generate(),
        fixtures::canonical_issued_at(),
        fixtures::canonical_session_ttl(),
    );
    let refresh = fixtures::refresh_token("checker-refresh");

    sessions
        .create_session(SessionRecord::new(session.clone(), refresh.clone()))
        .unwrap();

    checker.mark_revoked(session.id());

    let result = service.refresh(RefreshInput::new(
        refresh.as_str().to_owned(),
        fixtures::canonical_issued_at() + Duration::from_secs(10),
        fixtures::canonical_access_token_ttl(),
    ));

    assert!(matches!(result, Err(AuthError::SessionRevoked)));
}
