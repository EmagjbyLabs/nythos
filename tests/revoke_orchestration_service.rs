mod support;

use futures::executor::block_on;
use nythos_core::{
    AuthError, RevokeAllSessionsInput, RevokeAllSessionsService, RevokeSessionInput,
    RevokeSessionService, SessionId, SessionRecord, SessionStore, TenantId, UserId,
};
use support::{FakeRevocationChecker, InMemorySessionStore, fixtures};

#[test]
fn revoke_single_session_updates_future_lookup_state() {
    block_on(async {
        let store = InMemorySessionStore::new();
        let checker = FakeRevocationChecker::default();
        let service = RevokeSessionService::new(&store, &checker);

        let session = fixtures::session(
            SessionId::generate(),
            UserId::generate(),
            TenantId::generate(),
            fixtures::canonical_issued_at(),
            fixtures::canonical_session_ttl(),
        );
        let refresh = fixtures::refresh_token("session-refresh");

        store
            .create_session(SessionRecord::new(session.clone(), refresh.clone()))
            .await
            .unwrap();

        let result = service
            .revoke(RevokeSessionInput::new(session.id()))
            .await
            .unwrap();

        assert!(result.revoked());
        assert!(
            store
                .find_by_refresh_token(&refresh)
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn revoke_single_session_can_short_circuit_already_revoked_state() {
    block_on(async {
        let store = InMemorySessionStore::new();
        let checker = FakeRevocationChecker::default();
        let service = RevokeSessionService::new(&store, &checker);
        let session_id = SessionId::generate();

        checker.mark_revoked(session_id);

        let result = service
            .revoke(RevokeSessionInput::new(session_id))
            .await
            .unwrap();

        assert!(!result.revoked());
    });
}

#[test]
fn revoke_all_is_tenant_scoped() {
    block_on(async {
        let store = InMemorySessionStore::new();
        let service = RevokeAllSessionsService::new(&store);

        let tenant_a = TenantId::generate();
        let tenant_b = TenantId::generate();
        let user_id = UserId::generate();

        let session_a = fixtures::session(
            SessionId::generate(),
            user_id,
            tenant_a,
            fixtures::canonical_issued_at(),
            fixtures::canonical_session_ttl(),
        );
        let session_b = fixtures::session(
            SessionId::generate(),
            user_id,
            tenant_b,
            fixtures::canonical_issued_at(),
            fixtures::canonical_session_ttl(),
        );

        let refresh_a = fixtures::refresh_token("tenant-a-refresh");
        let refresh_b = fixtures::refresh_token("tenant-b-refresh");

        store
            .create_session(SessionRecord::new(session_a, refresh_a.clone()))
            .await
            .unwrap();
        store
            .create_session(SessionRecord::new(session_b, refresh_b.clone()))
            .await
            .unwrap();

        let result = service
            .revoke_all(RevokeAllSessionsInput::new(tenant_a, user_id))
            .await
            .unwrap();

        assert!(result.revoked());
        assert!(
            store
                .find_by_refresh_token(&refresh_a)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .find_by_refresh_token(&refresh_b)
                .await
                .unwrap()
                .is_some()
        );
    });
}

#[test]
fn revoke_single_session_surfaces_missing_session_failures() {
    block_on(async {
        let store = InMemorySessionStore::new();
        let checker = FakeRevocationChecker::default();
        let service = RevokeSessionService::new(&store, &checker);

        let result = service
            .revoke(RevokeSessionInput::new(SessionId::generate()))
            .await;

        assert!(matches!(result, Err(AuthError::SessionRevoked)));
    });
}

#[test]
fn revoke_all_returns_success_when_no_sessions_match() {
    block_on(async {
        let store = InMemorySessionStore::new();
        let service = RevokeAllSessionsService::new(&store);

        let result = service
            .revoke_all(RevokeAllSessionsInput::new(
                TenantId::generate(),
                UserId::generate(),
            ))
            .await
            .unwrap();

        assert!(result.revoked());
    });
}
