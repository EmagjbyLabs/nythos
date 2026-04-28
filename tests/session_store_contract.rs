mod support;

use nythos_core::{RefreshTokenRotation, SessionId, SessionRecord, SessionStore, TenantId, UserId};
use support::{InMemorySessionStore, fixtures};

#[test]
fn session_record_keeps_session_and_refresh_token_together() {
    let session = fixtures::session(
        SessionId::generate(),
        UserId::generate(),
        TenantId::generate(),
        fixtures::canonical_issued_at(),
        fixtures::canonical_session_ttl(),
    );
    let refresh = fixtures::refresh_token("opaque-refresh-token");

    let record = SessionRecord::new(session.clone(), refresh.clone());

    assert_eq!(record.session(), &session);
    assert_eq!(record.refresh_token(), &refresh);
}

#[test]
fn refresh_token_rotation_input_makes_one_time_rotation_explicit() {
    let rotation = RefreshTokenRotation::new(
        SessionId::generate(),
        fixtures::refresh_token("old-refresh"),
        fixtures::refresh_token("new-refresh"),
    );

    assert_eq!(rotation.previous().as_str(), "old-refresh");
    assert_eq!(rotation.next().as_str(), "new-refresh");
}

#[test]
fn contract_supports_create_lookup_and_rotation() {
    let store = InMemorySessionStore::new();
    let session_id = SessionId::generate();
    let user_id = UserId::generate();
    let tenant_id = TenantId::generate();
    let session = fixtures::session(
        session_id,
        user_id,
        tenant_id,
        fixtures::canonical_issued_at(),
        fixtures::canonical_session_ttl(),
    );
    let initial = fixtures::refresh_token("refresh-1");
    let next = fixtures::refresh_token("refresh-2");

    store
        .create_session(SessionRecord::new(session.clone(), initial.clone()))
        .unwrap();

    assert_eq!(
        store
            .find_by_refresh_token(&initial)
            .unwrap()
            .unwrap()
            .session()
            .id(),
        session_id
    );

    store
        .rotate_refresh_token(RefreshTokenRotation::new(
            session_id,
            initial.clone(),
            next.clone(),
        ))
        .unwrap();

    assert!(store.find_by_refresh_token(&initial).unwrap().is_none());
    assert_eq!(
        store
            .find_by_refresh_token(&next)
            .unwrap()
            .unwrap()
            .session()
            .id(),
        session_id
    );
}

#[test]
fn contract_supports_revoke_one_and_tenant_scoped_revoke_all() {
    let store = InMemorySessionStore::new();
    let tenant_a = TenantId::generate();
    let tenant_b = TenantId::generate();
    let user_id = UserId::generate();
    let other_user_id = UserId::generate();

    let session_a1 = fixtures::session(
        SessionId::generate(),
        user_id,
        tenant_a,
        fixtures::canonical_issued_at(),
        fixtures::canonical_session_ttl(),
    );
    let session_a2 = fixtures::session(
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
    let session_other_user = fixtures::session(
        SessionId::generate(),
        other_user_id,
        tenant_a,
        fixtures::canonical_issued_at(),
        fixtures::canonical_session_ttl(),
    );

    let refresh_a1 = fixtures::refresh_token("tenant-a-refresh-1");
    let refresh_a2 = fixtures::refresh_token("tenant-a-refresh-2");
    let refresh_b = fixtures::refresh_token("tenant-b-refresh");
    let refresh_other_user = fixtures::refresh_token("other-user-refresh");

    store
        .create_session(SessionRecord::new(session_a1.clone(), refresh_a1.clone()))
        .unwrap();
    store
        .create_session(SessionRecord::new(session_a2.clone(), refresh_a2.clone()))
        .unwrap();
    store
        .create_session(SessionRecord::new(session_b.clone(), refresh_b.clone()))
        .unwrap();
    store
        .create_session(SessionRecord::new(
            session_other_user.clone(),
            refresh_other_user.clone(),
        ))
        .unwrap();

    store.revoke_session(session_a1.id()).unwrap();

    assert!(store.find_by_refresh_token(&refresh_a1).unwrap().is_none());

    store.revoke_all_for_user(tenant_a, user_id).unwrap();

    assert!(store.find_by_refresh_token(&refresh_a2).unwrap().is_none());
    assert!(store.find_by_refresh_token(&refresh_b).unwrap().is_some());
    assert!(
        store
            .find_by_refresh_token(&refresh_other_user)
            .unwrap()
            .is_some()
    );
}

#[test]
fn ports_module_session_store_export_remains_usable() {
    fn assert_session_store_trait<T: SessionStore>() {}

    let _record_type: Option<SessionRecord> = None;
    let _rotation_type: Option<RefreshTokenRotation> = None;

    assert_session_store_trait::<InMemorySessionStore>();
}
