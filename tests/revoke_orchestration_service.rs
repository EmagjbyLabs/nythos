use nythos_core::{
    AuthError, NythosResult, RefreshToken, RevocationChecker, RevokeAllSessionsInput,
    RevokeAllSessionsService, RevokeSessionInput, RevokeSessionService, Session, SessionId,
    SessionRecord, SessionStore, TenantId, UserId,
};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
    time::{Duration, SystemTime},
};

type SessionStoreMap = BTreeMap<SessionId, SessionRecord>;
type RefreshIndex = BTreeMap<String, SessionId>;

#[derive(Clone)]
struct InMemorySessionStore {
    records: Rc<RefCell<SessionStoreMap>>,
    refresh_index: Rc<RefCell<RefreshIndex>>,
}

impl InMemorySessionStore {
    fn new() -> Self {
        Self {
            records: Rc::new(RefCell::new(BTreeMap::new())),
            refresh_index: Rc::new(RefCell::new(BTreeMap::new())),
        }
    }
}

impl SessionStore for InMemorySessionStore {
    fn create_session(&self, record: SessionRecord) -> NythosResult<()> {
        let session_id = record.session().id();
        let refresh_key = record.refresh_token().as_str().to_owned();

        self.refresh_index
            .borrow_mut()
            .insert(refresh_key, session_id);
        self.records.borrow_mut().insert(session_id, record);
        Ok(())
    }

    fn find_by_refresh_token(
        &self,
        refresh_token: &RefreshToken,
    ) -> NythosResult<Option<SessionRecord>> {
        let index = self.refresh_index.borrow();
        let records = self.records.borrow();

        Ok(index
            .get(refresh_token.as_str())
            .and_then(|session_id| records.get(session_id))
            .cloned())
    }

    fn rotate_refresh_token(
        &self,
        _rotation: nythos_core::RefreshTokenRotation,
    ) -> NythosResult<()> {
        Ok(())
    }

    fn revoke_session(&self, session_id: SessionId) -> NythosResult<()> {
        let mut records = self.records.borrow_mut();
        let record = records
            .get_mut(&session_id)
            .ok_or(AuthError::SessionRevoked)?;

        let refresh_key = record.refresh_token().as_str().to_owned();
        let mut session = record.session().clone();
        session.revoke();
        *record = SessionRecord::new(session, record.refresh_token().clone());
        self.refresh_index.borrow_mut().remove(&refresh_key);

        Ok(())
    }

    fn revoke_all_for_user(&self, tenant_id: TenantId, user_id: UserId) -> NythosResult<()> {
        let mut records = self.records.borrow_mut();
        let mut index = self.refresh_index.borrow_mut();

        for record in records.values_mut() {
            if record.session().tenant_id() == tenant_id && record.session().user_id() == user_id {
                let refresh_key = record.refresh_token().as_str().to_owned();
                let mut session = record.session().clone();
                session.revoke();
                *record = SessionRecord::new(session, record.refresh_token().clone());
                index.remove(&refresh_key);
            }
        }

        Ok(())
    }
}

#[derive(Default)]
struct FakeRevocationChecker {
    revoked: RefCell<BTreeSet<SessionId>>,
}

impl RevocationChecker for FakeRevocationChecker {
    fn is_revoked(&self, session_id: SessionId) -> NythosResult<bool> {
        Ok(self.revoked.borrow().contains(&session_id))
    }
}

#[test]
fn revoke_single_session_updates_future_lookup_state() {
    let store = InMemorySessionStore::new();
    let checker = FakeRevocationChecker::default();
    let service = RevokeSessionService::new(&store, &checker);

    let session = Session::with_ttl(
        SessionId::generate(),
        UserId::generate(),
        TenantId::generate(),
        SystemTime::UNIX_EPOCH,
        Duration::from_secs(600),
    )
    .unwrap();
    let refresh = RefreshToken::new("session-refresh".to_owned()).unwrap();

    store
        .create_session(SessionRecord::new(session.clone(), refresh.clone()))
        .unwrap();

    let result = service
        .revoke(RevokeSessionInput::new(session.id()))
        .unwrap();

    assert!(result.revoked());
    assert!(store.find_by_refresh_token(&refresh).unwrap().is_none());
}

#[test]
fn revoke_single_session_can_short_circuit_already_revoked_state() {
    let store = InMemorySessionStore::new();
    let checker = FakeRevocationChecker::default();
    let service = RevokeSessionService::new(&store, &checker);
    let session_id = SessionId::generate();

    checker.revoked.borrow_mut().insert(session_id);

    let result = service.revoke(RevokeSessionInput::new(session_id)).unwrap();

    assert!(!result.revoked());
}

#[test]
fn revoke_all_is_tenant_scoped() {
    let store = InMemorySessionStore::new();
    let service = RevokeAllSessionsService::new(&store);

    let tenant_a = TenantId::generate();
    let tenant_b = TenantId::generate();
    let user_id = UserId::generate();

    let session_a = Session::with_ttl(
        SessionId::generate(),
        user_id,
        tenant_a,
        SystemTime::UNIX_EPOCH,
        Duration::from_secs(600),
    )
    .unwrap();
    let session_b = Session::with_ttl(
        SessionId::generate(),
        user_id,
        tenant_b,
        SystemTime::UNIX_EPOCH,
        Duration::from_secs(600),
    )
    .unwrap();

    let refresh_a = RefreshToken::new("tenant-a-refresh".to_owned()).unwrap();
    let refresh_b = RefreshToken::new("tenant-b-refresh".to_owned()).unwrap();

    store
        .create_session(SessionRecord::new(session_a, refresh_a.clone()))
        .unwrap();
    store
        .create_session(SessionRecord::new(session_b, refresh_b.clone()))
        .unwrap();

    let result = service
        .revoke_all(RevokeAllSessionsInput::new(tenant_a, user_id))
        .unwrap();

    assert!(result.revoked());
    assert!(store.find_by_refresh_token(&refresh_a).unwrap().is_none());
    assert!(store.find_by_refresh_token(&refresh_b).unwrap().is_some());
}

#[test]
fn revoke_single_session_surfaces_missing_session_failures() {
    let store = InMemorySessionStore::new();
    let checker = FakeRevocationChecker::default();
    let service = RevokeSessionService::new(&store, &checker);

    let result = service.revoke(RevokeSessionInput::new(SessionId::generate()));

    assert!(matches!(result, Err(AuthError::SessionRevoked)));
}
