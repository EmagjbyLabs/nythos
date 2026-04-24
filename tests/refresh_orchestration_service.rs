use nythos_core::{
    AccessToken, AuthError, Claims, NythosResult, Permission, RefreshInput, RefreshService,
    RefreshToken, RefreshTokenRotation, RevocationChecker, Role, RoleAssignment,
    RoleAssignmentInput, RoleId, RoleRepository, Session, SessionId, SessionRecord, SessionStore,
    TenantId, TokenPurpose, TokenSigner, UserId,
};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
    time::{Duration, SystemTime},
};

type SessionStoreMap = BTreeMap<SessionId, SessionRecord>;
type RefreshIndex = BTreeMap<String, SessionId>;
type RoleStore = BTreeMap<(TenantId, RoleId), Role>;
type AssignmentStore = BTreeMap<(TenantId, UserId), Vec<RoleAssignment>>;

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

    fn rotate_refresh_token(&self, rotation: RefreshTokenRotation) -> NythosResult<()> {
        let (session_id, previous, next) = rotation.into_parts();

        let mut index = self.refresh_index.borrow_mut();
        let mut records = self.records.borrow_mut();

        let record = records
            .get_mut(&session_id)
            .ok_or(AuthError::SessionRevoked)?;

        let indexed_session = index
            .get(previous.as_str())
            .copied()
            .ok_or(AuthError::InvalidCredentials)?;

        if indexed_session != session_id {
            return Err(AuthError::InvalidCredentials);
        }

        index.remove(previous.as_str());
        index.insert(next.as_str().to_owned(), session_id);
        *record = SessionRecord::new(record.session().clone(), next);

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

#[derive(Clone)]
struct InMemoryRoleRepository {
    roles: Rc<RefCell<RoleStore>>,
    assignments: Rc<RefCell<AssignmentStore>>,
}

impl InMemoryRoleRepository {
    fn new() -> Self {
        Self {
            roles: Rc::new(RefCell::new(BTreeMap::new())),
            assignments: Rc::new(RefCell::new(BTreeMap::new())),
        }
    }

    fn insert_role(&self, role: Role) {
        self.roles
            .borrow_mut()
            .insert((role.tenant_id(), role.id()), role);
    }
}

impl RoleRepository for InMemoryRoleRepository {
    fn assign_role(&self, input: RoleAssignmentInput) -> NythosResult<()> {
        self.assignments
            .borrow_mut()
            .entry((input.tenant_id(), input.user_id()))
            .or_default()
            .push(input.into_assignment());
        Ok(())
    }

    fn revoke_role(&self, input: RoleAssignmentInput) -> NythosResult<()> {
        if let Some(entries) = self
            .assignments
            .borrow_mut()
            .get_mut(&(input.tenant_id(), input.user_id()))
        {
            entries.retain(|assignment| assignment.role_id() != input.role_id());
        }
        Ok(())
    }

    fn get_roles_for_user(&self, tenant_id: TenantId, user_id: UserId) -> NythosResult<Vec<Role>> {
        let assignments = self.assignments.borrow();
        let roles = self.roles.borrow();

        Ok(assignments
            .get(&(tenant_id, user_id))
            .into_iter()
            .flat_map(|items| items.iter())
            .filter_map(|assignment| roles.get(&(tenant_id, assignment.role_id())).cloned())
            .collect())
    }
}

#[derive(Default)]
struct FakeTokenSigner;

impl TokenSigner for FakeTokenSigner {
    fn sign(&self, claims: &Claims) -> NythosResult<AccessToken> {
        AccessToken::new(format!(
            "signed:{}:{}",
            claims.subject(),
            claims.tenant_id()
        ))
    }

    fn verify(&self, token: &AccessToken) -> NythosResult<Claims> {
        if token.as_str().is_empty() {
            return Err(AuthError::InvalidCredentials);
        }

        Claims::access(
            UserId::generate(),
            TenantId::generate(),
            SystemTime::UNIX_EPOCH,
            Duration::from_secs(300),
        )
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
fn refresh_rejects_unknown_refresh_tokens() {
    let sessions = InMemorySessionStore::new();
    let roles = InMemoryRoleRepository::new();
    let signer = FakeTokenSigner;
    let checker = FakeRevocationChecker::default();
    let service = RefreshService::new(&sessions, &roles, &signer, &checker);

    let result = service.refresh(RefreshInput::new(
        "missing-refresh".to_owned(),
        SystemTime::UNIX_EPOCH,
        Duration::from_secs(300),
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

    let session = Session::with_ttl(
        SessionId::generate(),
        UserId::generate(),
        TenantId::generate(),
        SystemTime::UNIX_EPOCH,
        Duration::from_secs(600),
    )
    .unwrap();
    let refresh = RefreshToken::new("revoked-refresh".to_owned()).unwrap();

    sessions
        .create_session(SessionRecord::new(session.clone(), refresh.clone()))
        .unwrap();
    sessions.revoke_session(session.id()).unwrap();

    let result = service.refresh(RefreshInput::new(
        refresh.as_str().to_owned(),
        SystemTime::UNIX_EPOCH + Duration::from_secs(10),
        Duration::from_secs(300),
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

    let issued_at = SystemTime::UNIX_EPOCH;
    let session = Session::with_ttl(
        SessionId::generate(),
        UserId::generate(),
        TenantId::generate(),
        issued_at,
        Duration::from_secs(60),
    )
    .unwrap();
    let refresh = RefreshToken::new("expired-refresh".to_owned()).unwrap();

    sessions
        .create_session(SessionRecord::new(session, refresh.clone()))
        .unwrap();

    let result = service.refresh(RefreshInput::new(
        refresh.as_str().to_owned(),
        issued_at + Duration::from_secs(60),
        Duration::from_secs(300),
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
    let role = Role::new(
        RoleId::generate(),
        tenant_id,
        "operator",
        [Permission::new("shipments.read").unwrap()],
    )
    .unwrap();

    roles.insert_role(role.clone());
    roles
        .assign_role(RoleAssignmentInput::new(tenant_id, user_id, role.id()))
        .unwrap();

    let issued_at = SystemTime::UNIX_EPOCH;
    let session = Session::with_ttl(
        SessionId::generate(),
        user_id,
        tenant_id,
        issued_at,
        Duration::from_secs(600),
    )
    .unwrap();
    let initial_refresh = RefreshToken::new("initial-refresh".to_owned()).unwrap();

    sessions
        .create_session(SessionRecord::new(session.clone(), initial_refresh.clone()))
        .unwrap();

    let result = service
        .refresh(RefreshInput::new(
            initial_refresh.as_str().to_owned(),
            issued_at + Duration::from_secs(10),
            Duration::from_secs(300),
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

    let session = Session::with_ttl(
        SessionId::generate(),
        UserId::generate(),
        TenantId::generate(),
        SystemTime::UNIX_EPOCH,
        Duration::from_secs(600),
    )
    .unwrap();
    let refresh = RefreshToken::new("checker-refresh".to_owned()).unwrap();

    sessions
        .create_session(SessionRecord::new(session.clone(), refresh.clone()))
        .unwrap();

    checker.revoked.borrow_mut().insert(session.id());

    let result = service.refresh(RefreshInput::new(
        refresh.as_str().to_owned(),
        SystemTime::UNIX_EPOCH + Duration::from_secs(10),
        Duration::from_secs(300),
    ));

    assert!(matches!(result, Err(AuthError::SessionRevoked)));
}
