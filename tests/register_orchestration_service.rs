use nythos_core::{
    AccessToken, AuthError, Claims, Email, NewUser, NythosResult, Password, PasswordHash,
    PasswordHasher, RefreshToken, RefreshTokenRotation, RegisterInput, RegisterService, SessionId,
    SessionRecord, SessionStore, TenantId, TokenSigner, User, UserId, UserRepository, UserStatus,
};

use std::{
    cell::RefCell,
    collections::BTreeMap,
    rc::Rc,
    time::{Duration, SystemTime},
};

type TestUserStore = BTreeMap<(TenantId, UserId), User>;
type TestSessionStoreMap = BTreeMap<String, SessionRecord>;

#[derive(Clone)]
struct InMemoryUserRepository {
    users: Rc<RefCell<TestUserStore>>,
}

impl InMemoryUserRepository {
    fn new() -> Self {
        Self {
            users: Rc::new(RefCell::new(BTreeMap::new())),
        }
    }
}

impl UserRepository for InMemoryUserRepository {
    fn find_by_email(
        &self,
        tenant_id: TenantId,
        email: &Email,
    ) -> crate::NythosResult<Option<User>> {
        Ok(self
            .users
            .borrow()
            .iter()
            .find(|((stored_tenant, _), user)| *stored_tenant == tenant_id && user.email() == email)
            .map(|(_, user)| user.clone()))
    }

    fn find_by_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> crate::NythosResult<Option<User>> {
        Ok(self.users.borrow().get(&(tenant_id, user_id)).cloned())
    }

    fn create(
        &self,
        tenant_id: TenantId,
        new_user: NewUser,
        _password_hash: PasswordHash,
    ) -> crate::NythosResult<User> {
        let user = User::new(
            UserId::generate(),
            new_user.into_email(),
            SystemTime::UNIX_EPOCH,
        );

        self.users
            .borrow_mut()
            .insert((tenant_id, user.id()), user.clone());

        Ok(user)
    }

    fn update_status(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        status: UserStatus,
    ) -> crate::NythosResult<()> {
        let mut users = self.users.borrow_mut();
        let user = users
            .get_mut(&(tenant_id, user_id))
            .ok_or(AuthError::UserNotFound)?;
        user.set_status(status);
        Ok(())
    }
}

#[derive(Default)]
struct FakePasswordHasher;

impl PasswordHasher for FakePasswordHasher {
    fn hash(&self, password: &Password) -> crate::NythosResult<PasswordHash> {
        PasswordHash::new(format!("argon2id${}", password.as_str()))
    }

    fn verify(&self, password: &Password, hash: &PasswordHash) -> crate::NythosResult<bool> {
        Ok(hash.as_str() == format!("argon2id${}", password.as_str()))
    }
}

#[derive(Default)]
struct FakeTokenSigner;

impl TokenSigner for FakeTokenSigner {
    fn sign(&self, claims: &Claims) -> crate::NythosResult<AccessToken> {
        AccessToken::new(format!(
            "signed:{}:{}",
            claims.subject(),
            claims.tenant_id()
        ))
    }

    fn verify(&self, token: &AccessToken) -> crate::NythosResult<Claims> {
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

#[derive(Clone)]
struct InMemorySessionStore {
    records: Rc<RefCell<TestSessionStoreMap>>,
}

impl InMemorySessionStore {
    fn new() -> Self {
        Self {
            records: Rc::new(RefCell::new(BTreeMap::new())),
        }
    }
}

impl SessionStore for InMemorySessionStore {
    fn create_session(&self, record: SessionRecord) -> crate::NythosResult<()> {
        self.records
            .borrow_mut()
            .insert(record.refresh_token().as_str().to_owned(), record);
        Ok(())
    }

    fn find_by_refresh_token(
        &self,
        refresh_token: &RefreshToken,
    ) -> crate::NythosResult<Option<SessionRecord>> {
        Ok(self.records.borrow().get(refresh_token.as_str()).cloned())
    }

    fn rotate_refresh_token(
        &self,
        _rotation: crate::RefreshTokenRotation,
    ) -> crate::NythosResult<()> {
        Ok(())
    }

    fn revoke_session(&self, _session_id: SessionId) -> crate::NythosResult<()> {
        Ok(())
    }

    fn revoke_all_for_user(
        &self,
        _tenant_id: TenantId,
        _user_id: UserId,
    ) -> crate::NythosResult<()> {
        Ok(())
    }
}

#[test]
fn register_validates_email_and_password_through_core_value_objects() {
    let users = InMemoryUserRepository::new();
    let sessions = InMemorySessionStore::new();
    let hasher = FakePasswordHasher;
    let signer = FakeTokenSigner;
    let service = RegisterService::new(&users, &sessions, &hasher, &signer);

    let result = service.register(RegisterInput::new(
        TenantId::generate(),
        "not-an-email".to_owned(),
        "short".to_owned(),
        SystemTime::UNIX_EPOCH,
        Duration::from_secs(300),
        Duration::from_secs(600),
    ));

    assert!(matches!(result, Err(AuthError::ValidationError(_))));
}

#[test]
fn register_enforces_tenant_scoped_duplicate_email_checks() {
    let users = InMemoryUserRepository::new();
    let sessions = InMemorySessionStore::new();
    let hasher = FakePasswordHasher;
    let signer = FakeTokenSigner;
    let service = RegisterService::new(&users, &sessions, &hasher, &signer);
    let tenant_id = TenantId::generate();

    service
        .register(RegisterInput::new(
            tenant_id,
            "person@example.com".to_owned(),
            "super-secret-password".to_owned(),
            SystemTime::UNIX_EPOCH,
            Duration::from_secs(300),
            Duration::from_secs(600),
        ))
        .unwrap();

    let duplicate = service.register(RegisterInput::new(
        tenant_id,
        "person@example.com".to_owned(),
        "another-secret-password".to_owned(),
        SystemTime::UNIX_EPOCH,
        Duration::from_secs(300),
        Duration::from_secs(600),
    ));

    assert!(matches!(duplicate, Err(AuthError::ValidationError(_))));
}

#[test]
fn register_returns_signed_auth_material_when_auto_sign_in_is_enabled() {
    let users = InMemoryUserRepository::new();
    let sessions = InMemorySessionStore::new();
    let hasher = FakePasswordHasher;
    let signer = FakeTokenSigner;
    let service = RegisterService::new(&users, &sessions, &hasher, &signer);
    let tenant_id = TenantId::generate();

    let result = service
        .register(RegisterInput::new(
            tenant_id,
            "person@example.com".to_owned(),
            "super-secret-password".to_owned(),
            SystemTime::UNIX_EPOCH,
            Duration::from_secs(300),
            Duration::from_secs(600),
        ))
        .unwrap();

    let auth = result.auth().unwrap();

    assert_eq!(result.user().id(), auth.user().id());
    assert_eq!(auth.session().tenant_id(), tenant_id);
    assert_eq!(auth.claims().tenant_id(), tenant_id);
    assert!(!auth.access_token().as_str().is_empty());
    assert!(!auth.refresh_token().as_str().is_empty());

    let stored = sessions
        .find_by_refresh_token(auth.refresh_token())
        .unwrap();
    assert!(stored.is_some());
}

#[test]
fn register_can_return_user_without_auth_material() {
    let users = InMemoryUserRepository::new();
    let sessions = InMemorySessionStore::new();
    let hasher = FakePasswordHasher;
    let signer = FakeTokenSigner;
    let service = RegisterService::new(&users, &sessions, &hasher, &signer);

    let result = service
        .register(
            RegisterInput::new(
                TenantId::generate(),
                "person@example.com".to_owned(),
                "super-secret-password".to_owned(),
                SystemTime::UNIX_EPOCH,
                Duration::from_secs(300),
                Duration::from_secs(600),
            )
            .with_auto_sign_in(false),
        )
        .unwrap();

    assert!(result.auth().is_none());
}
