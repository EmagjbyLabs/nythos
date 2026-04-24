use nythos_core::{
    AccessToken, AuthError, Claims, Email, LoginInput, LoginService, NewUser, NythosResult,
    Password, PasswordHash, PasswordHasher, Permission, RefreshToken, RefreshTokenRotation, Role,
    RoleAssignment, RoleAssignmentInput, RoleId, RoleRepository, SessionId, SessionRecord,
    SessionStore, TenantId, TokenPurpose, TokenSigner, User, UserCredentials, UserId,
    UserRepository, UserStatus,
};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    rc::Rc,
    time::{Duration, SystemTime},
};

type UserStore = BTreeMap<(TenantId, UserId), (User, PasswordHash)>;
type SessionStoreMap = BTreeMap<String, SessionRecord>;
type RoleStore = BTreeMap<(TenantId, RoleId), Role>;
type AssignmentStore = BTreeMap<(TenantId, UserId), Vec<RoleAssignment>>;

#[derive(Clone)]
struct InMemoryUserRepository {
    users: Rc<RefCell<UserStore>>,
}

impl InMemoryUserRepository {
    fn new() -> Self {
        Self {
            users: Rc::new(RefCell::new(BTreeMap::new())),
        }
    }
}

impl UserRepository for InMemoryUserRepository {
    fn find_by_email(&self, tenant_id: TenantId, email: &Email) -> NythosResult<Option<User>> {
        Ok(self
            .users
            .borrow()
            .iter()
            .find(|((stored_tenant, _), (user, _))| {
                *stored_tenant == tenant_id && user.email() == email
            })
            .map(|(_, (user, _))| user.clone()))
    }

    fn find_by_id(&self, tenant_id: TenantId, user_id: UserId) -> NythosResult<Option<User>> {
        Ok(self
            .users
            .borrow()
            .get(&(tenant_id, user_id))
            .map(|(user, _)| user.clone()))
    }

    fn find_credentials_by_email(
        &self,
        tenant_id: TenantId,
        email: &Email,
    ) -> NythosResult<Option<UserCredentials>> {
        Ok(self
            .users
            .borrow()
            .iter()
            .find(|((stored_tenant, _), (user, _))| {
                *stored_tenant == tenant_id && user.email() == email
            })
            .map(|(_, (user, hash))| UserCredentials::new(user.clone(), hash.clone())))
    }

    fn create(
        &self,
        tenant_id: TenantId,
        new_user: NewUser,
        password_hash: PasswordHash,
    ) -> NythosResult<User> {
        let user = User::new(
            UserId::generate(),
            new_user.into_email(),
            SystemTime::UNIX_EPOCH,
        );

        self.users
            .borrow_mut()
            .insert((tenant_id, user.id()), (user.clone(), password_hash));

        Ok(user)
    }

    fn update_status(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        status: UserStatus,
    ) -> NythosResult<()> {
        let mut users = self.users.borrow_mut();
        let (user, _) = users
            .get_mut(&(tenant_id, user_id))
            .ok_or(AuthError::UserNotFound)?;
        user.set_status(status);
        Ok(())
    }
}

#[derive(Default)]
struct FakePasswordHasher;

impl PasswordHasher for FakePasswordHasher {
    fn hash(&self, password: &Password) -> NythosResult<PasswordHash> {
        PasswordHash::new(format!("argon2id${}", password.as_str()))
    }

    fn verify(&self, password: &Password, hash: &PasswordHash) -> NythosResult<bool> {
        Ok(hash.as_str() == format!("argon2id${}", password.as_str()))
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

#[derive(Clone)]
struct InMemorySessionStore {
    records: Rc<RefCell<SessionStoreMap>>,
}

impl InMemorySessionStore {
    fn new() -> Self {
        Self {
            records: Rc::new(RefCell::new(BTreeMap::new())),
        }
    }
}

impl SessionStore for InMemorySessionStore {
    fn create_session(&self, record: SessionRecord) -> NythosResult<()> {
        self.records
            .borrow_mut()
            .insert(record.refresh_token().as_str().to_owned(), record);
        Ok(())
    }

    fn find_by_refresh_token(
        &self,
        refresh_token: &RefreshToken,
    ) -> NythosResult<Option<SessionRecord>> {
        Ok(self.records.borrow().get(refresh_token.as_str()).cloned())
    }

    fn rotate_refresh_token(&self, _rotation: RefreshTokenRotation) -> NythosResult<()> {
        Ok(())
    }

    fn revoke_session(&self, _session_id: SessionId) -> NythosResult<()> {
        Ok(())
    }

    fn revoke_all_for_user(&self, _tenant_id: TenantId, _user_id: UserId) -> NythosResult<()> {
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
        SystemTime::UNIX_EPOCH,
        Duration::from_secs(300),
        Duration::from_secs(600),
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

    let password_hash = hasher
        .hash(&Password::new("super-secret-password").unwrap())
        .unwrap();
    users
        .create(
            tenant_id,
            NewUser::new(Email::parse("person@example.com").unwrap()),
            password_hash,
        )
        .unwrap();

    let service = LoginService::new(&users, &roles, &sessions, &hasher, &signer);

    let result = service.login(LoginInput::new(
        tenant_id,
        "person@example.com".to_owned(),
        "wrong-password".to_owned(),
        SystemTime::UNIX_EPOCH,
        Duration::from_secs(300),
        Duration::from_secs(600),
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

    let password_hash = hasher
        .hash(&Password::new("super-secret-password").unwrap())
        .unwrap();
    let user = users
        .create(
            tenant_id,
            NewUser::new(Email::parse("person@example.com").unwrap()),
            password_hash,
        )
        .unwrap();

    users
        .update_status(tenant_id, user.id(), UserStatus::Locked)
        .unwrap();

    let service = LoginService::new(&users, &roles, &sessions, &hasher, &signer);

    let result = service.login(LoginInput::new(
        tenant_id,
        "person@example.com".to_owned(),
        "super-secret-password".to_owned(),
        SystemTime::UNIX_EPOCH,
        Duration::from_secs(300),
        Duration::from_secs(600),
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

    let password_hash = hasher
        .hash(&Password::new("super-secret-password").unwrap())
        .unwrap();
    let user = users
        .create(
            tenant_id,
            NewUser::new(Email::parse("person@example.com").unwrap()),
            password_hash,
        )
        .unwrap();

    let role = Role::new(
        RoleId::generate(),
        tenant_id,
        "operator",
        [Permission::new("shipments.read").unwrap()],
    )
    .unwrap();

    roles.insert_role(role.clone());
    roles
        .assign_role(RoleAssignmentInput::new(tenant_id, user.id(), role.id()))
        .unwrap();

    let service = LoginService::new(&users, &roles, &sessions, &hasher, &signer);

    let result = service
        .login(LoginInput::new(
            tenant_id,
            "person@example.com".to_owned(),
            "super-secret-password".to_owned(),
            SystemTime::UNIX_EPOCH,
            Duration::from_secs(300),
            Duration::from_secs(600),
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
