//! Pure trait contracts required by `nythos-core`.
//!
//! Implementations of these ports live outside the core crate.

use crate::{
    AccessToken, Claims, Email, NythosResult, Password, PasswordHash, RefreshToken, Role,
    RoleAssignment, RoleId, Session, SessionId, TenantId, User, UserId, UserStatus,
};

/// Domain-facing input used when creating a new user inside a tenant.
///
/// This keeps repository contracts focused on core data rather than storage
/// payloads or transport DTOs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewUser {
    email: Email,
}

impl NewUser {
    pub fn new(email: Email) -> Self {
        Self { email }
    }

    pub fn email(&self) -> &Email {
        &self.email
    }

    pub fn into_email(self) -> Email {
        self.email
    }
}

/// Tenant-scoped role assignment command.
///
/// This keeps assignment/revocation inputs explicit and avoids ambiguous
/// multi-argument method signatures in orchestration code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleAssignmentInput {
    tenant_id: TenantId,
    user_id: UserId,
    role_id: RoleId,
}

impl RoleAssignmentInput {
    pub const fn new(tenant_id: TenantId, user_id: UserId, role_id: RoleId) -> Self {
        Self {
            tenant_id,
            user_id,
            role_id,
        }
    }

    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    pub const fn user_id(&self) -> UserId {
        self.user_id
    }

    pub const fn role_id(&self) -> RoleId {
        self.role_id
    }

    pub const fn into_assignment(self) -> RoleAssignment {
        RoleAssignment::new(self.tenant_id, self.user_id, self.role_id)
    }
}

/// Session creation payload used by auth services when persisting a fresh session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    session: Session,
    refresh_token: RefreshToken,
}

impl SessionRecord {
    pub fn new(session: Session, refresh_token: RefreshToken) -> Self {
        Self {
            session,
            refresh_token,
        }
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn refresh_token(&self) -> &RefreshToken {
        &self.refresh_token
    }

    pub fn into_parts(self) -> (Session, RefreshToken) {
        (self.session, self.refresh_token)
    }
}

/// Refresh-token rotation command.
///
/// Makes one-time rotation semantics explicit at the contract boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshTokenRotation {
    session_id: SessionId,
    previous: RefreshToken,
    next: RefreshToken,
}

impl RefreshTokenRotation {
    pub fn new(session_id: SessionId, previous: RefreshToken, next: RefreshToken) -> Self {
        Self {
            session_id,
            previous,
            next,
        }
    }

    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn previous(&self) -> &RefreshToken {
        &self.previous
    }

    pub fn next(&self) -> &RefreshToken {
        &self.next
    }

    pub fn into_parts(self) -> (SessionId, RefreshToken, RefreshToken) {
        (self.session_id, self.previous, self.next)
    }
}

/// Tenant-scoped user repository contract used by registration and login flows.
///
/// All lookup and mutation methods that depend on tenant context require an
/// explicit `TenantId`. Implementations must not perform cross-tenant lookups
/// behind the scenes.
///
/// Duplicate-user and not-found behavior should be expressed through the core
/// result model and return shapes, rather than leaking database-specific errors.
pub trait UserRepository {
    /// Finds a user by normalized email within a specific tenant.
    fn find_by_email(&self, tenant_id: TenantId, email: &Email) -> NythosResult<Option<User>>;

    /// Finds a user by ID within a specific tenant.
    fn find_by_id(&self, tenant_id: TenantId, user_id: UserId) -> NythosResult<Option<User>>;

    /// Creates a new user in the given tenant using an already-validated email
    /// and an already-produced password hash.
    ///
    /// Implementations should make duplicate handling explicit through the core
    /// error model.
    fn create(
        &self,
        tenant_id: TenantId,
        new_user: NewUser,
        password_hash: PasswordHash,
    ) -> NythosResult<User>;

    /// Updates a user's status within a specific tenant boundary.
    fn update_status(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        status: UserStatus,
    ) -> NythosResult<()>;
}

/// Tenant-scoped role repository contract used by login and refresh flows.
///
/// Every method is explicitly tenant-bound. Implementations must not introduce
/// global-role behavior or silently cross tenant boundaries.
///
/// This contract supports loading current RBAC state as well as assigning and
/// revoking user-role membership inside a tenant.
pub trait RoleRepository {
    /// Assigns a role to a user within the provided tenant boundary.
    fn assign_role(&self, input: RoleAssignmentInput) -> NythosResult<()>;

    /// Revokes a role from a user within the provided tenant boundary.
    fn revoke_role(&self, input: RoleAssignmentInput) -> NythosResult<()>;

    /// Loads all roles currently assigned to a user within one tenant.
    fn get_roles_for_user(&self, tenant_id: TenantId, user_id: UserId) -> NythosResult<Vec<Role>>;
}

/// Session store contract used by register, login, refresh, logout, and revoke flows.
///
/// Rotation semantics are explicit at the API boundary:
/// - sessions are created together with one opaque refresh token
/// - refresh-token lookup returns the owning session context
/// - successful rotation invalidates the previous refresh token in favor of the next one
/// - revoke-all is always tenant-scoped
pub trait SessionStore {
    /// Persists a newly issued session together with its initial refresh token.
    fn create_session(&self, record: SessionRecord) -> NythosResult<()>;

    /// Finds the session currently associated with an opaque refresh token.
    fn find_by_refresh_token(
        &self,
        refresh_token: &RefreshToken,
    ) -> NythosResult<Option<SessionRecord>>;

    /// Rotates a refresh token for a specific session.
    ///
    /// Implementations should treat the `previous` token as invalid after a
    /// successful rotation.
    fn rotate_refresh_token(&self, rotation: RefreshTokenRotation) -> NythosResult<()>;

    /// Revokes a single session by ID.
    fn revoke_session(&self, session_id: SessionId) -> NythosResult<()>;

    /// Revokes all sessions owned by a user within a specific tenant.
    fn revoke_all_for_user(&self, tenant_id: TenantId, user_id: UserId) -> NythosResult<()>;
}

/// Pasword hashing port used by registration and login flows.
///
/// The expected outer implementation is Argon2id. This contract exists to keep
/// the core infrastructure-agnostic, not to treat weak hashing algorithms as
/// equivalent alternatives.
pub trait PasswordHasher {
    /// Hashes a validated raw password into a stored password-hash value.
    fn hash(&self, password: &Password) -> NythosResult<PasswordHash>;

    /// Verifies a validated raw password against a stored hash.
    fn verify(&self, password: &Password, hash: &PasswordHash) -> NythosResult<bool>;
}

/// Token signing port used to issue and verify signed access tokens.
///
/// This contract operates on core domain types only.  It must not expose HTTP,
/// bearer-header, or concrete JWT-library types at the boundary.
pub trait TokenSigner {
    /// Signs a structured claim set into an access token.
    fn sign(&self, claims: &Claims) -> NythosResult<AccessToken>;

    /// Verifies an access token and returns the structured claims it carries.
    fn verify(&self, token: &AccessToken) -> NythosResult<Claims>;
}

/// Revocation-checking port used by authenticated request flows.
///
/// Outer layers typically verify the access token first, then use this contract
/// to reject requests whose owning session has been revoked.
pub trait RevocationChecker {
    /// Returns whether the provided session has been revoked.
    fn is_revoked(&self, session_id: SessionId) -> NythosResult<bool>;
}

#[cfg(test)]
mod tests {
    use super::{
        NewUser, RefreshTokenRotation, RoleAssignmentInput, RoleRepository, SessionRecord,
        SessionStore, UserRepository,
    };
    use crate::{
        AccessToken, AuthError, Claims, Email, Password, PasswordHash, Permission, RefreshToken,
        Role, RoleAssignment, RoleId, Session, SessionId, TenantId, User, UserId, UserStatus,
        ports::{PasswordHasher, RevocationChecker, TokenSigner},
    };
    use std::{
        cell::RefCell,
        collections::{BTreeMap, BTreeSet},
        rc::Rc,
        time::SystemTime,
    };

    type TestStore = BTreeMap<(TenantId, UserId), (User, PasswordHash)>;

    #[derive(Clone)]
    struct InMemoryUserRepository {
        users: Rc<RefCell<TestStore>>,
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
                .find(|((stored_tenant, _), (user, _))| {
                    *stored_tenant == tenant_id && user.email() == email
                })
                .map(|(_, (user, _))| user.clone()))
        }

        fn find_by_id(
            &self,
            tenant_id: TenantId,
            user_id: UserId,
        ) -> crate::NythosResult<Option<User>> {
            Ok(self
                .users
                .borrow()
                .get(&(tenant_id, user_id))
                .map(|(user, _)| user.clone()))
        }

        fn create(
            &self,
            tenant_id: TenantId,
            new_user: NewUser,
            password_hash: PasswordHash,
        ) -> crate::NythosResult<User> {
            if self.find_by_email(tenant_id, new_user.email())?.is_some() {
                return Err(AuthError::ValidationError(
                    "user with email already exists in tenant".to_owned(),
                ));
            }

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
        ) -> crate::NythosResult<()> {
            let mut users = self.users.borrow_mut();
            let (user, _) = users
                .get_mut(&(tenant_id, user_id))
                .ok_or(AuthError::UserNotFound)?;

            user.set_status(status);
            Ok(())
        }
    }

    #[test]
    fn new_user_wraps_domain_email() {
        let email = Email::parse("person@example.com").unwrap();
        let new_user = NewUser::new(email.clone());

        assert_eq!(new_user.email(), &email);
    }

    #[test]
    fn repository_lookups_are_tenant_scoped() {
        let repo = InMemoryUserRepository::new();
        let tenant_a = TenantId::generate();
        let tenant_b = TenantId::generate();
        let email = Email::parse("person@example.com").unwrap();

        let created = repo
            .create(
                tenant_a,
                NewUser::new(email.clone()),
                PasswordHash::new("hash".to_owned()).unwrap(),
            )
            .unwrap();

        assert!(repo.find_by_email(tenant_a, &email).unwrap().is_some());
        assert!(repo.find_by_email(tenant_b, &email).unwrap().is_none());
        assert!(repo.find_by_id(tenant_a, created.id()).unwrap().is_some());
    }

    #[test]
    fn duplicate_user_handling_is_expressible_through_core_errors() {
        let repo = InMemoryUserRepository::new();
        let tenant_id = TenantId::generate();
        let email = Email::parse("person@example.com").unwrap();

        repo.create(
            tenant_id,
            NewUser::new(email.clone()),
            PasswordHash::new("hash".to_owned()).unwrap(),
        )
        .unwrap();

        let result = repo.create(
            tenant_id,
            NewUser::new(email.clone()),
            PasswordHash::new("hash".to_owned()).unwrap(),
        );

        assert!(matches!(
            result,
            Err(AuthError::ValidationError(msg)) if msg.contains("already exists")
        ));
    }

    #[test]
    fn update_status_is_tenant_scoped_and_not_found_aware() {
        let repo = InMemoryUserRepository::new();
        let tenant_id = TenantId::generate();
        let other_tenant = TenantId::generate();

        let email = Email::parse("person@example.com").unwrap();
        let user = repo
            .create(
                tenant_id,
                NewUser::new(email.clone()),
                PasswordHash::new("hash".to_owned()).unwrap(),
            )
            .unwrap();

        repo.update_status(tenant_id, user.id(), UserStatus::Locked)
            .unwrap();

        let updated = repo.find_by_id(tenant_id, user.id()).unwrap().unwrap();
        assert_eq!(updated.status(), UserStatus::Locked);

        let result = repo.update_status(other_tenant, user.id(), UserStatus::Disabled);
        assert!(matches!(result, Err(AuthError::UserNotFound)));
    }

    // ROLES

    type TestRoleAssignments = BTreeMap<(TenantId, UserId), Vec<RoleAssignment>>;
    type TestRoles = BTreeMap<(TenantId, RoleId), Role>;

    #[derive(Clone)]
    struct InMemoryRoleRepository {
        assignments: Rc<RefCell<TestRoleAssignments>>,
        roles: Rc<RefCell<TestRoles>>,
    }

    impl InMemoryRoleRepository {
        fn new() -> Self {
            Self {
                assignments: Rc::new(RefCell::new(BTreeMap::new())),
                roles: Rc::new(RefCell::new(BTreeMap::new())),
            }
        }

        fn insert_role(&self, role: Role) {
            self.roles
                .borrow_mut()
                .insert((role.tenant_id(), role.id()), role);
        }
    }

    impl RoleRepository for InMemoryRoleRepository {
        fn assign_role(&self, input: RoleAssignmentInput) -> crate::NythosResult<()> {
            if !self
                .roles
                .borrow()
                .contains_key(&(input.tenant_id(), input.role_id()))
            {
                return Err(AuthError::ValidationError(
                    "role does not exist in tenant".to_owned(),
                ));
            }

            let mut assignments = self.assignments.borrow_mut();
            let entry = assignments
                .entry((input.tenant_id(), input.user_id()))
                .or_default();

            if entry.iter().any(|a| a.role_id() == input.role_id()) {
                return Err(AuthError::ValidationError(
                    "role already assigned to user in tenant".to_owned(),
                ));
            }

            entry.push(input.into_assignment());
            Ok(())
        }

        fn revoke_role(&self, input: RoleAssignmentInput) -> crate::NythosResult<()> {
            let mut assignments = self.assignments.borrow_mut();
            let entry = assignments
                .get_mut(&(input.tenant_id(), input.user_id()))
                .ok_or(AuthError::UserNotFound)?;

            let before = entry.len();
            entry.retain(|assignment| assignment.role_id() != input.role_id());

            if entry.len() == before {
                return Err(AuthError::ValidationError(
                    "role assignment not found in tenant".to_owned(),
                ));
            }

            Ok(())
        }

        fn get_roles_for_user(
            &self,
            tenant_id: TenantId,
            user_id: UserId,
        ) -> crate::NythosResult<Vec<Role>> {
            let assignments = self.assignments.borrow();
            let roles = self.roles.borrow();

            let result = assignments
                .get(&(tenant_id, user_id))
                .into_iter()
                .flat_map(|items| items.iter())
                .filter_map(|assignment| roles.get(&(tenant_id, assignment.role_id())).cloned())
                .collect();

            Ok(result)
        }
    }

    #[test]
    fn role_assignment_input_keeps_tenant_scope_explicit() {
        let input =
            RoleAssignmentInput::new(TenantId::generate(), UserId::generate(), RoleId::generate());

        let assignment = input.into_assignment();

        assert_eq!(assignment.tenant_id(), input.tenant_id());
        assert_eq!(assignment.user_id(), input.user_id());
        assert_eq!(assignment.role_id(), input.role_id());
    }

    #[test]
    fn role_repository_loads_roles_within_tenant_scope() {
        let repo = InMemoryRoleRepository::new();
        let tenant_id = TenantId::generate();
        let user_id = UserId::generate();

        let role = Role::new(
            RoleId::generate(),
            tenant_id,
            "operator",
            [Permission::new("shipments.read").unwrap()],
        )
        .unwrap();

        repo.insert_role(role.clone());
        repo.assign_role(RoleAssignmentInput::new(tenant_id, user_id, role.id()))
            .unwrap();

        let roles = repo.get_roles_for_user(tenant_id, user_id).unwrap();

        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].id(), role.id());
    }

    #[test]
    fn role_repository_rejects_cross_tenant_assignment() {
        let repo = InMemoryRoleRepository::new();
        let tenant_a = TenantId::generate();
        let tenant_b = TenantId::generate();
        let user_id = UserId::generate();

        let role = Role::new(
            RoleId::generate(),
            tenant_a,
            "operator",
            [Permission::new("shipments.read").unwrap()],
        )
        .unwrap();

        repo.insert_role(role.clone());

        let result = repo.assign_role(RoleAssignmentInput::new(tenant_b, user_id, role.id()));

        assert!(matches!(result, Err(AuthError::ValidationError(_))));
    }

    #[test]
    fn role_repository_revocation_is_testable_at_trait_boundary() {
        let repo = InMemoryRoleRepository::new();
        let tenant_id = TenantId::generate();
        let user_id = UserId::generate();

        let role = Role::new(
            RoleId::generate(),
            tenant_id,
            "operator",
            [Permission::new("shipments.read").unwrap()],
        )
        .unwrap();

        repo.insert_role(role.clone());

        let input = RoleAssignmentInput::new(tenant_id, user_id, role.id());
        repo.assign_role(input).unwrap();
        repo.revoke_role(input).unwrap();

        let roles = repo.get_roles_for_user(tenant_id, user_id).unwrap();
        assert!(roles.is_empty());
    }

    type TestSessionStoreMap = BTreeMap<SessionId, SessionRecord>;
    type TestRefreshIndex = BTreeMap<String, SessionId>;

    #[derive(Clone)]
    struct InMemorySessionStore {
        records: Rc<RefCell<TestSessionStoreMap>>,
        refresh_index: Rc<RefCell<TestRefreshIndex>>,
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
        fn create_session(&self, record: SessionRecord) -> crate::NythosResult<()> {
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
        ) -> crate::NythosResult<Option<SessionRecord>> {
            let index = self.refresh_index.borrow();
            let records = self.records.borrow();

            Ok(index
                .get(refresh_token.as_str())
                .and_then(|session_id| records.get(session_id))
                .cloned())
        }

        fn rotate_refresh_token(&self, rotation: RefreshTokenRotation) -> crate::NythosResult<()> {
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

        fn revoke_session(&self, session_id: SessionId) -> crate::NythosResult<()> {
            let mut records = self.records.borrow_mut();
            let record = records
                .get_mut(&session_id)
                .ok_or(AuthError::SessionRevoked)?;

            let refresh_key = record.refresh_token().as_str().to_owned();
            record.session.revoke();
            self.refresh_index.borrow_mut().remove(&refresh_key);

            Ok(())
        }

        fn revoke_all_for_user(
            &self,
            tenant_id: TenantId,
            user_id: UserId,
        ) -> crate::NythosResult<()> {
            let mut records = self.records.borrow_mut();
            let mut index = self.refresh_index.borrow_mut();

            for record in records.values_mut() {
                if record.session().tenant_id() == tenant_id
                    && record.session().user_id() == user_id
                {
                    let refresh_key = record.refresh_token().as_str().to_owned();
                    record.session.revoke();
                    index.remove(&refresh_key);
                }
            }

            Ok(())
        }
    }

    #[test]
    fn session_record_keeps_session_and_refresh_token_together() {
        let session = Session::with_ttl(
            SessionId::generate(),
            UserId::generate(),
            TenantId::generate(),
            SystemTime::UNIX_EPOCH,
            std::time::Duration::from_secs(60),
        )
        .unwrap();
        let refresh = RefreshToken::new("opaque-refresh-token").unwrap();

        let record = SessionRecord::new(session.clone(), refresh.clone());

        assert_eq!(record.session(), &session);
        assert_eq!(record.refresh_token(), &refresh);
    }

    #[test]
    fn refresh_token_rotation_input_makes_one_time_rotation_explicit() {
        let rotation = RefreshTokenRotation::new(
            SessionId::generate(),
            RefreshToken::new("old-refresh").unwrap(),
            RefreshToken::new("new-refresh").unwrap(),
        );

        assert_eq!(rotation.previous().as_str(), "old-refresh");
        assert_eq!(rotation.next().as_str(), "new-refresh");
    }

    #[test]
    fn session_store_supports_one_time_refresh_token_rotation() {
        let store = InMemorySessionStore::new();
        let session = Session::with_ttl(
            SessionId::generate(),
            UserId::generate(),
            TenantId::generate(),
            SystemTime::UNIX_EPOCH,
            std::time::Duration::from_secs(600),
        )
        .unwrap();

        let initial = RefreshToken::new("initial-refresh").unwrap();
        let next = RefreshToken::new("next-refresh").unwrap();

        store
            .create_session(SessionRecord::new(session.clone(), initial.clone()))
            .unwrap();

        store
            .rotate_refresh_token(RefreshTokenRotation::new(
                session.id(),
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
            session.id()
        );
    }

    #[test]
    fn revoke_all_is_explicitly_tenant_scoped() {
        let store = InMemorySessionStore::new();
        let tenant_a = TenantId::generate();
        let tenant_b = TenantId::generate();
        let user_id = UserId::generate();

        let session_a = Session::with_ttl(
            SessionId::generate(),
            user_id,
            tenant_a,
            SystemTime::UNIX_EPOCH,
            std::time::Duration::from_secs(600),
        )
        .unwrap();
        let session_b = Session::with_ttl(
            SessionId::generate(),
            user_id,
            tenant_b,
            SystemTime::UNIX_EPOCH,
            std::time::Duration::from_secs(600),
        )
        .unwrap();

        let refresh_a = RefreshToken::new("tenant-a-refresh").unwrap();
        let refresh_b = RefreshToken::new("tenant-b-refresh").unwrap();

        store
            .create_session(SessionRecord::new(session_a.clone(), refresh_a.clone()))
            .unwrap();
        store
            .create_session(SessionRecord::new(session_b.clone(), refresh_b.clone()))
            .unwrap();

        store.revoke_all_for_user(tenant_a, user_id).unwrap();

        assert!(store.find_by_refresh_token(&refresh_a).unwrap().is_none());
        assert!(store.find_by_refresh_token(&refresh_b).unwrap().is_some());
    }

    #[derive(Default)]
    struct TestPasswordHasher;

    impl PasswordHasher for TestPasswordHasher {
        fn hash(&self, password: &Password) -> crate::NythosResult<PasswordHash> {
            PasswordHash::new(format!("argon2id${}", password.as_str()))
        }

        fn verify(&self, password: &Password, hash: &PasswordHash) -> crate::NythosResult<bool> {
            Ok(hash.as_str() == format!("argon2id${}", password.as_str()))
        }
    }

    #[derive(Default)]
    struct TestTokenSigner;

    impl TokenSigner for TestTokenSigner {
        fn sign(&self, claims: &Claims) -> crate::NythosResult<AccessToken> {
            AccessToken::new(format!(
                "signed:{}:{}",
                claims.subject(),
                claims.tenant_id()
            ))
        }

        fn verify(&self, token: &AccessToken) -> crate::NythosResult<Claims> {
            if token.as_str().trim().is_empty() {
                return Err(AuthError::InvalidCredentials);
            }

            Claims::access(
                UserId::generate(),
                TenantId::generate(),
                SystemTime::UNIX_EPOCH,
                std::time::Duration::from_secs(300),
            )
        }
    }

    #[derive(Default)]
    struct TestRevocationChecker {
        revoked: RefCell<BTreeSet<SessionId>>,
    }

    impl RevocationChecker for TestRevocationChecker {
        fn is_revoked(&self, session_id: SessionId) -> crate::NythosResult<bool> {
            Ok(self.revoked.borrow().contains(&session_id))
        }
    }

    #[test]
    fn password_hasher_contract_supports_hash_and_verify() {
        let hasher = TestPasswordHasher;
        let password = Password::new("super-secret-password").unwrap();

        let hash = hasher.hash(&password).unwrap();

        assert!(hash.as_str().starts_with("argon2id$"));
        assert!(hasher.verify(&password, &hash).unwrap());
        assert!(
            !hasher
                .verify(&Password::new("another-password").unwrap(), &hash)
                .unwrap()
        );
    }

    #[test]
    fn token_signer_contract_operates_on_core_claims_and_access_tokens() {
        let signer = TestTokenSigner;
        let claims = Claims::access(
            UserId::generate(),
            TenantId::generate(),
            SystemTime::UNIX_EPOCH,
            std::time::Duration::from_secs(300),
        )
        .unwrap();

        let token = signer.sign(&claims).unwrap();
        let verified = signer.verify(&token).unwrap();

        assert!(!token.as_str().is_empty());
        assert_eq!(verified.purpose(), &crate::TokenPurpose::Access);
    }

    #[test]
    fn revocation_checker_contract_reports_session_revocation_state() {
        let checker = TestRevocationChecker::default();
        let session_id = SessionId::generate();

        assert!(!checker.is_revoked(session_id).unwrap());

        checker.revoked.borrow_mut().insert(session_id);

        assert!(checker.is_revoked(session_id).unwrap());
    }
}
