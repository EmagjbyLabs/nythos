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

/// User credentials payload returned by the user repository for login orchestration.
///
/// This keeps password-hash details out of the core service while still allowing
/// password verification to happen in the core layer, where it belongs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserCredentials {
    user: User,
    password_hash: PasswordHash,
}

impl UserCredentials {
    pub fn new(user: User, password_hash: PasswordHash) -> Self {
        Self {
            user,
            password_hash,
        }
    }

    pub fn user(&self) -> &User {
        &self.user
    }

    pub fn password_hash(&self) -> &PasswordHash {
        &self.password_hash
    }

    pub fn into_parts(self) -> (User, PasswordHash) {
        (self.user, self.password_hash)
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

    /// Finds a user and stored password hash by normalized email within a specific tenant.
    ///
    /// This is used by login orchestration so password verification can stay in
    /// the core service while persistence details remain outside the core.
    fn find_credentials_by_email(
        &self,
        tenant_id: TenantId,
        email: &Email,
    ) -> NythosResult<Option<UserCredentials>>;

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

/// Password hashing port used by registration and login flows.
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
    use std::time::SystemTime;

    use crate::{Email, RefreshToken, RoleId, Session, SessionId, TenantId, UserId};

    use super::{NewUser, RefreshTokenRotation, RoleAssignmentInput, SessionRecord};

    #[test]
    fn new_user_wraps_domain_email() {
        let email = Email::parse("person@example.com").unwrap();
        let new_user = NewUser::new(email.clone());

        assert_eq!(new_user.email(), &email);
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
}
