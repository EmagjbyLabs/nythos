use crate::{Email, NythosResult, PasswordHash, TenantId, User, UserId, UserStatus};

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
