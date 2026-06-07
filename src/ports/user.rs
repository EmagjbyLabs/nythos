use crate::{
    DisplayName, Email, NythosResult, PasswordHash, TenantId, User, UserId, UserStatus, Username,
};

/// Domain-facing input used when creating a new user inside a tenant.
///
/// This keeps repository contracts focused on core data rather than storage
/// payloads or transport DTOs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewUser {
    email: Email,
    username: Option<Username>,
    display_name: Option<DisplayName>,
}

impl NewUser {
    pub fn new(email: Email) -> Self {
        Self {
            email,
            username: None,
            display_name: None,
        }
    }

    pub fn with_profile(
        email: Email,
        username: Option<Username>,
        display_name: Option<DisplayName>,
    ) -> Self {
        Self {
            email,
            username,
            display_name,
        }
    }

    pub fn email(&self) -> &Email {
        &self.email
    }

    pub fn username(&self) -> Option<&Username> {
        self.username.as_ref()
    }

    pub fn display_name(&self) -> Option<&DisplayName> {
        self.display_name.as_ref()
    }

    pub fn into_email(self) -> Email {
        self.email
    }

    pub fn into_parts(self) -> (Email, Option<Username>, Option<DisplayName>) {
        (self.email, self.username, self.display_name)
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
///
/// Username lookup methods are explicit on purpose. Services parse
/// `LoginIdentifier` and enforce tenant auth policy before choosing which
/// repository method to call. Repositories only resolve concrete lookup keys.
pub trait UserRepository {
    /// Finds a user by normalized email within a specific tenant.
    async fn find_by_email(&self, tenant_id: TenantId, email: &Email)
    -> NythosResult<Option<User>>;

    // Finds a user by normalized username within a specific tenant.
    async fn find_by_username(
        &self,
        tenant_id: TenantId,
        username: &Username,
    ) -> NythosResult<Option<User>>;

    /// Finds a user by ID within a specific tenant.
    async fn find_by_id(&self, tenant_id: TenantId, user_id: UserId) -> NythosResult<Option<User>>;

    /// Finds a user and stored password hash by normalized email within a specific tenant.
    ///
    /// This is used by login orchestration so password verification can stay in
    /// the core service while persistence details remain outside the core.
    async fn find_credentials_by_email(
        &self,
        tenant_id: TenantId,
        email: &Email,
    ) -> NythosResult<Option<UserCredentials>>;

    /// Finds a user and stored password hash by normalized username within a specific tenant.
    ///
    /// This is used only after a service has parsed `LoginIdentifier::Username`
    /// and enforced tenant username-login policy. This method must not make
    /// tenant auth policy decisions.
    async fn find_credentials_by_username(
        &self,
        tenant_id: TenantId,
        username: &Username,
    ) -> NythosResult<Option<UserCredentials>>;

    /// Creates a new user in the given tenant using an already-validated email
    /// and an already-produced password hash.
    ///
    /// Implementations should make duplicate handling explicit through the core
    /// error model.
    async fn create(
        &self,
        tenant_id: TenantId,
        new_user: NewUser,
        password_hash: PasswordHash,
    ) -> NythosResult<User>;

    /// Updates a user's status within a specific tenant boundary.
    async fn update_status(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        status: UserStatus,
    ) -> NythosResult<()>;
}
