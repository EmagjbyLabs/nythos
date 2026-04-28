use std::time::{Duration, SystemTime};

use uuid::Uuid;

use crate::{
    AccessToken, AuthError, Claims, Email, NythosResult, Password, PasswordHasher, RefreshToken,
    Role, RoleRepository, Session, SessionId, SessionRecord, SessionStore, TenantId, TokenSigner,
    User, UserRepository,
};

/// Input for the login orchestration flow.
#[derive(Debug, Clone)]
pub struct LoginInput {
    tenant_id: TenantId,
    email: String,
    password: String,
    issued_at: SystemTime,
    access_token_ttl: Duration,
    session_ttl: Duration,
}

impl LoginInput {
    pub fn new(
        tenant_id: TenantId,
        email: String,
        password: String,
        issued_at: SystemTime,
        access_token_ttl: Duration,
        session_ttl: Duration,
    ) -> Self {
        Self {
            tenant_id,
            email,
            password,
            issued_at,
            access_token_ttl,
            session_ttl,
        }
    }

    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    pub fn email(&self) -> &str {
        &self.email
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub const fn issued_at(&self) -> SystemTime {
        self.issued_at
    }

    pub const fn access_token_ttl(&self) -> Duration {
        self.access_token_ttl
    }

    pub const fn session_ttl(&self) -> Duration {
        self.session_ttl
    }
}

/// Signed auth material returned by the login flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginAuthMaterial {
    user: User,
    roles: Vec<Role>,
    session: Session,
    refresh_token: RefreshToken,
    access_token: AccessToken,
    claims: Claims,
}

impl LoginAuthMaterial {
    pub fn new(
        user: User,
        roles: Vec<Role>,
        session: Session,
        refresh_token: RefreshToken,
        access_token: AccessToken,
        claims: Claims,
    ) -> Self {
        Self {
            user,
            roles,
            session,
            refresh_token,
            access_token,
            claims,
        }
    }

    pub fn user(&self) -> &User {
        &self.user
    }

    pub fn roles(&self) -> &[Role] {
        &self.roles
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn refresh_token(&self) -> &RefreshToken {
        &self.refresh_token
    }

    pub fn access_token(&self) -> &AccessToken {
        &self.access_token
    }

    pub fn claims(&self) -> &Claims {
        &self.claims
    }
}

/// Login orchestration service.
///
/// This flow:
/// - validates inbound email and password
/// - loads the user within tenant scope
/// - checks account status before password verification completes the login
/// - verifies the password through `PasswordHasher`
/// - loads tenant-scoped roles through `RoleRepository`
/// - creates session state through `SessionStore`
/// - builds claims and signs an access token through `TokenSigner`
pub struct LoginService<'a, U, R, S, H, T> {
    user_repository: &'a U,
    role_repository: &'a R,
    session_store: &'a S,
    password_hasher: &'a H,
    token_signer: &'a T,
}

impl<'a, U, R, S, H, T> LoginService<'a, U, R, S, H, T>
where
    U: UserRepository,
    R: RoleRepository,
    S: SessionStore,
    H: PasswordHasher,
    T: TokenSigner,
{
    pub fn new(
        user_repository: &'a U,
        role_repository: &'a R,
        session_store: &'a S,
        password_hasher: &'a H,
        token_signer: &'a T,
    ) -> Self {
        Self {
            user_repository,
            role_repository,
            session_store,
            password_hasher,
            token_signer,
        }
    }

    pub fn login(&self, input: LoginInput) -> NythosResult<LoginAuthMaterial> {
        let email = Email::parse(input.email())?;
        let password = Password::new(input.password())?;

        let credentials = self
            .user_repository
            .find_credentials_by_email(input.tenant_id(), &email)?
            .ok_or(AuthError::InvalidCredentials)?;

        let user = credentials.user().clone();

        self.ensure_user_can_login(&user)?;

        let verified = self
            .password_hasher
            .verify(&password, credentials.password_hash())?;

        if !verified {
            return Err(AuthError::InvalidCredentials);
        }

        let roles = self
            .role_repository
            .get_roles_for_user(input.tenant_id(), user.id())?;

        let session = Session::with_ttl(
            SessionId::generate(),
            user.id(),
            input.tenant_id(),
            input.issued_at(),
            input.session_ttl(),
        )?;

        let claims = Claims::access(
            user.id(),
            input.tenant_id(),
            input.issued_at(),
            input.access_token_ttl(),
        )?;

        let access_token = self.token_signer.sign(&claims)?;
        let refresh_token = RefreshToken::new(Uuid::new_v4().to_string())?;

        self.session_store
            .create_session(SessionRecord::new(session.clone(), refresh_token.clone()))?;

        Ok(LoginAuthMaterial::new(
            user,
            roles,
            session,
            refresh_token,
            access_token,
            claims,
        ))
    }

    fn ensure_user_can_login(&self, user: &User) -> NythosResult<()> {
        if user.is_locked() || user.is_disabled() {
            return Err(AuthError::AccountLocked);
        }

        if !user.can_authenticate() {
            return Err(AuthError::InvalidCredentials);
        }

        Ok(())
    }
}
