use std::time::{Duration, SystemTime};

use super::issuance::issue_session_auth;
use crate::{
    AccessToken, AuthError, Claims, Email, NewUser, NythosResult, Password, PasswordHasher,
    RefreshToken, Session, SessionStore, TenantId, TokenSigner, User, UserRepository,
};

/// Input for the register orchestration flow.
#[derive(Debug, Clone)]
pub struct RegisterInput {
    tenant_id: TenantId,
    email: String,
    password: String,
    issued_at: SystemTime,
    access_token_ttl: Duration,
    session_ttl: Duration,
    auto_sign_in: bool,
}

impl RegisterInput {
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
            auto_sign_in: true,
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

    pub const fn auto_sign_in(&self) -> bool {
        self.auto_sign_in
    }

    pub fn with_auto_sign_in(mut self, auto_sign_in: bool) -> Self {
        self.auto_sign_in = auto_sign_in;
        self
    }
}

/// Signed auth material returned when registration also creates a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterAuthMaterial {
    user: User,
    session: Session,
    refresh_token: RefreshToken,
    access_token: AccessToken,
    claims: Claims,
}

impl RegisterAuthMaterial {
    pub fn new(
        user: User,
        session: Session,
        refresh_token: RefreshToken,
        access_token: AccessToken,
        claims: Claims,
    ) -> Self {
        Self {
            user,
            session,
            refresh_token,
            access_token,
            claims,
        }
    }

    pub fn user(&self) -> &User {
        &self.user
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

/// Result of a register flow.
///
/// `auth` is present when the flow is configured to auto-sign-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterResult {
    user: User,
    auth: Option<RegisterAuthMaterial>,
}

impl RegisterResult {
    pub fn new(user: User, auth: Option<RegisterAuthMaterial>) -> Self {
        Self { user, auth }
    }

    pub fn user(&self) -> &User {
        &self.user
    }

    pub fn auth(&self) -> Option<&RegisterAuthMaterial> {
        self.auth.as_ref()
    }
}

/// Register orchestration service.
///
/// This flow:
/// - validates email and password through core value objects
/// - enforces tenant-scoped uniqueness through `UserRepository`
/// - hashes the password through `PasswordHasher`
/// - persists the user through `UserRepository`
/// - optionally creates a session and signed access token through `SessionStore` and `TokenSigner`
pub struct RegisterService<'a, U, S, H, T> {
    user_repository: &'a U,
    session_store: &'a S,
    password_hasher: &'a H,
    token_signer: &'a T,
}

impl<'a, U, S, H, T> RegisterService<'a, U, S, H, T>
where
    U: UserRepository,
    S: SessionStore,
    H: PasswordHasher,
    T: TokenSigner,
{
    pub fn new(
        user_repository: &'a U,
        session_store: &'a S,
        password_hasher: &'a H,
        token_signer: &'a T,
    ) -> Self {
        Self {
            user_repository,
            session_store,
            password_hasher,
            token_signer,
        }
    }

    pub async fn register(&self, input: RegisterInput) -> NythosResult<RegisterResult> {
        let email = Email::parse(input.email())?;
        let password = Password::new(input.password())?;

        self.ensure_email_available(input.tenant_id(), &email)
            .await?;

        let password_hash = self.password_hasher.hash(&password).await?;
        let user = self
            .user_repository
            .create(input.tenant_id(), NewUser::new(email), password_hash)
            .await?;

        let auth = if input.auto_sign_in() {
            Some(self.create_auth_material(&input, &user).await?)
        } else {
            None
        };

        Ok(RegisterResult::new(user, auth))
    }

    async fn ensure_email_available(&self, tenant_id: TenantId, email: &Email) -> NythosResult<()> {
        if self
            .user_repository
            .find_by_email(tenant_id, email)
            .await?
            .is_some()
        {
            return Err(AuthError::ValidationError(
                "user with email already exists in tenant".to_owned(),
            ));
        }

        Ok(())
    }

    async fn create_auth_material(
        &self,
        input: &RegisterInput,
        user: &User,
    ) -> NythosResult<RegisterAuthMaterial> {
        let issued = issue_session_auth(
            self.session_store,
            self.token_signer,
            user.id(),
            input.tenant_id(),
            input.issued_at(),
            input.access_token_ttl(),
            input.session_ttl(),
        )
        .await?;

        Ok(RegisterAuthMaterial::new(
            user.clone(),
            issued.session,
            issued.refresh_token,
            issued.access_token,
            issued.claims,
        ))
    }
}
