use std::time::{Duration, SystemTime};

use super::issuance::issue_session_auth;
use crate::{
    AccessToken, AuthError, Claims, LoginIdentifier, NythosResult, Password, PasswordHasher,
    RefreshToken, Role, RoleRepository, Session, SessionStore, TenantId, TenantPolicyPort,
    TokenSigner, User, UserCredentials, UserRepository,
};

/// Input for the login orchestration flow.
#[derive(Debug, Clone)]
pub struct LoginInput {
    tenant_id: TenantId,
    identifier: String,
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
            identifier: email,
            password,
            issued_at,
            access_token_ttl,
            session_ttl,
        }
    }

    pub fn new_with_identifier(
        tenant_id: TenantId,
        identifier: String,
        password: String,
        issued_at: SystemTime,
        access_token_ttl: Duration,
        session_ttl: Duration,
    ) -> Self {
        Self {
            tenant_id,
            identifier,
            password,
            issued_at,
            access_token_ttl,
            session_ttl,
        }
    }

    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    /// Compatibility alias for the previous email-shaped login input.
    ///
    /// The returned value is the same raw login identifier string. New code
    /// should prefer `identifier()`.
    pub fn email(&self) -> &str {
        &self.identifier
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
/// - parses inbound login identifier and password
/// - loads tenant auth policy through `TenantPolicyPort`
/// - branches between email and username credential lookup
/// - rejects username login when tenant policy disables it
/// - checks account status before password verification completes the login
/// - verifies the password through `PasswordHasher`
/// - loads tenant-scoped roles through `RoleRepository`
/// - creates session state through `SessionStore`
/// - builds claims and signs an access token through `TokenSigner`
pub struct LoginService<'a, U, R, P, S, H, T> {
    user_repository: &'a U,
    role_repository: &'a R,
    tenant_policy_port: &'a P,
    session_store: &'a S,
    password_hasher: &'a H,
    token_signer: &'a T,
}

impl<'a, U, R, P, S, H, T> LoginService<'a, U, R, P, S, H, T>
where
    U: UserRepository,
    R: RoleRepository,
    P: TenantPolicyPort,
    S: SessionStore,
    H: PasswordHasher,
    T: TokenSigner,
{
    pub fn new(
        user_repository: &'a U,
        role_repository: &'a R,
        tenant_policy_port: &'a P,
        session_store: &'a S,
        password_hasher: &'a H,
        token_signer: &'a T,
    ) -> Self {
        Self {
            user_repository,
            role_repository,
            tenant_policy_port,
            session_store,
            password_hasher,
            token_signer,
        }
    }

    pub async fn login(&self, input: LoginInput) -> NythosResult<LoginAuthMaterial> {
        let identifier = LoginIdentifier::parse(input.identifier())?;
        let password = Password::new(input.password())?;
        let policy = self
            .tenant_policy_port
            .load_auth_policy(input.tenant_id())
            .await?;

        let credentials = self
            .find_credentials(
                input.tenant_id(),
                &identifier,
                policy.username_login_enabled(),
            )
            .await?
            .ok_or(AuthError::InvalidCredentials)?;

        let user = credentials.user().clone();

        self.ensure_user_can_login(&user)?;

        let verified = self
            .password_hasher
            .verify(&password, credentials.password_hash())
            .await?;

        if !verified {
            return Err(AuthError::InvalidCredentials);
        }

        let roles = self
            .role_repository
            .get_roles_for_user(input.tenant_id(), user.id())
            .await?;

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

        Ok(LoginAuthMaterial::new(
            user,
            roles,
            issued.session,
            issued.refresh_token,
            issued.access_token,
            issued.claims,
        ))
    }

    async fn find_credentials(
        &self,
        tenant_id: TenantId,
        identifier: &LoginIdentifier,
        username_login_enabled: bool,
    ) -> NythosResult<Option<UserCredentials>> {
        match identifier {
            LoginIdentifier::Email(email) => {
                self.user_repository
                    .find_credentials_by_email(tenant_id, email)
                    .await
            }
            LoginIdentifier::Username(username) => {
                if !username_login_enabled {
                    return Err(AuthError::InvalidCredentials);
                }

                self.user_repository
                    .find_credentials_by_username(tenant_id, username)
                    .await
            }
        }
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
