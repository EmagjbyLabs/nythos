//! Authentication domain concepts and orchestration services.
//!
//! This module contains types such as `PasswordHash`, `Claims`,
//! `AccessToken`, and auth flow services.

use std::time::{Duration, SystemTime};

use uuid::Uuid;

use crate::{
    AuthError, Email, NewUser, NythosResult, Password, PasswordHasher, RefreshToken,
    RefreshTokenRotation, RevocationChecker, Role, RoleRepository, Session, SessionId,
    SessionRecord, SessionStore, TenantId, TokenSigner, User, UserId, UserRepository,
};

/// Input for revoking a single session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevokeSessionInput {
    session_id: SessionId,
}

impl RevokeSessionInput {
    pub const fn new(session_id: SessionId) -> Self {
        Self { session_id }
    }

    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }
}

/// Input for revoking all sessions for a user within a tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevokeAllSessionsInput {
    tenant_id: TenantId,
    user_id: UserId,
}

impl RevokeAllSessionsInput {
    pub const fn new(tenant_id: TenantId, user_id: UserId) -> Self {
        Self { tenant_id, user_id }
    }

    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    pub const fn user_id(&self) -> UserId {
        self.user_id
    }
}

/// Domain result for revoke operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevokeResult {
    revoked: bool,
}

impl RevokeResult {
    pub const fn new(revoked: bool) -> Self {
        Self { revoked }
    }

    pub const fn revoked(&self) -> bool {
        self.revoked
    }
}

/// Input for the refresh orchestration flow.
#[derive(Debug, Clone)]
pub struct RefreshInput {
    refresh_token: String,
    issued_at: SystemTime,
    access_token_ttl: Duration,
}

impl RefreshInput {
    pub fn new(refresh_token: String, issued_at: SystemTime, access_token_ttl: Duration) -> Self {
        Self {
            refresh_token,
            issued_at,
            access_token_ttl,
        }
    }

    pub fn refresh_token(&self) -> &str {
        &self.refresh_token
    }

    pub const fn issued_at(&self) -> SystemTime {
        self.issued_at
    }

    pub const fn access_token_ttl(&self) -> Duration {
        self.access_token_ttl
    }
}

/// Fresh auth material returned by a successful refresh flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshAuthMaterial {
    session: Session,
    roles: Vec<Role>,
    refresh_token: RefreshToken,
    access_token: AccessToken,
    claims: Claims,
}

impl RefreshAuthMaterial {
    pub fn new(
        session: Session,
        roles: Vec<Role>,
        refresh_token: RefreshToken,
        access_token: AccessToken,
        claims: Claims,
    ) -> Self {
        Self {
            session,
            roles,
            refresh_token,
            access_token,
            claims,
        }
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn roles(&self) -> &[Role] {
        &self.roles
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

/// Service for revoking a single session.
pub struct RevokeSessionService<'a, S, C> {
    session_store: &'a S,
    revocation_checker: &'a C,
}

impl<'a, S, C> RevokeSessionService<'a, S, C>
where
    S: SessionStore,
    C: RevocationChecker,
{
    pub fn new(session_store: &'a S, revocation_checker: &'a C) -> Self {
        Self {
            session_store,
            revocation_checker,
        }
    }

    pub fn revoke(&self, input: RevokeSessionInput) -> NythosResult<RevokeResult> {
        if self.revocation_checker.is_revoked(input.session_id())? {
            return Ok(RevokeResult::new(false));
        }

        self.session_store.revoke_session(input.session_id())?;
        Ok(RevokeResult::new(true))
    }
}

/// Service for revoking all sessions for a user within a tenant.
pub struct RevokeAllSessionsService<'a, S> {
    session_store: &'a S,
}

impl<'a, S> RevokeAllSessionsService<'a, S>
where
    S: SessionStore,
{
    pub fn new(session_store: &'a S) -> Self {
        Self { session_store }
    }

    pub fn revoke_all(&self, input: RevokeAllSessionsInput) -> NythosResult<RevokeResult> {
        self.session_store
            .revoke_all_for_user(input.tenant_id(), input.user_id())?;

        Ok(RevokeResult::new(true))
    }
}

/// Refresh orchestration service.
///
/// This flow:
/// - looks up session state by opaque refresh token
/// - rejects missing, revoked, or expired sessions
/// - reloads tenant-scoped roles for fresh auth material
/// - issues a fresh access token
/// - rotates the refresh token through `SessionStore`
pub struct RefreshService<'a, S, R, T, C> {
    session_store: &'a S,
    role_repository: &'a R,
    token_signer: &'a T,
    revocation_checker: &'a C,
}

impl<'a, S, R, T, C> RefreshService<'a, S, R, T, C>
where
    S: SessionStore,
    R: RoleRepository,
    T: TokenSigner,
    C: RevocationChecker,
{
    pub fn new(
        session_store: &'a S,
        role_repository: &'a R,
        token_signer: &'a T,
        revocation_checker: &'a C,
    ) -> Self {
        Self {
            session_store,
            role_repository,
            token_signer,
            revocation_checker,
        }
    }

    pub fn refresh(&self, input: RefreshInput) -> NythosResult<RefreshAuthMaterial> {
        let previous_refresh = RefreshToken::new(input.refresh_token().to_owned())?;

        let record = self
            .session_store
            .find_by_refresh_token(&previous_refresh)?
            .ok_or(AuthError::InvalidCredentials)?;

        let session = record.session().clone();

        self.ensure_session_can_refresh(&session, input.issued_at())?;

        let roles = self
            .role_repository
            .get_roles_for_user(session.tenant_id(), session.user_id())?;

        let claims = Claims::access(
            session.user_id(),
            session.tenant_id(),
            input.issued_at(),
            input.access_token_ttl(),
        )?;

        let access_token = self.token_signer.sign(&claims)?;
        let next_refresh = RefreshToken::new(Uuid::new_v4().to_string())?;

        self.session_store
            .rotate_refresh_token(RefreshTokenRotation::new(
                session.id(),
                previous_refresh,
                next_refresh.clone(),
            ))?;

        Ok(RefreshAuthMaterial::new(
            session,
            roles,
            next_refresh,
            access_token,
            claims,
        ))
    }

    fn ensure_session_can_refresh(&self, session: &Session, now: SystemTime) -> NythosResult<()> {
        if session.is_revoked() || self.revocation_checker.is_revoked(session.id())? {
            return Err(AuthError::SessionRevoked);
        }

        if session.is_expired_at(now) {
            return Err(AuthError::SessionExpired);
        }

        Ok(())
    }
}

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
/// - hashes the password through `UserRepository`
/// - persistes the user through `UserRepository`
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

    pub fn register(&self, input: RegisterInput) -> NythosResult<RegisterResult> {
        let email = Email::parse(input.email())?;
        let password = Password::new(input.password())?;

        self.ensure_email_available(input.tenant_id(), &email)?;

        let password_hash = self.password_hasher.hash(&password)?;
        let user =
            self.user_repository
                .create(input.tenant_id(), NewUser::new(email), password_hash)?;

        let auth = if input.auto_sign_in() {
            Some(self.create_auth_material(&input, &user)?)
        } else {
            None
        };

        Ok(RegisterResult::new(user, auth))
    }

    fn ensure_email_available(&self, tenant_id: TenantId, email: &Email) -> NythosResult<()> {
        if self
            .user_repository
            .find_by_email(tenant_id, email)?
            .is_some()
        {
            return Err(AuthError::ValidationError(
                "user with email already exists in tenant".to_owned(),
            ));
        }

        Ok(())
    }

    fn create_auth_material(
        &self,
        input: &RegisterInput,
        user: &User,
    ) -> NythosResult<RegisterAuthMaterial> {
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

        Ok(RegisterAuthMaterial::new(
            user.clone(),
            session,
            refresh_token,
            access_token,
            claims,
        ))
    }
}

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

/// Stored password hash produced by the configured password hasher.
///
/// This is a first-class domain type so the core never passes stored hashes
/// around as base strings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct PasswordHash(String);

impl PasswordHash {
    pub fn new(value: impl Into<String>) -> NythosResult<Self> {
        let value = value.into();

        if value.trim().is_empty() {
            return Err(AuthError::ValidationError(
                "password hash cannot be empty".to_owned(),
            ));
        }

        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for PasswordHash {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Opaque signed access token value.
///
/// The core expects JWT-like semantics, but this type does not depend on any
/// concrete JWT crate or HTTP transport representation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct AccessToken(String);

impl AccessToken {
    pub fn new(value: impl Into<String>) -> NythosResult<Self> {
        let value = value.into();

        if value.trim().is_empty() {
            return Err(AuthError::ValidationError(
                "access token cannot be empty".to_owned(),
            ));
        }

        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for AccessToken {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Purpose of a signed token in the auth domain.
///
/// This currently models access-token behavior only and intentionally does not
/// imply refresh JWTs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TokenPurpose {
    Access,
}

/// Structured claim set used to build and verify signed auth material.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Claims {
    subject: UserId,
    tenant_id: TenantId,
    purpose: TokenPurpose,
    issued_at: SystemTime,
    expires_at: SystemTime,
}

impl Claims {
    pub fn new(
        subject: UserId,
        tenant_id: TenantId,
        purpose: TokenPurpose,
        issued_at: SystemTime,
        expires_at: SystemTime,
    ) -> NythosResult<Self> {
        if expires_at <= issued_at {
            return Err(AuthError::ValidationError(
                "claims expiry must be after issued time".to_owned(),
            ));
        }

        Ok(Self {
            subject,
            tenant_id,
            purpose,
            issued_at,
            expires_at,
        })
    }

    pub fn access(
        subject: UserId,
        tenant_id: TenantId,
        issued_at: SystemTime,
        ttl: Duration,
    ) -> NythosResult<Self> {
        let expires_at = issued_at.checked_add(ttl).ok_or_else(|| {
            AuthError::ValidationError("claims expiry overflowed system time".to_owned())
        })?;

        Self::new(
            subject,
            tenant_id,
            TokenPurpose::Access,
            issued_at,
            expires_at,
        )
    }

    pub const fn subject(&self) -> UserId {
        self.subject
    }

    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    pub const fn purpose(&self) -> &TokenPurpose {
        &self.purpose
    }

    pub const fn issued_at(&self) -> SystemTime {
        self.issued_at
    }

    pub const fn expires_at(&self) -> SystemTime {
        self.expires_at
    }

    pub fn is_expired_at(&self, now: SystemTime) -> bool {
        self.expires_at <= now
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use crate::{TenantId, UserId};

    use super::{AccessToken, Claims, PasswordHash, TokenPurpose};

    #[test]
    fn password_hash_requires_non_empty_value() {
        assert!(matches!(
            PasswordHash::new("".to_owned()),
            Err(crate::AuthError::ValidationError(_))
        ));

        let hash = PasswordHash::new("hashed_password".to_owned()).unwrap();
        assert_eq!(hash.as_str(), "hashed_password");
    }

    #[test]
    fn access_token_requires_non_empty_value() {
        assert!(matches!(
            AccessToken::new("".to_owned()),
            Err(crate::AuthError::ValidationError(_))
        ));

        let token = AccessToken::new("token_value".to_owned()).unwrap();
        assert_eq!(token.as_str(), "token_value");
    }

    #[test]
    fn claims_require_expiry_after_issue_time() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

        let results = Claims::new(
            UserId::generate(),
            TenantId::generate(),
            TokenPurpose::Access,
            now,
            now,
        );

        assert!(matches!(results, Err(crate::AuthError::ValidationError(_))));
    }

    #[test]
    fn access_claims_capture_tenant_scoped_auth_material() {
        let user_id = UserId::generate();
        let tenant_id = TenantId::generate();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let ttl = Duration::from_secs(900);

        let claims = Claims::access(user_id, tenant_id, now, ttl).unwrap();

        assert_eq!(claims.subject(), user_id);
        assert_eq!(claims.tenant_id(), tenant_id);
        assert_eq!(claims.purpose(), &TokenPurpose::Access);
        assert_eq!(claims.issued_at(), now);
        assert_eq!(claims.expires_at(), now + ttl);
    }

    #[test]
    fn claims_expiry_helper_matches_expected_semantics() {
        let issued_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let claims = Claims::access(
            UserId::generate(),
            TenantId::generate(),
            issued_at,
            Duration::from_secs(60),
        )
        .unwrap();

        assert!(!claims.is_expired_at(issued_at + Duration::from_secs(59)));
        assert!(claims.is_expired_at(issued_at + Duration::from_secs(60)));
    }
}
