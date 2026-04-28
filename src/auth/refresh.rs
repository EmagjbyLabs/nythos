use std::time::{Duration, SystemTime};

use uuid::Uuid;

use crate::{
    AccessToken, AuthError, Claims, NythosResult, RefreshToken, RefreshTokenRotation,
    RevocationChecker, Role, RoleRepository, Session, SessionStore, TokenSigner,
};

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
