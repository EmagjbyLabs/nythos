//! Session lifecycle and refresh token concepts.
//!
//! This module contains the core session model and opaque refresh-token type
//! used by refresh and revocation flows.

use std::time::{Duration, SystemTime};

use crate::{AuthError, NythosResult, SessionId, TenantId, UserId};

/// Opaque refresh-token value used for session continuation.
///
/// This is intentionally not modeled as JWT claims or a transport payload.
/// Rotation is handled by store/service logic around this type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct RefreshToken(String);

impl RefreshToken {
    pub fn new(value: impl Into<String>) -> NythosResult<Self> {
        let value = value.into();

        if value.trim().is_empty() {
            return Err(AuthError::ValidationError(
                "refresh token cannot be empty".to_owned(),
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

/// Authenticated session behind refresh and revocation flows.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Session {
    id: SessionId,
    user_id: UserId,
    tenant_id: TenantId,
    issued_at: SystemTime,
    expires_at: SystemTime,
    revoked: bool,
}

impl Session {
    pub fn new(
        id: SessionId,
        user_id: UserId,
        tenant_id: TenantId,
        issued_at: SystemTime,
        expires_at: SystemTime,
    ) -> NythosResult<Self> {
        if expires_at <= issued_at {
            return Err(AuthError::ValidationError(
                "session expiration must be after issue time".to_owned(),
            ));
        }

        Ok(Self {
            id,
            user_id,
            tenant_id,
            issued_at,
            expires_at,
            revoked: false,
        })
    }

    pub fn with_ttl(
        id: SessionId,
        user_id: UserId,
        tenant_id: TenantId,
        issued_at: SystemTime,
        ttl: Duration,
    ) -> NythosResult<Self> {
        let expires_at = issued_at.checked_add(ttl).ok_or_else(|| {
            AuthError::ValidationError("session expiry overflowed system time".to_owned())
        })?;

        Self::new(id, user_id, tenant_id, issued_at, expires_at)
    }

    pub const fn id(&self) -> SessionId {
        self.id
    }

    pub const fn user_id(&self) -> UserId {
        self.user_id
    }

    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    pub const fn issued_at(&self) -> SystemTime {
        self.issued_at
    }

    pub const fn expires_at(&self) -> SystemTime {
        self.expires_at
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub fn is_expired_at(&self, now: SystemTime) -> bool {
        self.expires_at <= now
    }

    pub fn is_active_at(&self, now: SystemTime) -> bool {
        !self.revoked && !self.is_expired_at(now)
    }
}

#[cfg(test)]
mod tests {
    use super::{RefreshToken, Session};
    use crate::{AuthError, SessionId, TenantId, UserId};
    use std::time::{Duration, SystemTime};

    #[test]
    fn refresh_token_requires_non_empty_value() {
        assert!(matches!(
            RefreshToken::new(""),
            Err(AuthError::ValidationError(_))
        ));

        let token = RefreshToken::new("opaque-refresh-token").unwrap();
        assert_eq!(token.as_str(), "opaque-refresh-token");
    }

    #[test]
    fn session_requires_expiry_after_issue_time() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

        let result = Session::new(
            SessionId::generate(),
            UserId::generate(),
            TenantId::generate(),
            now,
            now,
        );

        assert!(matches!(result, Err(AuthError::ValidationError(_))));
    }

    #[test]
    fn session_with_ttl_builds_active_session() {
        let issued_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let ttl = Duration::from_secs(3_600);

        let session = Session::with_ttl(
            SessionId::generate(),
            UserId::generate(),
            TenantId::generate(),
            issued_at,
            ttl,
        )
        .unwrap();

        assert_eq!(session.issued_at(), issued_at);
        assert_eq!(session.expires_at(), issued_at + ttl);
        assert!(!session.is_revoked());
        assert!(session.is_active_at(issued_at + Duration::from_secs(60)));
    }

    #[test]
    fn session_expiry_helper_matches_expected_semantics() {
        let issued_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let session = Session::with_ttl(
            SessionId::generate(),
            UserId::generate(),
            TenantId::generate(),
            issued_at,
            Duration::from_secs(60),
        )
        .unwrap();

        assert!(!session.is_expired_at(issued_at + Duration::from_secs(59)));
        assert!(session.is_expired_at(issued_at + Duration::from_secs(60)));
    }

    #[test]
    fn revoked_session_is_no_longer_active() {
        let issued_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let mut session = Session::with_ttl(
            SessionId::generate(),
            UserId::generate(),
            TenantId::generate(),
            issued_at,
            Duration::from_secs(600),
        )
        .unwrap();

        assert!(session.is_active_at(issued_at + Duration::from_secs(1)));

        session.revoke();

        assert!(session.is_revoked());
        assert!(!session.is_active_at(issued_at + Duration::from_secs(1)));
    }
}
