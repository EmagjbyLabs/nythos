use std::time::{Duration, SystemTime};

use crate::{AuthError, NythosResult, TenantId, UserId};

/// Stored password hash produced by the configured password hasher.
///
/// This is a first-class domain type so the core never passes stored hashes
/// around as plain strings.
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

    use crate::{AuthError, TenantId, UserId};

    use super::{AccessToken, Claims, PasswordHash, TokenPurpose};

    #[test]
    fn password_hash_requires_non_empty_value() {
        assert!(matches!(
            PasswordHash::new("".to_owned()),
            Err(AuthError::ValidationError(_))
        ));

        let hash = PasswordHash::new("hashed_password".to_owned()).unwrap();
        assert_eq!(hash.as_str(), "hashed_password");
    }

    #[test]
    fn access_token_requires_non_empty_value() {
        assert!(matches!(
            AccessToken::new("".to_owned()),
            Err(AuthError::ValidationError(_))
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

        assert!(matches!(results, Err(AuthError::ValidationError(_))));
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
