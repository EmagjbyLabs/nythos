//! Core error types shared across `nythos-core`.
use std::fmt;

/// Standard result type for core operations.
pub type NythosResult<T> = Result<T, AuthError>;

/// Common failure type for domain and application-level auth logic.
///
/// This error model is intentionally transport-agnostic. It does not encode
/// HTTP status codes, framework errors, or infra-specific concerns.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    UserNotFound,
    InvalidCredentials,
    AccountLocked,
    SessionRevoked,
    SessionExpired,
    TenantNotFound,
    PermissionDenied,
    OAuthIdentityAlreadyLinked,
    ValidationError(String),
    Internal(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::UserNotFound => f.write_str("user not found"),
            AuthError::InvalidCredentials => f.write_str("invalid credentials"),
            AuthError::AccountLocked => f.write_str("account locked"),
            AuthError::SessionRevoked => f.write_str("session revoked"),
            AuthError::SessionExpired => f.write_str("session expired"),
            AuthError::TenantNotFound => f.write_str("tenant not found"),
            AuthError::PermissionDenied => f.write_str("permission denied"),
            AuthError::OAuthIdentityAlreadyLinked => f.write_str("OAuth identity already linked"),
            AuthError::ValidationError(msg) => write!(f, "validation error: {}", msg),
            AuthError::Internal(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl std::error::Error for AuthError {}

#[cfg(test)]
mod tests {
    use super::{AuthError, NythosResult};

    #[test]
    fn string_payload_variants_preserve_messages() {
        let validation_error = AuthError::ValidationError("invalid email".to_owned());
        let internal_error = AuthError::Internal("signer unavailable".to_owned());

        assert_eq!(
            validation_error.to_string(),
            "validation error: invalid email"
        );

        assert_eq!(
            internal_error.to_string(),
            "internal error: signer unavailable"
        );
    }

    #[test]
    fn unit_variants_match_as_expected() {
        let err = AuthError::InvalidCredentials;

        assert!(matches!(err, AuthError::InvalidCredentials));
        assert_ne!(err, AuthError::UserNotFound);
    }

    #[test]
    fn display_messages_are_transport_agnostic() {
        assert_eq!(AuthError::UserNotFound.to_string(), "user not found");
        assert_eq!(
            AuthError::ValidationError("bad input".to_owned()).to_string(),
            "validation error: bad input"
        );
        assert_eq!(
            AuthError::Internal("store failed".to_owned()).to_string(),
            "internal error: store failed"
        );
    }

    #[test]
    fn nythos_result_alias_uses_auth_error() {
        fn fails() -> NythosResult<()> {
            Err(AuthError::SessionExpired)
        }

        let result = fails();

        assert!(matches!(result, Err(AuthError::SessionExpired)));
    }
}
