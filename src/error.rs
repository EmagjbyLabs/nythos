//! Core error types shared across `nythos-core`.

/// Standard result type for core operations.
pub type NythosResult<T> = Result<T, AuthError>;

/// Common failure type for domain and application-level auth logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    UserNotFound,
    InvalidCredentials,
    AccountLocked,
    SessionRevoked,
    SessionExpired,
    TenantNotFound,
    PermissionDenied,
    ValidationError(String),
    Internal(String),
}
