use nythos_core::{AuthError, NythosResult};

#[test]
fn all_expected_variants_are_constructible() {
    let variants = [
        AuthError::UserNotFound,
        AuthError::InvalidCredentials,
        AuthError::AccountLocked,
        AuthError::SessionRevoked,
        AuthError::SessionExpired,
        AuthError::TenantNotFound,
        AuthError::PermissionDenied,
    ];

    for variant in variants {
        assert_ne!(variant, AuthError::Internal("x".into()));
    }
}

#[test]
fn payload_variants_have_expected_shape() {
    let validation_error = AuthError::ValidationError("invalid email".to_owned());
    let internal_error = AuthError::Internal("signer unavailable".to_owned());

    assert!(matches!(validation_error, AuthError::ValidationError(_)));
    assert!(matches!(internal_error, AuthError::Internal(_)));
}

#[test]
fn return_alias_is_crate_wide_result_pattern() {
    fn make_result() -> NythosResult<&'static str> {
        Ok("success")
    }

    assert_eq!(make_result(), Ok("success"));
}
