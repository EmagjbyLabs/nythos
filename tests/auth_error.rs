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
        AuthError::OAuthIdentityAlreadyLinked,
        AuthError::OAuthIdentityAlreadyLinkedToSelf,
        AuthError::UserNotFoundOrInactive,
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
fn oauth_variants_have_transport_agnostic_display_messages() {
    assert_eq!(
        AuthError::OAuthIdentityAlreadyLinked.to_string(),
        "OAuth identity already linked"
    );
    assert_eq!(
        AuthError::OAuthIdentityAlreadyLinkedToSelf.to_string(),
        "OAuth identity already linked to this user"
    );
    assert_eq!(
        AuthError::UserNotFoundOrInactive.to_string(),
        "user not found or inactive"
    );
}

#[test]
fn provider_disabled_is_not_an_auth_error_variant() {
    let variants = [
        AuthError::OAuthIdentityAlreadyLinked.to_string(),
        AuthError::OAuthIdentityAlreadyLinkedToSelf.to_string(),
        AuthError::UserNotFoundOrInactive.to_string(),
    ];

    assert!(
        !variants
            .iter()
            .any(|message| message == "provider disabled")
    );
}

#[test]
fn return_alias_is_crate_wide_result_pattern() {
    fn make_result() -> NythosResult<&'static str> {
        Ok("success")
    }

    assert_eq!(make_result(), Ok("success"));
}
