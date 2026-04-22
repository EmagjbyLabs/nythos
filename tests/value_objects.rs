use nythos_core::{
    AuthError,
    domain::{Email, Password},
};

#[test]
fn email_round_trips_through_display_and_parse() {
    let email = Email::parse("User@Example.com").unwrap();
    let rendered = email.to_string();

    assert_eq!(rendered, "user@example.com");

    let parsed = Email::parse(&rendered).unwrap();
    assert_eq!(parsed, email);
}

#[test]
fn email_has_stable_comparison_semantics() {
    let left = Email::parse("Admin@Example.com").unwrap();
    let right = Email::parse("  admin@example.com").unwrap();

    assert_eq!(left, right);
}

#[test]
fn email_validation_maps_to_auth_error() {
    let error = Email::parse("bad-email").unwrap_err();

    assert!(matches!(error, AuthError::ValidationError(_)));
}

#[test]
fn password_validation_maps_to_auth_error() {
    let error = Password::new("short").unwrap_err();

    assert!(matches!(error, AuthError::ValidationError(_)));
}

#[test]
fn password_preserves_raw_value_after_validation() {
    let password = Password::new("super-secret-password").unwrap();

    assert_eq!(password.as_str(), "super-secret-password");
}
