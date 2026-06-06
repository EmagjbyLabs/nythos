use nythos_core::{
    AuthError,
    domain::{DisplayName, Email, LoginIdentifier, Password, Username},
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
fn username_round_trips_through_display_and_parse() {
    let username = Username::parse("Gencho_XD").unwrap();

    assert_eq!(username.as_str(), "gencho_xd");
    assert_eq!(username.to_string(), "gencho_xd");

    let parsed = Username::parse(username.to_string()).unwrap();
    assert_eq!(parsed, username);
}

#[test]
fn username_validation_maps_to_auth_error() {
    let error = Username::parse("ab").unwrap_err();

    assert!(matches!(error, AuthError::ValidationError(_)));
}

#[test]
fn username_rejects_email_like_values() {
    let error = Username::parse("person@example.com").unwrap_err();

    assert!(matches!(error, AuthError::ValidationError(_)));
}

#[test]
fn display_name_round_trips_through_display_and_parse() {
    let display_name = DisplayName::parse("  Evgeni Dochev  ").unwrap();

    assert_eq!(display_name.as_str(), "Evgeni Dochev");
    assert_eq!(display_name.to_string(), "Evgeni Dochev");

    let parsed = DisplayName::parse(display_name.to_string()).unwrap();
    assert_eq!(parsed, display_name);
}

#[test]
fn display_name_preserves_unicode_and_casing() {
    let display_name = DisplayName::parse("Генчо Dev").unwrap();

    assert_eq!(display_name.as_str(), "Генчо Dev");
}

#[test]
fn display_name_validation_maps_to_auth_error() {
    let error = DisplayName::parse("line\nbreak").unwrap_err();

    assert!(matches!(error, AuthError::ValidationError(_)));
}

#[test]
fn login_identifier_parses_email_values() {
    let identifier = LoginIdentifier::parse("User@Example.com").unwrap();

    assert!(identifier.is_email());
    assert!(!identifier.is_username());
    assert_eq!(identifier.as_email().unwrap().as_str(), "user@example.com");
    assert!(identifier.as_username().is_none());
}

#[test]
fn login_identifier_parses_username_values() {
    let identifier = LoginIdentifier::parse("Gencho_XD").unwrap();

    assert!(identifier.is_username());
    assert!(!identifier.is_email());
    assert_eq!(identifier.as_username().unwrap().as_str(), "gencho_xd");
    assert!(identifier.as_email().is_none());
}

#[test]
fn login_identifier_validation_maps_to_auth_error() {
    let error = LoginIdentifier::parse("!!bad").unwrap_err();

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
