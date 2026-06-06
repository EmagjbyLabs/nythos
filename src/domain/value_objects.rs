use std::fmt;
use std::str::FromStr;

use crate::{AuthError, NythosResult};

/// Validated email value object used as the core input boundary.
///
/// Construction normalizes the email into a stable lookup from:
/// - trims surrounding whitespace
/// - requires exactly one '@'
/// - lowercases the full address
/// - rejects empty local/domain parts
/// - rejects whitespace inside the address
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Email(String);

impl Email {
    /// Parses and validates an email input into its normalized form.
    pub fn parse(input: impl AsRef<str>) -> NythosResult<Self> {
        let raw = input.as_ref().trim();

        if raw.is_empty() {
            return Err(AuthError::ValidationError(
                "email cannot be empty".to_owned(),
            ));
        }

        if raw.chars().any(char::is_whitespace) {
            return Err(AuthError::ValidationError(
                "email cannot contain whitespace".to_owned(),
            ));
        }

        let (local, domain) = raw.split_once("@").ok_or_else(|| {
            AuthError::ValidationError("email must contain a single @".to_owned())
        })?;

        if local.is_empty() || domain.is_empty() || domain.contains('@') {
            return Err(AuthError::ValidationError(
                "email must contain a single @ with non-empty local and domain parts".to_owned(),
            ));
        }

        if domain.starts_with('.') || domain.ends_with('.') || !domain.contains('.') {
            return Err(AuthError::ValidationError(
                "email domain must be valid".to_owned(),
            ));
        }

        let normalized = raw.to_ascii_lowercase();

        Ok(Self(normalized))
    }

    /// Returns the normalized email string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the value object and returns the normalized email string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for Email {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for Email {
    type Err = AuthError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Stable tenant-scoped username value object.
///
/// Usernames are normalized to lowercase ASCII and are intended for lookup.
/// They are distinct from display names and must never contain email-like input.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Username(String);

impl Username {
    const MIN_LEN: usize = 3;
    const MAX_LEN: usize = 32;

    /// Parses and validates a username into its normalized lookup form.
    pub fn parse(input: impl AsRef<str>) -> NythosResult<Self> {
        let raw = input.as_ref().trim();

        if raw.is_empty() {
            return Err(AuthError::ValidationError(
                "username cannot be empty".to_owned(),
            ));
        }

        if raw.contains('@') {
            return Err(AuthError::ValidationError(
                "username cannot contain '@'".to_owned(),
            ));
        }

        if raw.chars().any(char::is_whitespace) {
            return Err(AuthError::ValidationError(
                "username cannot contain whitespace".to_owned(),
            ));
        }

        let normalized = raw.to_ascii_lowercase();

        if normalized.len() < Self::MIN_LEN {
            return Err(AuthError::ValidationError(format!(
                "username must be at least {} characters",
                Self::MIN_LEN
            )));
        }

        if normalized.len() > Self::MAX_LEN {
            return Err(AuthError::ValidationError(format!(
                "username must be at most {} characters",
                Self::MAX_LEN
            )));
        }

        if normalized.starts_with(['_', '-']) || normalized.ends_with(['_', '-']) {
            return Err(AuthError::ValidationError(
                "username cannot start or end with '_' or '-'".to_owned(),
            ));
        }

        if !normalized
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        {
            return Err(AuthError::ValidationError(
                "username must contain only lowercase ASCII letters, digits, '_' or '-'".to_owned(),
            ));
        }

        Ok(Self(normalized))
    }

    /// Returns the normalized username string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the username and returns the normalized string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for Username {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for Username {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for Username {
    type Err = AuthError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Human-readable display name value object.
///
/// Display names are profile metadata only. They are not lookup identifiers and
/// must never be used for authentication.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DisplayName(String);

impl DisplayName {
    const MAX_LEN: usize = 80;

    /// Parses and validates a display name while preserving user-facing casing.
    pub fn parse(input: impl AsRef<str>) -> NythosResult<Self> {
        let value = input.as_ref().trim();

        if value.is_empty() {
            return Err(AuthError::ValidationError(
                "display name cannot be empty".to_owned(),
            ));
        }

        if value.chars().count() > Self::MAX_LEN {
            return Err(AuthError::ValidationError(format!(
                "display name must be at most {} characters",
                Self::MAX_LEN
            )));
        }

        if value.chars().any(|c| c == '\n' || c == '\r') {
            return Err(AuthError::ValidationError(
                "display name cannot contain newlines".to_owned(),
            ));
        }

        if value.chars().any(char::is_control) {
            return Err(AuthError::ValidationError(
                "display name cannot contain control characters".to_owned(),
            ));
        }

        Ok(Self(value.to_owned()))
    }

    /// Returns the validated display name string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the display name and returns the owned string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for DisplayName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for DisplayName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for DisplayName {
    type Err = AuthError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Typed login identifier used to classify login input as email or username.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum LoginIdentifier {
    Email(Email),
    Username(Username),
}

impl LoginIdentifier {
    /// Parses a raw login identifier.
    ///
    /// Email parsing is attempted first. If that fails, username parsing is
    /// attempted. This keeps classification deterministic.
    pub fn parse(input: impl AsRef<str>) -> NythosResult<Self> {
        let raw = input.as_ref();

        if let Ok(email) = Email::parse(raw) {
            return Ok(Self::Email(email));
        }

        Username::parse(raw).map(Self::Username)
    }

    pub const fn is_email(&self) -> bool {
        matches!(self, Self::Email(_))
    }

    pub const fn is_username(&self) -> bool {
        matches!(self, Self::Username(_))
    }

    pub const fn as_email(&self) -> Option<&Email> {
        match self {
            Self::Email(email) => Some(email),
            Self::Username(_) => None,
        }
    }

    pub const fn as_username(&self) -> Option<&Username> {
        match self {
            Self::Email(_) => None,
            Self::Username(username) => Some(username),
        }
    }
}

impl From<Email> for LoginIdentifier {
    fn from(value: Email) -> Self {
        Self::Email(value)
    }
}

impl From<Username> for LoginIdentifier {
    fn from(value: Username) -> Self {
        Self::Username(value)
    }
}

impl FromStr for LoginIdentifier {
    type Err = AuthError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Raw validated password input.
///
/// This is intentionally distinct from a stored password hash. It represents
/// inbound credential material that has passed the core validation boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Password(String);

impl Password {
    const MIN_LEN: usize = 8;
    const MAX_LEN: usize = 1024;

    /// Validates and constructs a raw password input.
    pub fn new(input: impl AsRef<str>) -> NythosResult<Self> {
        let raw = input.as_ref();

        if raw.is_empty() {
            return Err(AuthError::ValidationError(
                "password cannot be empty".to_owned(),
            ));
        }

        if raw.len() < Self::MIN_LEN {
            return Err(AuthError::ValidationError(format!(
                "password must be at least {} characters",
                Self::MIN_LEN
            )));
        }

        if raw.len() > Self::MAX_LEN {
            return Err(AuthError::ValidationError(format!(
                "password must be at most {} characters",
                Self::MAX_LEN
            )));
        }

        if raw.chars().any(|c| c == '\n' || c == '\r') {
            return Err(AuthError::ValidationError(
                "password cannot contain newlines".to_owned(),
            ));
        }

        Ok(Self(raw.to_owned()))
    }

    /// Returns the validated raw password as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the password input and returns the owned string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::{DisplayName, Email, LoginIdentifier, Password, Username};
    use crate::AuthError;

    #[test]
    fn email_normalizes_for_stable_lookup() {
        let email = Email::parse("  Alice.Example@Example.COM").unwrap();

        assert_eq!(email.as_str(), "alice.example@example.com");
    }

    #[test]
    fn email_rejects_empty_input() {
        let error = Email::parse("   ").unwrap_err();

        assert_eq!(
            error,
            AuthError::ValidationError("email cannot be empty".to_owned())
        )
    }

    #[test]
    fn email_rejects_invalid_shapes() {
        assert!(matches!(
            Email::parse("missing-at.example.com"),
            Err(AuthError::ValidationError(_))
        ));
        assert!(matches!(
            Email::parse("a@b"),
            Err(AuthError::ValidationError(_))
        ));
        assert!(matches!(
            Email::parse("a@@example.com"),
            Err(AuthError::ValidationError(_))
        ));
        assert!(matches!(
            Email::parse("a @example.com"),
            Err(AuthError::ValidationError(_))
        ));
    }

    #[test]
    fn username_accepts_simple_values_and_normalizes() {
        let username = Username::parse("  Alice_123  ").unwrap();

        assert_eq!(username.as_str(), "alice_123");
        assert_eq!(username.to_string(), "alice_123");
    }

    #[test]
    fn username_accepts_digits_underscore_and_hyphen() {
        let username = Username::parse("dev-ops_123").unwrap();

        assert_eq!(username.as_str(), "dev-ops_123");
    }

    #[test]
    fn username_rejects_invalid_shapes() {
        assert!(matches!(
            Username::parse(""),
            Err(AuthError::ValidationError(_))
        ));
        assert!(matches!(
            Username::parse("ab"),
            Err(AuthError::ValidationError(_))
        ));
        assert!(matches!(
            Username::parse("a".repeat(33)),
            Err(AuthError::ValidationError(_))
        ));
        assert!(matches!(
            Username::parse("-alice"),
            Err(AuthError::ValidationError(_))
        ));
        assert!(matches!(
            Username::parse("alice_"),
            Err(AuthError::ValidationError(_))
        ));
        assert!(matches!(
            Username::parse("ali ce"),
            Err(AuthError::ValidationError(_))
        ));
        assert!(matches!(
            Username::parse("alice@example.com"),
            Err(AuthError::ValidationError(_))
        ));
        assert!(matches!(
            Username::parse("álîce"),
            Err(AuthError::ValidationError(_))
        ));
    }

    #[test]
    fn display_name_accepts_unicode_and_preserves_casing() {
        let display_name = DisplayName::parse("  Ada Lovelace 张伟  ").unwrap();

        assert_eq!(display_name.as_str(), "Ada Lovelace 张伟");
        assert_eq!(display_name.to_string(), "Ada Lovelace 张伟");
    }

    #[test]
    fn display_name_rejects_invalid_shapes() {
        assert!(matches!(
            DisplayName::parse("   "),
            Err(AuthError::ValidationError(_))
        ));
        assert!(matches!(
            DisplayName::parse("a".repeat(81)),
            Err(AuthError::ValidationError(_))
        ));
        assert!(matches!(
            DisplayName::parse("Ada\nLovelace"),
            Err(AuthError::ValidationError(_))
        ));
        assert!(matches!(
            DisplayName::parse("Ada\rLovelace"),
            Err(AuthError::ValidationError(_))
        ));
        assert!(matches!(
            DisplayName::parse("Ada\u{0001}Lovelace"),
            Err(AuthError::ValidationError(_))
        ));
    }

    #[test]
    fn login_identifier_parses_email_first() {
        let identifier = LoginIdentifier::parse("User@Example.com").unwrap();

        assert!(identifier.is_email());
        assert!(!identifier.is_username());
        assert_eq!(identifier.as_email().unwrap().as_str(), "user@example.com");
        assert!(identifier.as_username().is_none());
    }

    #[test]
    fn login_identifier_parses_username_when_email_fails() {
        let identifier = LoginIdentifier::parse("Alice_123").unwrap();

        assert!(identifier.is_username());
        assert!(!identifier.is_email());
        assert_eq!(identifier.as_username().unwrap().as_str(), "alice_123");
        assert!(identifier.as_email().is_none());
    }

    #[test]
    fn login_identifier_rejects_invalid_input() {
        assert!(matches!(
            LoginIdentifier::parse("!!bad"),
            Err(AuthError::ValidationError(_))
        ));
    }

    #[test]
    fn login_identifier_from_value_objects_keeps_variant() {
        let email = Email::parse("person@example.com").unwrap();
        let username = Username::parse("person").unwrap();

        assert!(LoginIdentifier::from(email).is_email());
        assert!(LoginIdentifier::from(username).is_username());
    }

    #[test]
    fn password_accepts_valid_raw_input() {
        let password = Password::new("correct-horse-battery-staple").unwrap();

        assert_eq!(password.as_str(), "correct-horse-battery-staple");
    }

    #[test]
    fn password_rejects_empty_short_and_newline_inputs() {
        assert!(matches!(
            Password::new(""),
            Err(AuthError::ValidationError(_))
        ));
        assert!(matches!(
            Password::new("short"),
            Err(AuthError::ValidationError(_))
        ));
        assert!(matches!(
            Password::new("line\nbreak"),
            Err(AuthError::ValidationError(_))
        ));
    }
}
