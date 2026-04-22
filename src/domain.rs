//! Foundational domain types and identity models.
//!
//! This module is the home for shared primitives such as typed IDs,
//! value objects, and core identity entities.
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

use crate::{AuthError, NythosResult};

macro_rules! typed_id {
    ($name:ident) => {
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            serde::Serialize,
            serde::Deserialize,
        )]
        pub struct $name(Uuid);

        impl $name {
            /// Creates a new typed ID from a raw UUID.
            pub const fn new(value: Uuid) -> Self {
                Self(value)
            }

            /// Generates a new random UUID.
            pub fn generate() -> Self {
                Self(Uuid::new_v4())
            }

            /// Returns the wrapped UUID by value.
            pub const fn into_uuid(self) -> Uuid {
                self.0
            }

            /// Returns a shared reference to the wrapped UUID.
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl From<Uuid> for $name {
            fn from(value: Uuid) -> Self {
                Self::new(value)
            }
        }

        impl From<$name> for Uuid {
            fn from(value: $name) -> Self {
                value.into_uuid()
            }
        }

        impl AsRef<Uuid> for $name {
            fn as_ref(&self) -> &Uuid {
                self.as_uuid()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(s).map(Self::new)
            }
        }
    };
}

typed_id!(UserId);
typed_id!(TenantId);
typed_id!(SessionId);
typed_id!(RoleId);

/// Validated email value object used as the core input boundary.
///
/// Construction normalizes the email into a stable lookup from:
/// - trims surrounding whitespace
/// - requires exactly one '@'
/// - lowercases the full address
/// - rejects empty local/domain parts
/// - rejects whitespace inside the address
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    use crate::{
        AuthError,
        domain::{Email, Password},
    };

    use super::{RoleId, SessionId, TenantId, UserId};
    use core::str::FromStr;
    use uuid::Uuid;

    #[test]
    fn typed_ids_wrap_and_unwrap_uuid() {
        let raw = Uuid::new_v4();

        let user_id = UserId::new(raw);

        assert_eq!(user_id.as_uuid(), &raw);
        assert_eq!(user_id.into_uuid(), raw);
    }

    #[test]
    fn typed_ids_parse_and_format_round_trip() {
        let raw = Uuid::new_v4();

        let user_id = UserId::from_str(&raw.to_string()).unwrap();

        assert_eq!(user_id.to_string(), raw.to_string());
        assert_eq!(user_id.into_uuid(), raw);
    }

    #[test]
    fn typed_ids_support_equality_hashing_and_copy() {
        let raw = Uuid::new_v4();

        let a = TenantId::new(raw);
        let b = a;

        assert_eq!(a, b);

        let mut set = std::collections::HashSet::new();
        set.insert(a);

        assert!(set.contains(&b));
    }

    #[test]
    fn all_core_identity_types_exist_and_are_distinct() {
        let user_id = UserId::generate();
        let tenant_id = TenantId::generate();
        let session_id = SessionId::generate();
        let role_id = RoleId::generate();

        assert_ne!(user_id.to_string(), tenant_id.to_string());
        assert_ne!(session_id.to_string(), role_id.to_string());
    }

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
