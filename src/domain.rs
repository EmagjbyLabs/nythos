//! Foundational domain types and identity models.
//!
//! This module is the home for shared primitives such as typed IDs,
//! value objects, and core identity entities.
use std::collections::BTreeMap;
use std::str::FromStr;
use std::{fmt, time::SystemTime};
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

/// Domain status used by auth flows and account checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UserStatus {
    Active,
    Locked,
    Disabled,
}

impl UserStatus {
    /// Returns whether the account is allowed to authenticate.
    pub const fn can_authenticate(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Returns whether the account is locked from login attempts.
    pub const fn is_locked(self) -> bool {
        matches!(self, Self::Locked)
    }

    /// Returns whether the account is disabled.
    pub const fn is_disabled(self) -> bool {
        matches!(self, Self::Disabled)
    }
}

/// Tenant-scoped user identity.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct User {
    id: UserId,
    email: Email,
    status: UserStatus,
    created_at: SystemTime,
}

impl User {
    /// Creates a new user with active status.
    pub fn new(id: UserId, email: Email, created_at: SystemTime) -> Self {
        Self {
            id,
            email,
            status: UserStatus::Active,
            created_at,
        }
    }

    /// Creates a user with an explicit status
    pub fn with_status(
        id: UserId,
        email: Email,
        status: UserStatus,
        created_at: SystemTime,
    ) -> Self {
        Self {
            id,
            email,
            status,
            created_at,
        }
    }

    pub const fn id(&self) -> UserId {
        self.id
    }

    pub const fn email(&self) -> &Email {
        &self.email
    }

    pub const fn status(&self) -> UserStatus {
        self.status
    }

    pub const fn created_at(&self) -> SystemTime {
        self.created_at
    }

    pub fn set_status(&mut self, status: UserStatus) {
        self.status = status;
    }

    pub const fn can_authenticate(&self) -> bool {
        self.status.can_authenticate()
    }

    pub const fn is_locked(&self) -> bool {
        self.status.is_locked()
    }

    pub const fn is_disabled(&self) -> bool {
        self.status.is_disabled()
    }
}

/// Optional tenant-level settings kept as plain domain metadata.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct TenantSettings(BTreeMap<String, String>);

impl TenantSettings {
    pub fn new(entries: BTreeMap<String, String>) -> Self {
        Self(entries)
    }

    pub fn as_map(&self) -> &BTreeMap<String, String> {
        &self.0
    }

    pub fn into_inner(self) -> BTreeMap<String, String> {
        self.0
    }
}

/// Tenant boundary in the auth domain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Tenant {
    id: TenantId,
    slug: String,
    settings: Option<TenantSettings>,
}

impl Tenant {
    const MAX_SLUG_LEN: usize = 64;

    pub fn new(id: TenantId, slug: impl AsRef<str>) -> NythosResult<Self> {
        Self::with_settings(id, slug, None)
    }

    pub fn with_settings(
        id: TenantId,
        slug: impl AsRef<str>,
        settings: Option<TenantSettings>,
    ) -> NythosResult<Self> {
        let slug = Self::validate_slug(slug.as_ref())?;

        Ok(Self { id, slug, settings })
    }

    pub const fn id(&self) -> TenantId {
        self.id
    }

    pub fn slug(&self) -> &str {
        &self.slug
    }

    pub fn settings(&self) -> Option<&TenantSettings> {
        self.settings.as_ref()
    }

    pub fn set_settings(&mut self, settings: Option<TenantSettings>) {
        self.settings = settings;
    }

    fn validate_slug(input: &str) -> NythosResult<String> {
        let slug = input.trim();

        if slug.is_empty() {
            return Err(AuthError::ValidationError(
                "tenant slug cannot be empty".to_owned(),
            ));
        }

        if slug.len() > Self::MAX_SLUG_LEN {
            return Err(AuthError::ValidationError(format!(
                "tenant slug must be at most {} characters",
                Self::MAX_SLUG_LEN
            )));
        }

        if slug.starts_with('-') || slug.ends_with('-') {
            return Err(AuthError::ValidationError(
                "tenant slug cannot start or end with '-'".to_owned(),
            ));
        }

        if !slug
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(AuthError::ValidationError(
                "tenant slug must contain only lowercase ASCII letters, digits, or '-'".to_owned(),
            ));
        }

        Ok(slug.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Email, Password, RoleId, SessionId, Tenant, TenantId, TenantSettings, User, UserId,
        UserStatus,
    };
    use crate::AuthError;
    use std::{
        collections::BTreeMap,
        str::FromStr,
        time::{Duration, SystemTime},
    };
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

    #[test]
    fn user_new_defaults_to_active_status() {
        let created_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let user = User::new(
            UserId::generate(),
            Email::parse("user@example.com").unwrap(),
            created_at,
        );

        assert_eq!(user.status(), UserStatus::Active);
        assert!(user.can_authenticate());
        assert_eq!(user.created_at(), created_at);
    }

    #[test]
    fn user_status_helpers_match_auth_expectations() {
        assert!(UserStatus::Active.can_authenticate());
        assert!(!UserStatus::Locked.can_authenticate());
        assert!(!UserStatus::Disabled.can_authenticate());

        assert!(UserStatus::Locked.is_locked());
        assert!(UserStatus::Disabled.is_disabled());
    }

    #[test]
    fn user_status_can_be_updated_without_extra_booleans() {
        let mut user = User::new(
            UserId::generate(),
            Email::parse("user@example.com").unwrap(),
            SystemTime::now(),
        );

        user.set_status(UserStatus::Locked);
        assert!(user.is_locked());
        assert!(!user.can_authenticate());

        user.set_status(UserStatus::Disabled);
        assert!(user.is_disabled());
        assert!(!user.can_authenticate());
    }

    #[test]
    fn tenant_accepts_valid_slug_and_optional_settings() {
        let mut settings = BTreeMap::new();
        settings.insert("locale".to_owned(), "en".to_owned());

        let tenant = Tenant::with_settings(
            TenantId::generate(),
            "acme-logistics",
            Some(TenantSettings::new(settings.clone())),
        )
        .unwrap();

        assert_eq!(tenant.slug(), "acme-logistics");
        assert_eq!(tenant.settings().unwrap().as_map(), &settings);
    }

    #[test]
    fn tenant_rejects_invalid_slug_shapes() {
        assert!(matches!(
            Tenant::new(TenantId::generate(), ""),
            Err(AuthError::ValidationError(_))
        ));
        assert!(matches!(
            Tenant::new(TenantId::generate(), "Acme"),
            Err(AuthError::ValidationError(_))
        ));
        assert!(matches!(
            Tenant::new(TenantId::generate(), "-leading"),
            Err(AuthError::ValidationError(_))
        ));
        assert!(matches!(
            Tenant::new(TenantId::generate(), "trailing-"),
            Err(AuthError::ValidationError(_))
        ));
        assert!(matches!(
            Tenant::new(TenantId::generate(), "acme logistics"),
            Err(AuthError::ValidationError(_))
        ));
    }
}
