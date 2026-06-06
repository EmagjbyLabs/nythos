use std::collections::BTreeMap;
use std::time::SystemTime;

use crate::{AuthError, NythosResult};

use super::{DisplayName, Email, TenantId, UserId, Username};

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
    username: Option<Username>,
    display_name: Option<DisplayName>,
    status: UserStatus,
    created_at: SystemTime,
}

impl User {
    /// Creates a new user with active status.
    pub fn new(id: UserId, email: Email, created_at: SystemTime) -> Self {
        Self {
            id,
            email,
            username: None,
            display_name: None,
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
            username: None,
            display_name: None,
            status,
            created_at,
        }
    }

    /// Creates a user with explicit optional profile fields and status.
    pub fn with_profile(
        id: UserId,
        email: Email,
        username: Option<Username>,
        display_name: Option<DisplayName>,
        status: UserStatus,
        created_at: SystemTime,
    ) -> Self {
        Self {
            id,
            email,
            username,
            display_name,
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

    pub fn username(&self) -> Option<&Username> {
        self.username.as_ref()
    }

    pub fn display_name(&self) -> Option<&DisplayName> {
        self.display_name.as_ref()
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

/// Typed auth-relevant tenant policy.
///
/// These flags control whether optional profile fields may be collected and
/// whether username login is enabled. Auth behavior must consult this typed
/// policy instead of stringly tenant settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct TenantAuthPolicy {
    username_registration_enabled: bool,
    display_name_registration_enabled: bool,
    username_login_enabled: bool,
}

impl TenantAuthPolicy {
    pub const fn new(
        username_registration_enabled: bool,
        display_name_registration_enabled: bool,
        username_login_enabled: bool,
    ) -> Self {
        Self {
            username_registration_enabled,
            display_name_registration_enabled,
            username_login_enabled,
        }
    }

    pub const fn username_registration_enabled(&self) -> bool {
        self.username_registration_enabled
    }

    pub const fn display_name_registration_enabled(&self) -> bool {
        self.display_name_registration_enabled
    }

    pub const fn username_login_enabled(&self) -> bool {
        self.username_login_enabled
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
    auth_policy: TenantAuthPolicy,
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
        Self::with_auth_policy(id, slug, settings, TenantAuthPolicy::default())
    }

    pub fn with_auth_policy(
        id: TenantId,
        slug: impl AsRef<str>,
        settings: Option<TenantSettings>,
        auth_policy: TenantAuthPolicy,
    ) -> NythosResult<Self> {
        let slug = Self::validate_slug(slug.as_ref())?;

        Ok(Self {
            id,
            slug,
            settings,
            auth_policy,
        })
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

    pub const fn auth_policy(&self) -> &TenantAuthPolicy {
        &self.auth_policy
    }

    pub fn set_settings(&mut self, settings: Option<TenantSettings>) {
        self.settings = settings;
    }

    pub fn set_auth_policy(&mut self, auth_policy: TenantAuthPolicy) {
        self.auth_policy = auth_policy;
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
    use super::{Tenant, TenantAuthPolicy, TenantSettings, User, UserStatus};
    use crate::{AuthError, DisplayName, Email, TenantId, UserId, Username};
    use core::option::Option::None;
    use std::{
        collections::BTreeMap,
        time::{Duration, SystemTime},
    };

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
    fn tenant_auth_policy_default_disables_optional_profile_and_username_login() {
        let policy = TenantAuthPolicy::default();

        assert!(!policy.username_registration_enabled());
        assert!(!policy.display_name_registration_enabled());
        assert!(!policy.username_login_enabled());
    }

    #[test]
    fn tenant_auth_policy_new_sets_all_flags() {
        let policy = TenantAuthPolicy::new(true, true, true);

        assert!(policy.username_registration_enabled());
        assert!(policy.display_name_registration_enabled());
        assert!(policy.username_login_enabled());
    }

    #[test]
    fn tenant_new_uses_default_auth_policy() {
        let tenant = Tenant::new(TenantId::generate(), "northstar").unwrap();

        assert_eq!(tenant.auth_policy(), &TenantAuthPolicy::default());
    }

    #[test]
    fn tenant_with_settings_uses_default_auth_policy() {
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
        assert_eq!(tenant.auth_policy(), &TenantAuthPolicy::default());
    }

    #[test]
    fn tenant_with_auth_policy_stores_explicit_policy() {
        let policy = TenantAuthPolicy::new(true, false, true);
        let tenant =
            Tenant::with_auth_policy(TenantId::generate(), "northstar", None, policy).unwrap();

        assert_eq!(tenant.auth_policy(), &policy);
        assert!(tenant.auth_policy().username_registration_enabled());
        assert!(!tenant.auth_policy().display_name_registration_enabled());
        assert!(tenant.auth_policy().username_login_enabled());
    }

    #[test]
    fn tenant_set_auth_policy_updates_policy() {
        let mut tenant = Tenant::new(TenantId::generate(), "northstar").unwrap();

        let new_policy = TenantAuthPolicy::new(true, true, false);
        tenant.set_auth_policy(new_policy);

        assert_eq!(tenant.auth_policy(), &new_policy);
    }

    #[test]
    fn tenant_settings_remain_non_auth_metadata() {
        let mut settings = BTreeMap::new();
        settings.insert("locale".to_owned(), "en".to_owned());

        let tenant = Tenant::with_settings(
            TenantId::generate(),
            "acme-logistics",
            Some(TenantSettings::new(settings.clone())),
        )
        .unwrap();

        assert!(!tenant.auth_policy().username_login_enabled());
        assert_eq!(
            tenant.settings().unwrap().as_map().get("locale"),
            Some(&"en".to_owned())
        );
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

    #[test]
    fn user_new_has_no_profile_fields() {
        let user = User::new(
            UserId::generate(),
            Email::parse("user@example.com").unwrap(),
            SystemTime::UNIX_EPOCH,
        );

        assert!(user.username().is_none());
        assert!(user.display_name().is_none());
    }

    #[test]
    fn user_with_status_has_no_profile_fields() {
        let user = User::with_status(
            UserId::generate(),
            Email::parse("user@example.com").unwrap(),
            UserStatus::Locked,
            SystemTime::UNIX_EPOCH,
        );

        assert_eq!(user.status(), UserStatus::Locked);
        assert!(user.username().is_none());
        assert!(user.display_name().is_none());
    }

    #[test]
    fn user_with_profile_stores_optional_profile_fields() {
        let username = Username::parse("Gencho_XD").unwrap();
        let display_name = DisplayName::parse("Gencho XD").unwrap();

        let user = User::with_profile(
            UserId::generate(),
            Email::parse("user@example.com").unwrap(),
            Some(username.clone()),
            Some(display_name.clone()),
            UserStatus::Active,
            SystemTime::UNIX_EPOCH,
        );

        assert_eq!(user.username(), Some(&username));
        assert_eq!(user.display_name(), Some(&display_name));
        assert_eq!(user.status(), UserStatus::Active);
    }
}
