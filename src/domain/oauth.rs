//! OAuth provider and external identity domain models.
//!
//! This module contains the infrastructure-free OAauth domain surface used by
//! `nythos-core`. Provider redirects, token exchange, JWKS validation, provider
//! HTTP calls, and userinfo fetching remain outside core.

use std::{fmt, str::FromStr, time::SystemTime};

use crate::{AuthError, DisplayName, Email, NythosResult, TenantId, UserId};

/// Supported OAuth/OIDC provider kinds.
///
/// The stable string representation is intentionally lowercase and suitable for
/// persistence. This enum is non-exhaustive so future providers can be added
/// without forcing downstream exhaustive matches.
#[non_exhaustive]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum OAuthProviderKind {
    Google,
    GitHub,
    Microsoft,
}

impl OAuthProviderKind {
    /// Returns the stable lowercase provider identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::GitHub => "github",
            Self::Microsoft => "microsoft",
        }
    }

    /// Parses a stable provider identifier.
    pub fn parse(input: impl AsRef<str>) -> NythosResult<Self> {
        match input.as_ref().trim().to_ascii_lowercase().as_str() {
            "google" => Ok(Self::Google),
            "github" => Ok(Self::GitHub),
            "microsoft" => Ok(Self::Microsoft),
            _ => Err(AuthError::ValidationError(
                "unknown OAuth provider kind".to_owned(),
            )),
        }
    }
}

impl fmt::Display for OAuthProviderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl FromStr for OAuthProviderKind {
    type Err = AuthError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// A provider identity linked to a Nythos user inside one tenant.
///
/// The natural key is:
/// `(tenant_id, provider_kind, provider_subject)`.
///
/// The provider subject is the stable opaque subject/user ID issued by the
/// external provider. Provider email and display name are metadata captured at
/// link time and must not replace the provider subject as the login key.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExternalIdentity {
    tenant_id: TenantId,
    user_id: UserId,
    provider_kind: OAuthProviderKind,
    provider_subject: String,
    provider_email: Option<Email>,
    provider_display_name: Option<DisplayName>,
    linked_at: SystemTime,
    last_seen_at: SystemTime,
}

impl ExternalIdentity {
    /// Creates a new external identity with matching link and last-seen times.
    pub fn new(
        tenant_id: TenantId,
        user_id: UserId,
        provider_kind: OAuthProviderKind,
        provider_subject: impl AsRef<str>,
        provider_email: Option<Email>,
        provider_display_name: Option<DisplayName>,
        now: SystemTime,
    ) -> NythosResult<Self> {
        Self::with_timestamps(
            tenant_id,
            user_id,
            provider_kind,
            provider_subject,
            provider_email,
            provider_display_name,
            now,
            now,
        )
    }

    /// Creates an external identity with explicit timestamps.
    ///
    /// This is useful for repository hydration and deterministic tests.
    #[allow(clippy::too_many_arguments)]
    pub fn with_timestamps(
        tenant_id: TenantId,
        user_id: UserId,
        provider_kind: OAuthProviderKind,
        provider_subject: impl AsRef<str>,
        provider_email: Option<Email>,
        provider_display_name: Option<DisplayName>,
        linked_at: SystemTime,
        last_seen_at: SystemTime,
    ) -> NythosResult<Self> {
        let provider_subject = Self::validate_provider_subject(provider_subject.as_ref())?;

        Ok(Self {
            tenant_id,
            user_id,
            provider_kind,
            provider_subject,
            provider_email,
            provider_display_name,
            linked_at,
            last_seen_at,
        })
    }

    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    pub const fn user_id(&self) -> UserId {
        self.user_id
    }

    pub const fn provider_kind(&self) -> OAuthProviderKind {
        self.provider_kind
    }

    pub fn provider_subject(&self) -> &str {
        &self.provider_subject
    }

    pub fn provider_email(&self) -> Option<&Email> {
        self.provider_email.as_ref()
    }

    pub fn provider_display_name(&self) -> Option<&DisplayName> {
        self.provider_display_name.as_ref()
    }

    pub const fn linked_at(&self) -> SystemTime {
        self.linked_at
    }

    pub const fn last_seen_at(&self) -> SystemTime {
        self.last_seen_at
    }

    /// Updates the last successful provider login timestamp.
    pub fn touch(&mut self, now: SystemTime) {
        self.last_seen_at = now;
    }

    fn validate_provider_subject(input: &str) -> NythosResult<String> {
        let value = input.trim();

        if value.is_empty() {
            return Err(AuthError::ValidationError(
                "provider subject cannot be empty".to_owned(),
            ));
        }

        Ok(value.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::{ExternalIdentity, OAuthProviderKind};
    use crate::{AuthError, DisplayName, Email, TenantId, UserId};
    use std::{
        str::FromStr,
        time::{Duration, SystemTime},
    };

    #[test]
    fn provider_kind_uses_stable_lowercase_strings() {
        assert_eq!(OAuthProviderKind::Google.as_str(), "google");
        assert_eq!(OAuthProviderKind::GitHub.as_str(), "github");
        assert_eq!(OAuthProviderKind::Microsoft.as_str(), "microsoft");
    }

    #[test]
    fn provider_kind_displays_stable_string() {
        assert_eq!(OAuthProviderKind::Google.to_string(), "google");
        assert_eq!(OAuthProviderKind::GitHub.to_string(), "github");
        assert_eq!(OAuthProviderKind::Microsoft.to_string(), "microsoft");
    }

    #[test]
    fn provider_kind_parses_stable_settings() {
        assert_eq!(
            OAuthProviderKind::parse("google").unwrap(),
            OAuthProviderKind::Google
        );
        assert_eq!(
            OAuthProviderKind::parse("github").unwrap(),
            OAuthProviderKind::GitHub
        );
        assert_eq!(
            OAuthProviderKind::parse("microsoft").unwrap(),
            OAuthProviderKind::Microsoft
        );
    }

    #[test]
    fn provider_kind_parse_trims_and_accepts_case_variations() {
        assert_eq!(
            OAuthProviderKind::parse("  Google  ").unwrap(),
            OAuthProviderKind::Google
        );
        assert_eq!(
            OAuthProviderKind::parse("GITHUB").unwrap(),
            OAuthProviderKind::GitHub
        );
        assert_eq!(
            OAuthProviderKind::parse("Microsoft").unwrap(),
            OAuthProviderKind::Microsoft
        );
    }

    #[test]
    fn provider_kind_from_str_matches_parse() {
        assert_eq!(
            OAuthProviderKind::from_str("github").unwrap(),
            OAuthProviderKind::GitHub
        );
    }

    #[test]
    fn provider_kind_rejects_unknown_provider() {
        let result = OAuthProviderKind::parse("yahoo");

        assert!(matches!(result, Err(AuthError::ValidationError(_))));
    }

    #[test]
    fn external_identity_new_sets_linked_and_last_seen_to_now() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

        let identity = ExternalIdentity::new(
            TenantId::generate(),
            UserId::generate(),
            OAuthProviderKind::Google,
            "google-sub-123",
            None,
            None,
            now,
        )
        .unwrap();

        assert_eq!(identity.linked_at(), now);
        assert_eq!(identity.last_seen_at(), now);
    }

    #[test]
    fn external_identity_with_timestamps_allows_explicit_times() {
        let linked_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let last_seen_at = linked_at + Duration::from_secs(3600);

        let identity = ExternalIdentity::with_timestamps(
            TenantId::generate(),
            UserId::generate(),
            OAuthProviderKind::GitHub,
            "github-sub-456",
            None,
            None,
            linked_at,
            last_seen_at,
        )
        .unwrap();

        assert_eq!(identity.linked_at(), linked_at);
        assert_eq!(identity.last_seen_at(), last_seen_at);
    }

    #[test]
    fn external_identity_rejects_empty_provider_subject() {
        let result = ExternalIdentity::new(
            TenantId::generate(),
            UserId::generate(),
            OAuthProviderKind::Microsoft,
            "   ",
            None,
            None,
            SystemTime::UNIX_EPOCH,
        );

        assert!(matches!(result, Err(AuthError::ValidationError(_))));
    }

    #[test]
    fn external_identity_stores_tenant_user_provider_and_subject() {
        let tenant_id = TenantId::generate();
        let user_id = UserId::generate();
        let email = Email::parse("Person@Example.com").unwrap();
        let display_name = DisplayName::parse("Example Person").unwrap();

        let identity = ExternalIdentity::new(
            tenant_id,
            user_id,
            OAuthProviderKind::Microsoft,
            "microsoft-sub-789",
            Some(email.clone()),
            Some(display_name.clone()),
            SystemTime::UNIX_EPOCH,
        )
        .unwrap();

        assert_eq!(identity.tenant_id(), tenant_id);
        assert_eq!(identity.user_id(), user_id);
        assert_eq!(identity.provider_kind(), OAuthProviderKind::Microsoft);
        assert_eq!(identity.provider_subject(), "microsoft-sub-789");
        assert_eq!(identity.provider_email(), Some(&email));
        assert_eq!(identity.provider_display_name(), Some(&display_name));
    }

    #[test]
    fn external_identity_subject_is_trimmed_for_stable_lookup() {
        let identity = ExternalIdentity::new(
            TenantId::generate(),
            UserId::generate(),
            OAuthProviderKind::Google,
            "  google-sub-123  ",
            None,
            None,
            SystemTime::UNIX_EPOCH,
        )
        .unwrap();

        assert_eq!(identity.provider_subject(), "google-sub-123");
    }

    #[test]
    fn external_identity_touch_updates_only_last_seen_at() {
        let tenant_id = TenantId::generate();
        let user_id = UserId::generate();
        let linked_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let first_seen_at = linked_at + Duration::from_secs(60);
        let next_seen_at = first_seen_at + Duration::from_secs(120);

        let mut identity = ExternalIdentity::with_timestamps(
            tenant_id,
            user_id,
            OAuthProviderKind::GitHub,
            "github-sub-456",
            None,
            None,
            linked_at,
            first_seen_at,
        )
        .unwrap();

        identity.touch(next_seen_at);

        assert_eq!(identity.tenant_id(), tenant_id);
        assert_eq!(identity.user_id(), user_id);
        assert_eq!(identity.provider_kind(), OAuthProviderKind::GitHub);
        assert_eq!(identity.provider_subject(), "github-sub-456");
        assert_eq!(identity.linked_at(), linked_at);
        assert_eq!(identity.last_seen_at(), next_seen_at);
    }
}
