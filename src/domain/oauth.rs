//! OAuth provider and external identity domain models.
//!
//! This module contains the infrastructure-free OAauth domain surface used by
//! `nythos-core`. Provider redirects, token exchange, JWKS validation, provider
//! HTTP calls, and userinfo fetching remain outside core.

use std::{fmt, str::FromStr};

use crate::{AuthError, NythosResult};

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

#[cfg(test)]
mod tests {
    use super::OAuthProviderKind;
    use crate::AuthError;
    use std::str::FromStr;

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
}
