use std::str::FromStr;

use nythos_core::{AuthError, OAuthProviderKind};

#[test]
fn oauth_provider_kind_parses_stable_strings() {
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
fn oauth_provider_kind_rejects_unknown_provider() {
    let result = OAuthProviderKind::parse("facebook");

    assert!(matches!(result, Err(AuthError::ValidationError(_))));
}

#[test]
fn oauth_provider_kind_displays_stable_strings() {
    assert_eq!(OAuthProviderKind::Google.to_string(), "google");
    assert_eq!(OAuthProviderKind::GitHub.to_string(), "github");
    assert_eq!(OAuthProviderKind::Microsoft.to_string(), "microsoft");
}

#[test]
fn oauth_provider_kind_round_trips_through_from_str() {
    for provider in [
        OAuthProviderKind::Google,
        OAuthProviderKind::GitHub,
        OAuthProviderKind::Microsoft,
    ] {
        let parsed = OAuthProviderKind::from_str(provider.as_str()).unwrap();

        assert_eq!(parsed, provider);
    }
}

#[test]
fn oauth_provider_kind_parse_accepts_trimmed_case_variants() {
    assert_eq!(
        OAuthProviderKind::parse("  Google  ").unwrap(),
        OAuthProviderKind::Google
    );
    assert_eq!(
        OAuthProviderKind::parse("GitHub").unwrap(),
        OAuthProviderKind::GitHub
    );
    assert_eq!(
        OAuthProviderKind::parse("MICROSOFT").unwrap(),
        OAuthProviderKind::Microsoft
    );
}
