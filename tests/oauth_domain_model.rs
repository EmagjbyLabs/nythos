use std::{
    str::FromStr,
    time::{Duration, SystemTime},
};

use nythos_core::{
    AuthError, DisplayName, Email, ExternalIdentity, OAuthProviderKind, TenantId, UserId,
};

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
fn external_identity_with_timestamps_preserves_explicit_times() {
    let linked_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let last_seen_at = linked_at + Duration::from_secs(60);

    let identity = ExternalIdentity::with_timestamps(
        TenantId::generate(),
        UserId::generate(),
        OAuthProviderKind::GitHub,
        "github-sub-123",
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
fn external_identity_requires_subject() {
    let result = ExternalIdentity::new(
        TenantId::generate(),
        UserId::generate(),
        OAuthProviderKind::Google,
        "   ",
        None,
        None,
        SystemTime::UNIX_EPOCH,
    );

    assert!(matches!(result, Err(AuthError::ValidationError(_))));
}

#[test]
fn external_identity_stores_tenant_user_provider_subject() {
    let tenant_id = TenantId::generate();
    let user_id = UserId::generate();

    let identity = ExternalIdentity::new(
        tenant_id,
        user_id,
        OAuthProviderKind::Microsoft,
        "microsoft-sub-123",
        None,
        None,
        SystemTime::UNIX_EPOCH,
    )
    .unwrap();

    assert_eq!(identity.tenant_id(), tenant_id);
    assert_eq!(identity.user_id(), user_id);
    assert_eq!(identity.provider_kind(), OAuthProviderKind::Microsoft);
    assert_eq!(identity.provider_subject(), "microsoft-sub-123");
}

#[test]
fn external_identity_stores_optional_provider_metadata() {
    let email = Email::parse("Person@Example.com").unwrap();
    let display_name = DisplayName::parse("Person Example").unwrap();

    let identity = ExternalIdentity::new(
        TenantId::generate(),
        UserId::generate(),
        OAuthProviderKind::Google,
        "google-sub-123",
        Some(email.clone()),
        Some(display_name.clone()),
        SystemTime::UNIX_EPOCH,
    )
    .unwrap();

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
fn external_identity_touch_updates_last_seen_at() {
    let linked_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let first_seen_at = linked_at + Duration::from_secs(60);
    let next_seen_at = linked_at + Duration::from_secs(120);

    let mut identity = ExternalIdentity::with_timestamps(
        TenantId::generate(),
        UserId::generate(),
        OAuthProviderKind::Google,
        "google-sub-123",
        None,
        None,
        linked_at,
        first_seen_at,
    )
    .unwrap();

    identity.touch(next_seen_at);

    assert_eq!(identity.linked_at(), linked_at);
    assert_eq!(identity.last_seen_at(), next_seen_at);
}
