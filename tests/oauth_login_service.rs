mod support;

use futures::executor::block_on;
use nythos_core::{
    AuthError, ExternalIdentity, ExternalIdentityRepository, NewUser, OAuthLoginOutcome,
    OAuthLoginService, OAuthProviderKind, PasswordHash, TenantId, TenantOAuthProviderConfig,
    UserId, UserRepository, UserStatus, VerifiedExternalProfile,
};
use std::time::{Duration, SystemTime};
use support::{
    InMemoryExternalIdentityRepository, InMemoryTenantOAuthProviderConfigPort,
    InMemoryUserRepository,
};

fn issued_at() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn later() -> SystemTime {
    issued_at() + Duration::from_secs(120)
}

fn google_profile() -> VerifiedExternalProfile {
    VerifiedExternalProfile::new(
        OAuthProviderKind::Google,
        "google-sub-123",
        None,
        false,
        None,
    )
    .unwrap()
}

fn verified_google_profile(email: &str) -> VerifiedExternalProfile {
    VerifiedExternalProfile::new(
        OAuthProviderKind::Google,
        "google-sub-123",
        Some(nythos_core::Email::parse(email).unwrap()),
        true,
        None,
    )
    .unwrap()
}

fn unverified_google_profile(email: &str) -> VerifiedExternalProfile {
    VerifiedExternalProfile::new(
        OAuthProviderKind::Google,
        "google-sub-123",
        Some(nythos_core::Email::parse(email).unwrap()),
        false,
        None,
    )
    .unwrap()
}

fn enabled_google_config(
    tenant_id: TenantId,
    registration_allowed: bool,
) -> TenantOAuthProviderConfig {
    TenantOAuthProviderConfig::new(
        tenant_id,
        OAuthProviderKind::Google,
        true,
        registration_allowed,
    )
}

fn disabled_google_config(tenant_id: TenantId) -> TenantOAuthProviderConfig {
    TenantOAuthProviderConfig::new(tenant_id, OAuthProviderKind::Google, false, true)
}

fn external_identity(
    tenant_id: TenantId,
    user_id: UserId,
    provider_subject: &str,
) -> ExternalIdentity {
    ExternalIdentity::new(
        tenant_id,
        user_id,
        OAuthProviderKind::Google,
        provider_subject,
        None,
        None,
        issued_at(),
    )
    .unwrap()
}

fn password_hash() -> PasswordHash {
    PasswordHash::new("hashed-password").unwrap()
}

#[test]
fn oauth_login_outcome_provider_disabled_is_constructible() {
    let outcome = OAuthLoginOutcome::ProviderDisabled {
        provider_kind: OAuthProviderKind::Google,
    };

    assert_eq!(
        outcome,
        OAuthLoginOutcome::ProviderDisabled {
            provider_kind: OAuthProviderKind::Google,
        }
    );
}

#[test]
fn oauth_login_outcome_existing_identity_login_is_constructible() {
    let user_id = UserId::generate();

    let outcome = OAuthLoginOutcome::ExistingIdentityLogin { user_id };

    assert_eq!(
        outcome,
        OAuthLoginOutcome::ExistingIdentityLogin { user_id }
    );
}

#[test]
fn oauth_login_outcome_link_required_is_constructible() {
    let user_id = UserId::generate();
    let profile = VerifiedExternalProfile::new(
        OAuthProviderKind::GitHub,
        "github-sub-123",
        None,
        false,
        None,
    )
    .unwrap();

    let outcome = OAuthLoginOutcome::LinkRequired {
        user_id,
        profile: profile.clone(),
    };

    assert_eq!(
        outcome,
        OAuthLoginOutcome::LinkRequired { user_id, profile }
    );
}

#[test]
fn oauth_login_outcome_registration_required_is_constructible() {
    let profile = VerifiedExternalProfile::new(
        OAuthProviderKind::Microsoft,
        "microsoft-sub-123",
        None,
        false,
        None,
    )
    .unwrap();

    let outcome = OAuthLoginOutcome::RegistrationRequired {
        profile: profile.clone(),
        registration_allowed: true,
    };

    assert_eq!(
        outcome,
        OAuthLoginOutcome::RegistrationRequired {
            profile,
            registration_allowed: true,
        }
    );
}

#[test]
fn oauth_login_service_borrows_dependencies() {
    let identities = InMemoryExternalIdentityRepository::new();
    let users = InMemoryUserRepository::new();
    let configs = InMemoryTenantOAuthProviderConfigPort::new();

    let service = OAuthLoginService::new(&identities, &users, &configs);

    let _identity_repo = service.identity_repository();
    let _user_repo = service.user_repository();
    let _oauth_config = service.oauth_config_port();
}

#[test]
fn resolve_login_returns_provider_disabled_when_config_missing() {
    block_on(async {
        let identities = InMemoryExternalIdentityRepository::new();
        let users = InMemoryUserRepository::new();
        let configs = InMemoryTenantOAuthProviderConfigPort::new();
        let service = OAuthLoginService::new(&identities, &users, &configs);

        let result = service
            .resolve_login(TenantId::generate(), google_profile(), issued_at())
            .await
            .unwrap();

        assert_eq!(
            result,
            OAuthLoginOutcome::ProviderDisabled {
                provider_kind: OAuthProviderKind::Google
            }
        );
    });
}

#[test]
fn resolve_login_returns_provider_disabled_when_config_disabled() {
    block_on(async {
        let identities = InMemoryExternalIdentityRepository::new();
        let users = InMemoryUserRepository::new();
        let configs = InMemoryTenantOAuthProviderConfigPort::new();
        let tenant_id = TenantId::generate();

        configs.insert_config(disabled_google_config(tenant_id));

        let service = OAuthLoginService::new(&identities, &users, &configs);

        let result = service
            .resolve_login(tenant_id, google_profile(), issued_at())
            .await
            .unwrap();

        assert_eq!(
            result,
            OAuthLoginOutcome::ProviderDisabled {
                provider_kind: OAuthProviderKind::Google
            }
        );
    });
}

#[test]
fn resolve_login_existing_identity_returns_existing_identity_login() {
    block_on(async {
        let identities = InMemoryExternalIdentityRepository::new();
        let users = InMemoryUserRepository::new();
        let configs = InMemoryTenantOAuthProviderConfigPort::new();
        let tenant_id = TenantId::generate();

        configs.insert_config(enabled_google_config(tenant_id, true));

        let user = users
            .create(
                tenant_id,
                NewUser::new(nythos_core::Email::parse("person@example.com").unwrap()),
                password_hash(),
            )
            .await
            .unwrap();

        identities
            .link(external_identity(tenant_id, user.id(), "google-sub-123"))
            .await
            .unwrap();

        let service = OAuthLoginService::new(&identities, &users, &configs);

        let result = service
            .resolve_login(tenant_id, google_profile(), later())
            .await
            .unwrap();

        assert_eq!(
            result,
            OAuthLoginOutcome::ExistingIdentityLogin { user_id: user.id() }
        );
    });
}

#[test]
fn resolve_login_existing_identity_touches_last_seen_at() {
    block_on(async {
        let identities = InMemoryExternalIdentityRepository::new();
        let users = InMemoryUserRepository::new();
        let configs = InMemoryTenantOAuthProviderConfigPort::new();
        let tenant_id = TenantId::generate();
        let now = later();

        configs.insert_config(enabled_google_config(tenant_id, true));

        let user = users
            .create(
                tenant_id,
                NewUser::new(nythos_core::Email::parse("person@example.com").unwrap()),
                password_hash(),
            )
            .await
            .unwrap();

        identities
            .link(external_identity(tenant_id, user.id(), "google-sub-123"))
            .await
            .unwrap();

        let service = OAuthLoginService::new(&identities, &users, &configs);

        service
            .resolve_login(tenant_id, google_profile(), now)
            .await
            .unwrap();

        let touched = identities
            .find_by_provider(tenant_id, OAuthProviderKind::Google, "google-sub-123")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(touched.last_seen_at(), now);
    });
}

#[test]
fn resolve_login_existing_identity_rejects_missing_user() {
    block_on(async {
        let identities = InMemoryExternalIdentityRepository::new();
        let users = InMemoryUserRepository::new();
        let configs = InMemoryTenantOAuthProviderConfigPort::new();
        let tenant_id = TenantId::generate();

        configs.insert_config(enabled_google_config(tenant_id, true));

        identities
            .link(external_identity(
                tenant_id,
                UserId::generate(),
                "google-sub-123",
            ))
            .await
            .unwrap();

        let service = OAuthLoginService::new(&identities, &users, &configs);

        let result = service
            .resolve_login(tenant_id, google_profile(), later())
            .await;

        assert!(matches!(result, Err(AuthError::UserNotFoundOrInactive)));
    });
}

#[test]
fn resolve_login_existing_identity_rejects_locked_user() {
    block_on(async {
        let identities = InMemoryExternalIdentityRepository::new();
        let users = InMemoryUserRepository::new();
        let configs = InMemoryTenantOAuthProviderConfigPort::new();
        let tenant_id = TenantId::generate();

        configs.insert_config(enabled_google_config(tenant_id, true));

        let user = users
            .create(
                tenant_id,
                NewUser::new(nythos_core::Email::parse("person@example.com").unwrap()),
                password_hash(),
            )
            .await
            .unwrap();

        users
            .update_status(tenant_id, user.id(), UserStatus::Locked)
            .await
            .unwrap();

        identities
            .link(external_identity(tenant_id, user.id(), "google-sub-123"))
            .await
            .unwrap();

        let service = OAuthLoginService::new(&identities, &users, &configs);

        let result = service
            .resolve_login(tenant_id, google_profile(), later())
            .await;

        assert!(matches!(result, Err(AuthError::UserNotFoundOrInactive)));
    });
}

#[test]
fn resolve_login_existing_identity_rejects_disabled_user() {
    block_on(async {
        let identities = InMemoryExternalIdentityRepository::new();
        let users = InMemoryUserRepository::new();
        let configs = InMemoryTenantOAuthProviderConfigPort::new();
        let tenant_id = TenantId::generate();

        configs.insert_config(enabled_google_config(tenant_id, true));

        let user = users
            .create(
                tenant_id,
                NewUser::new(nythos_core::Email::parse("person@example.com").unwrap()),
                password_hash(),
            )
            .await
            .unwrap();

        users
            .update_status(tenant_id, user.id(), UserStatus::Disabled)
            .await
            .unwrap();

        identities
            .link(external_identity(tenant_id, user.id(), "google-sub-123"))
            .await
            .unwrap();

        let service = OAuthLoginService::new(&identities, &users, &configs);

        let result = service
            .resolve_login(tenant_id, google_profile(), later())
            .await;

        assert!(matches!(result, Err(AuthError::UserNotFoundOrInactive)));
    });
}

#[test]
fn resolve_login_verified_email_match_returns_link_required() {
    block_on(async {
        let identities = InMemoryExternalIdentityRepository::new();
        let users = InMemoryUserRepository::new();
        let configs = InMemoryTenantOAuthProviderConfigPort::new();
        let tenant_id = TenantId::generate();
        let profile = verified_google_profile("person@example.com");

        configs.insert_config(enabled_google_config(tenant_id, true));

        let user = users
            .create(
                tenant_id,
                NewUser::new(nythos_core::Email::parse("person@example.com").unwrap()),
                password_hash(),
            )
            .await
            .unwrap();

        let service = OAuthLoginService::new(&identities, &users, &configs);

        let result = service
            .resolve_login(tenant_id, profile.clone(), issued_at())
            .await
            .unwrap();

        assert_eq!(
            result,
            OAuthLoginOutcome::LinkRequired {
                user_id: user.id(),
                profile,
            }
        );
    });
}

#[test]
fn resolve_login_unverified_email_does_not_lookup_user() {
    block_on(async {
        let identities = InMemoryExternalIdentityRepository::new();
        let users = InMemoryUserRepository::new();
        let configs = InMemoryTenantOAuthProviderConfigPort::new();
        let tenant_id = TenantId::generate();
        let profile = unverified_google_profile("person@example.com");

        configs.insert_config(enabled_google_config(tenant_id, true));

        users
            .create(
                tenant_id,
                NewUser::new(nythos_core::Email::parse("person@example.com").unwrap()),
                password_hash(),
            )
            .await
            .unwrap();

        let service = OAuthLoginService::new(&identities, &users, &configs);

        let result = service
            .resolve_login(tenant_id, profile.clone(), issued_at())
            .await
            .unwrap();

        assert_eq!(
            result,
            OAuthLoginOutcome::RegistrationRequired {
                profile,
                registration_allowed: true,
            }
        );
    });
}

#[test]
fn resolve_login_no_match_registration_allowed_returns_registration_required_true() {
    block_on(async {
        let identities = InMemoryExternalIdentityRepository::new();
        let users = InMemoryUserRepository::new();
        let configs = InMemoryTenantOAuthProviderConfigPort::new();
        let tenant_id = TenantId::generate();
        let profile = google_profile();

        configs.insert_config(enabled_google_config(tenant_id, true));

        let service = OAuthLoginService::new(&identities, &users, &configs);

        let result = service
            .resolve_login(tenant_id, profile.clone(), issued_at())
            .await
            .unwrap();

        assert_eq!(
            result,
            OAuthLoginOutcome::RegistrationRequired {
                profile,
                registration_allowed: true,
            }
        );
    });
}

#[test]
fn resolve_login_no_match_registration_disabled_returns_registration_required_false() {
    block_on(async {
        let identities = InMemoryExternalIdentityRepository::new();
        let users = InMemoryUserRepository::new();
        let configs = InMemoryTenantOAuthProviderConfigPort::new();
        let tenant_id = TenantId::generate();
        let profile = google_profile();

        configs.insert_config(enabled_google_config(tenant_id, false));

        let service = OAuthLoginService::new(&identities, &users, &configs);

        let result = service
            .resolve_login(tenant_id, profile.clone(), issued_at())
            .await
            .unwrap();

        assert_eq!(
            result,
            OAuthLoginOutcome::RegistrationRequired {
                profile,
                registration_allowed: false,
            }
        );
    });
}

#[test]
fn resolve_login_inactive_email_match_returns_user_not_found_or_inactive() {
    block_on(async {
        let identities = InMemoryExternalIdentityRepository::new();
        let users = InMemoryUserRepository::new();
        let configs = InMemoryTenantOAuthProviderConfigPort::new();
        let tenant_id = TenantId::generate();
        let profile = verified_google_profile("person@example.com");

        configs.insert_config(enabled_google_config(tenant_id, true));

        let user = users
            .create(
                tenant_id,
                NewUser::new(nythos_core::Email::parse("person@example.com").unwrap()),
                password_hash(),
            )
            .await
            .unwrap();

        users
            .update_status(tenant_id, user.id(), UserStatus::Disabled)
            .await
            .unwrap();

        let service = OAuthLoginService::new(&identities, &users, &configs);

        let result = service.resolve_login(tenant_id, profile, issued_at()).await;

        assert!(matches!(result, Err(AuthError::UserNotFoundOrInactive)));
    });
}

#[test]
fn resolve_login_does_not_cross_tenant_boundaries_for_verified_email() {
    block_on(async {
        let identities = InMemoryExternalIdentityRepository::new();
        let users = InMemoryUserRepository::new();
        let configs = InMemoryTenantOAuthProviderConfigPort::new();
        let tenant_a = TenantId::generate();
        let tenant_b = TenantId::generate();
        let profile = verified_google_profile("person@example.com");

        configs.insert_config(enabled_google_config(tenant_b, true));

        users
            .create(
                tenant_a,
                NewUser::new(nythos_core::Email::parse("person@example.com").unwrap()),
                password_hash(),
            )
            .await
            .unwrap();

        let service = OAuthLoginService::new(&identities, &users, &configs);

        let result = service
            .resolve_login(tenant_b, profile.clone(), issued_at())
            .await
            .unwrap();

        assert_eq!(
            result,
            OAuthLoginOutcome::RegistrationRequired {
                profile,
                registration_allowed: true,
            }
        );
    });
}

#[test]
fn oauth_login_provider_disabled_is_modeled_as_outcome_not_error() {
    let outcome = OAuthLoginOutcome::ProviderDisabled {
        provider_kind: OAuthProviderKind::Google,
    };

    match outcome {
        OAuthLoginOutcome::ProviderDisabled { provider_kind } => {
            assert_eq!(provider_kind, OAuthProviderKind::Google);
        }
        _ => panic!("expected provider disabled outcome"),
    }
}
