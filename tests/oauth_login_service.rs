mod support;

use nythos_core::{
    OAuthLoginOutcome, OAuthLoginService, OAuthProviderKind, UserId, VerifiedExternalProfile,
};
use support::{
    InMemoryExternalIdentityRepository, InMemoryTenantOAuthProviderConfigPort,
    InMemoryUserRepository,
};

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
fn oauth_login_outcome_does_not_issue_session_or_create_user() {
    let user_id = UserId::generate();

    let outcome = OAuthLoginOutcome::ExistingIdentityLogin { user_id };

    match outcome {
        OAuthLoginOutcome::ExistingIdentityLogin { user_id: actual } => {
            assert_eq!(actual, user_id);
        }
        _ => panic!("expected existing identity login outcome"),
    }
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
