mod support;

use futures::executor::block_on;
use nythos_core::{
    AuthError, ExternalIdentity, ExternalIdentityRepository, OAuthProviderKind, TenantId, UserId,
};
use std::time::{Duration, SystemTime};
use support::InMemoryExternalIdentityRepository;

fn external_identity(
    tenant_id: TenantId,
    user_id: UserId,
    provider_kind: OAuthProviderKind,
    provider_subject: &str,
) -> ExternalIdentity {
    ExternalIdentity::new(
        tenant_id,
        user_id,
        provider_kind,
        provider_subject,
        None,
        None,
        SystemTime::UNIX_EPOCH,
    )
    .unwrap()
}

#[test]
fn link_and_find_by_provider_round_trips_identity() {
    block_on(async {
        let repo = InMemoryExternalIdentityRepository::new();
        let tenant_id = TenantId::generate();
        let user_id = UserId::generate();

        let identity = external_identity(
            tenant_id,
            user_id,
            OAuthProviderKind::Google,
            "google-sub-123",
        );

        repo.link(identity.clone()).await.unwrap();

        let found = repo
            .find_by_provider(tenant_id, OAuthProviderKind::Google, "google-sub-123")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(found, identity);
    });
}

#[test]
fn find_by_provider_is_tenant_scoped() {
    block_on(async {
        let repo = InMemoryExternalIdentityRepository::new();
        let tenant_a = TenantId::generate();
        let tenant_b = TenantId::generate();

        let identity = external_identity(
            tenant_a,
            UserId::generate(),
            OAuthProviderKind::Google,
            "shared-subject",
        );

        repo.link(identity).await.unwrap();

        assert!(
            repo.find_by_provider(tenant_a, OAuthProviderKind::Google, "shared-subject")
                .await
                .unwrap()
                .is_some()
        );

        assert!(
            repo.find_by_provider(tenant_b, OAuthProviderKind::Google, "shared-subject")
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn find_by_provider_is_provider_scoped() {
    block_on(async {
        let repo = InMemoryExternalIdentityRepository::new();
        let tenant_id = TenantId::generate();

        let identity = external_identity(
            tenant_id,
            UserId::generate(),
            OAuthProviderKind::Google,
            "shared-subject",
        );

        repo.link(identity).await.unwrap();

        assert!(
            repo.find_by_provider(tenant_id, OAuthProviderKind::Google, "shared-subject")
                .await
                .unwrap()
                .is_some()
        );

        assert!(
            repo.find_by_provider(tenant_id, OAuthProviderKind::GitHub, "shared-subject")
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn duplicate_provider_subject_in_tenant_returns_already_linked() {
    block_on(async {
        let repo = InMemoryExternalIdentityRepository::new();
        let tenant_id = TenantId::generate();

        let first = external_identity(
            tenant_id,
            UserId::generate(),
            OAuthProviderKind::Google,
            "google-sub-123",
        );

        let second = external_identity(
            tenant_id,
            UserId::generate(),
            OAuthProviderKind::Google,
            "google-sub-123",
        );

        repo.link(first).await.unwrap();

        let result = repo.link(second).await;

        assert!(matches!(result, Err(AuthError::OAuthIdentityAlreadyLinked)));
    });
}

#[test]
fn same_provider_subject_allowed_in_different_tenants() {
    block_on(async {
        let repo = InMemoryExternalIdentityRepository::new();
        let tenant_a = TenantId::generate();
        let tenant_b = TenantId::generate();

        let first = external_identity(
            tenant_a,
            UserId::generate(),
            OAuthProviderKind::Google,
            "shared-subject",
        );

        let second = external_identity(
            tenant_b,
            UserId::generate(),
            OAuthProviderKind::Google,
            "shared-subject",
        );

        repo.link(first).await.unwrap();
        repo.link(second).await.unwrap();

        assert!(
            repo.find_by_provider(tenant_a, OAuthProviderKind::Google, "shared-subject")
                .await
                .unwrap()
                .is_some()
        );

        assert!(
            repo.find_by_provider(tenant_b, OAuthProviderKind::Google, "shared-subject")
                .await
                .unwrap()
                .is_some()
        );
    });
}

#[test]
fn find_by_user_returns_all_tenant_user_identities() {
    block_on(async {
        let repo = InMemoryExternalIdentityRepository::new();
        let tenant_id = TenantId::generate();
        let user_id = UserId::generate();

        repo.link(external_identity(
            tenant_id,
            user_id,
            OAuthProviderKind::Google,
            "google-sub-123",
        ))
        .await
        .unwrap();

        repo.link(external_identity(
            tenant_id,
            user_id,
            OAuthProviderKind::GitHub,
            "github-sub-123",
        ))
        .await
        .unwrap();

        let identities = repo.find_by_user(tenant_id, user_id).await.unwrap();

        assert_eq!(identities.len(), 2);
    });
}

#[test]
fn find_by_user_does_not_cross_tenants() {
    block_on(async {
        let repo = InMemoryExternalIdentityRepository::new();
        let tenant_a = TenantId::generate();
        let tenant_b = TenantId::generate();
        let user_id = UserId::generate();

        repo.link(external_identity(
            tenant_a,
            user_id,
            OAuthProviderKind::Google,
            "tenant-a-subject",
        ))
        .await
        .unwrap();

        repo.link(external_identity(
            tenant_b,
            user_id,
            OAuthProviderKind::Google,
            "tenant-b-subject",
        ))
        .await
        .unwrap();

        let tenant_a_identities = repo.find_by_user(tenant_a, user_id).await.unwrap();
        let tenant_b_identities = repo.find_by_user(tenant_b, user_id).await.unwrap();

        assert_eq!(tenant_a_identities.len(), 1);
        assert_eq!(tenant_b_identities.len(), 1);
        assert_eq!(
            tenant_a_identities[0].provider_subject(),
            "tenant-a-subject"
        );
        assert_eq!(
            tenant_b_identities[0].provider_subject(),
            "tenant-b-subject"
        );
    });
}

#[test]
fn touch_updates_last_seen_at() {
    block_on(async {
        let repo = InMemoryExternalIdentityRepository::new();
        let tenant_id = TenantId::generate();
        let user_id = UserId::generate();
        let linked_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let first_seen_at = linked_at + Duration::from_secs(60);
        let next_seen_at = linked_at + Duration::from_secs(120);

        let identity = ExternalIdentity::with_timestamps(
            tenant_id,
            user_id,
            OAuthProviderKind::Google,
            "google-sub-123",
            None,
            None,
            linked_at,
            first_seen_at,
        )
        .unwrap();

        repo.link(identity).await.unwrap();

        repo.touch(
            tenant_id,
            OAuthProviderKind::Google,
            "google-sub-123",
            next_seen_at,
        )
        .await
        .unwrap();

        let found = repo
            .find_by_provider(tenant_id, OAuthProviderKind::Google, "google-sub-123")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(found.linked_at(), linked_at);
        assert_eq!(found.last_seen_at(), next_seen_at);
    });
}

#[test]
fn ports_module_external_identity_repository_export_remains_usable() {
    fn assert_external_identity_repository<T: ExternalIdentityRepository>() {}

    assert_external_identity_repository::<InMemoryExternalIdentityRepository>();
}
