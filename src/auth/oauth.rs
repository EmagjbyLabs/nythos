//! OAuth login and explicit identity-linking decisions.
//!
//! `nythos-core` receives `VerifiedExternalProfile` values after the gateway or
//! provider adapter has completed OAuth verification. This module does not own
//! redirects, state/CSRF, PKCE, token exchange, provider token validation, JWKS,
//! provider userinfo calls, cookies, client credentials, HTTP routes,
//! runtime/framework behavior, user creation, or OAuth session issuance.

use std::time::SystemTime;

use crate::{
    AuthError, ExternalIdentity, ExternalIdentityRepository, NythosResult, OAuthProviderKind,
    TenantId, TenantOAuthProviderConfigPort, User, UserId, UserRepository, VerifiedExternalProfile,
};

/// The domain outcome of resolving an OAuth login attempt.
///
/// These variants represent expected auth states, not transport errors.
/// The caller decides whether to issue a session, show a linking flow,
/// start registration, or reject the request.
///
/// In v0.2.1, core returns the decision only. It does not issue OAuth sessions
/// or create users for any outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthLoginOutcome {
    /// The provider is disabled or not configured for the tenant.
    ProviderDisabled { provider_kind: OAuthProviderKind },

    /// An existing external identity was found and can proceed to login.
    ///
    /// Session issuance is intentionally not performed by this outcome.
    ExistingIdentityLogin { user_id: UserId },

    /// A verified provider email matched an existing user, but no external
    /// identity is linked yet. The gateway should ask for explicit consent
    /// before linking.
    LinkRequired {
        user_id: UserId,
        profile: VerifiedExternalProfile,
    },

    /// No existing linked identity or matching active user was found.
    ///
    /// The caller decides whether to present registration based on
    /// `registration_allowed`.
    RegistrationRequired {
        profile: VerifiedExternalProfile,
        registration_allowed: bool,
    },
}

/// OAuth login/linking orchestration service.
///
/// This service owns only domain decisions. It does not perform OAuth
/// redirects, provider HTTP calls, token verification, user creation, or
/// session issuance.
pub struct OAuthLoginService<'a, I, U, C>
where
    I: ExternalIdentityRepository,
    U: UserRepository,
    C: TenantOAuthProviderConfigPort,
{
    identity_repository: &'a I,
    user_repository: &'a U,
    oauth_config_port: &'a C,
}

impl<'a, I, U, C> OAuthLoginService<'a, I, U, C>
where
    I: ExternalIdentityRepository,
    U: UserRepository,
    C: TenantOAuthProviderConfigPort,
{
    /// Creates an OAuth login service over tenant-scoped repository ports.
    pub fn new(
        identity_repository: &'a I,
        user_repository: &'a U,
        oauth_config_port: &'a C,
    ) -> Self {
        Self {
            identity_repository,
            user_repository,
            oauth_config_port,
        }
    }

    /// Returns the external identity repository used by this service.
    pub fn identity_repository(&self) -> &'a I {
        self.identity_repository
    }

    /// Returns the user repository used for tenant-scoped user lookups.
    pub fn user_repository(&self) -> &'a U {
        self.user_repository
    }

    /// Returns the tenant OAuth provider configuration port.
    pub fn oauth_config_port(&self) -> &'a C {
        self.oauth_config_port
    }

    /// Resolves the domain outcome for an OAuth login attempt.
    ///
    /// This method does not create users, link external identities, issue
    /// sessions, or validate provider tokens. It only decides what should happen
    /// next based on tenant provider configuration, existing external identity
    /// links, linked-user status, verified-email matching, registration policy,
    /// and matched-user status.
    ///
    /// Decision order matches the implementation: disabled or missing provider
    /// config returns `ProviderDisabled`; an existing provider identity returns
    /// `ExistingIdentityLogin` after status checks and last-seen update; a
    /// verified email match returns `LinkRequired`; otherwise the result is
    /// `RegistrationRequired` with the tenant provider registration policy.
    pub async fn resolve_login(
        &self,
        tenant_id: TenantId,
        profile: VerifiedExternalProfile,
        now: SystemTime,
    ) -> NythosResult<OAuthLoginOutcome> {
        let provider_kind = profile.provider_kind();

        let Some(config) = self
            .oauth_config_port
            .load_provider_config(tenant_id, provider_kind)
            .await?
        else {
            return Ok(OAuthLoginOutcome::ProviderDisabled { provider_kind });
        };

        if !config.is_enabled() {
            return Ok(OAuthLoginOutcome::ProviderDisabled { provider_kind });
        }

        if let Some(identity) = self
            .identity_repository
            .find_by_provider(tenant_id, provider_kind, profile.provider_subject())
            .await?
        {
            let user = self
                .user_repository
                .find_by_id(tenant_id, identity.user_id())
                .await?
                .ok_or(AuthError::UserNotFoundOrInactive)?;

            Self::ensure_user_is_active(&user)?;

            self.identity_repository
                .touch(tenant_id, provider_kind, profile.provider_subject(), now)
                .await?;

            return Ok(OAuthLoginOutcome::ExistingIdentityLogin {
                user_id: identity.user_id(),
            });
        }

        if let Some(email) = profile.verified_email()
            && let Some(user) = self.user_repository.find_by_email(tenant_id, email).await?
        {
            Self::ensure_user_is_active(&user)?;

            return Ok(OAuthLoginOutcome::LinkRequired {
                user_id: user.id(),
                profile,
            });
        }

        Ok(OAuthLoginOutcome::RegistrationRequired {
            profile,
            registration_allowed: config.registration_allowed(),
        })
    }

    /// Explicitly links a verified external profile to an existing active user.
    ///
    /// This method should be called only after gateway has obtained explicit
    /// user consent. It validates that the target user exists and can
    /// authenticate, rejects duplicate provider-subject linkage, and persists
    /// the new external identity through `ExternalIdentityRepository`.
    ///
    /// It does not create users, issue sessions, perform provider verification,
    /// or re-check provider enablement.
    pub async fn link_identity(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        profile: VerifiedExternalProfile,
        now: SystemTime,
    ) -> NythosResult<ExternalIdentity> {
        let user = self
            .user_repository
            .find_by_id(tenant_id, user_id)
            .await?
            .ok_or(AuthError::UserNotFoundOrInactive)?;

        Self::ensure_user_is_active(&user)?;

        if let Some(existing_identity) = self
            .identity_repository
            .find_by_provider(
                tenant_id,
                profile.provider_kind(),
                profile.provider_subject(),
            )
            .await?
        {
            if existing_identity.user_id() == user_id {
                return Err(AuthError::OAuthIdentityAlreadyLinkedToSelf);
            }

            return Err(AuthError::OAuthIdentityAlreadyLinked);
        }

        let identity = ExternalIdentity::new(
            tenant_id,
            user_id,
            profile.provider_kind(),
            profile.provider_subject(),
            profile.email().cloned(),
            profile.display_name().cloned(),
            now,
        )?;

        self.identity_repository.link(identity.clone()).await?;

        Ok(identity)
    }

    fn ensure_user_is_active(user: &User) -> NythosResult<()> {
        if !user.can_authenticate() {
            return Err(AuthError::UserNotFoundOrInactive);
        }

        Ok(())
    }
}
