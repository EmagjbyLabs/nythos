use std::time::SystemTime;

use crate::{
    AuthError, ExternalIdentityRepository, NythosResult, OAuthProviderKind, TenantId,
    TenantOAuthProviderConfigPort, User, UserId, UserRepository, UserStatus,
    VerifiedExternalProfile,
};

/// The domain outcome of resolving an OAuth login attempt.
///
/// These variants represent expected auth states, not transport errors.
/// The caller decides whether to issue a session, show a linking flow,
/// start registration, or reject the request.
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
/// redirect, provider HTTP calls, token verification, user creation, or
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

    pub fn identity_repository(&self) -> &'a I {
        self.identity_repository
    }

    pub fn user_repository(&self) -> &'a U {
        self.user_repository
    }

    pub fn oauth_config_port(&self) -> &'a C {
        self.oauth_config_port
    }

    /// Resolves the domain outcome for an OAuth login attempt.
    ///
    /// This method does not create users, link external identities, or issue
    /// sessions. It only decides what should happen next based on tenant
    /// provider configuration, existing external identity links, verified email
    /// matching, and account status.
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

    fn ensure_user_is_active(user: &User) -> NythosResult<()> {
        if user.status() != UserStatus::Active {
            return Err(AuthError::UserNotFoundOrInactive);
        }

        Ok(())
    }
}
