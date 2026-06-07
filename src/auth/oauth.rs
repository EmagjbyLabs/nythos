use crate::{
    ExternalIdentityRepository, OAuthProviderKind, TenantOAuthProviderConfigPort, UserId,
    UserRepository, VerifiedExternalProfile,
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
}
