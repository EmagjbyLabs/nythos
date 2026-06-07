use std::{cell::RefCell, collections::BTreeMap, rc::Rc, time::SystemTime};

use nythos_core::{
    AuthError, ExternalIdentity, ExternalIdentityRepository, NythosResult, OAuthProviderKind,
    TenantId, UserId,
};

type ExternalIdentityKey = (TenantId, OAuthProviderKind, String);
type ExternalIdentityStore = BTreeMap<ExternalIdentityKey, ExternalIdentity>;

#[derive(Clone)]
pub struct InMemoryExternalIdentityRepository {
    identities: Rc<RefCell<ExternalIdentityStore>>,
}

impl InMemoryExternalIdentityRepository {
    pub fn new() -> Self {
        Self {
            identities: Rc::new(RefCell::new(BTreeMap::new())),
        }
    }

    fn key(
        tenant_id: TenantId,
        provider_kind: OAuthProviderKind,
        provider_subject: &str,
    ) -> ExternalIdentityKey {
        (tenant_id, provider_kind, provider_subject.trim().to_owned())
    }
}

impl Default for InMemoryExternalIdentityRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl ExternalIdentityRepository for InMemoryExternalIdentityRepository {
    async fn find_by_provider(
        &self,
        tenant_id: TenantId,
        provider_kind: OAuthProviderKind,
        provider_subject: &str,
    ) -> NythosResult<Option<ExternalIdentity>> {
        Ok(self
            .identities
            .borrow()
            .get(&Self::key(tenant_id, provider_kind, provider_subject))
            .cloned())
    }

    async fn find_by_user(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> NythosResult<Vec<ExternalIdentity>> {
        Ok(self
            .identities
            .borrow()
            .values()
            .filter(|identity| identity.tenant_id() == tenant_id && identity.user_id() == user_id)
            .cloned()
            .collect())
    }

    async fn link(&self, identity: ExternalIdentity) -> NythosResult<()> {
        let key = Self::key(
            identity.tenant_id(),
            identity.provider_kind(),
            identity.provider_subject(),
        );

        let mut identities = self.identities.borrow_mut();

        if identities.contains_key(&key) {
            return Err(AuthError::OAuthIdentityAlreadyLinked);
        }

        identities.insert(key, identity);
        Ok(())
    }

    async fn touch(
        &self,
        tenant_id: TenantId,
        provider_kind: OAuthProviderKind,
        provider_subject: &str,
        seen_at: SystemTime,
    ) -> NythosResult<()> {
        let mut identities = self.identities.borrow_mut();

        let identity = identities
            .get_mut(&Self::key(tenant_id, provider_kind, provider_subject))
            .ok_or(AuthError::UserNotFound)?;

        identity.touch(seen_at);

        Ok(())
    }
}
