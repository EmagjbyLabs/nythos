use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

use nythos_core::{
    NythosResult, OAuthProviderKind, TenantId, TenantOAuthProviderConfig,
    TenantOAuthProviderConfigPort,
};

type TenantOAuthProviderConfigKey = (TenantId, OAuthProviderKind);
type TenantOAuthProviderConfigStore =
    BTreeMap<TenantOAuthProviderConfigKey, TenantOAuthProviderConfig>;

#[derive(Clone)]
pub struct InMemoryTenantOAuthProviderConfigPort {
    configs: Rc<RefCell<TenantOAuthProviderConfigStore>>,
}

impl InMemoryTenantOAuthProviderConfigPort {
    pub fn new() -> Self {
        Self {
            configs: Rc::new(RefCell::new(BTreeMap::new())),
        }
    }

    pub fn insert_config(&self, config: TenantOAuthProviderConfig) {
        self.configs
            .borrow_mut()
            .insert((config.tenant_id(), config.provider_kind()), config);
    }
}

impl Default for InMemoryTenantOAuthProviderConfigPort {
    fn default() -> Self {
        Self::new()
    }
}

impl TenantOAuthProviderConfigPort for InMemoryTenantOAuthProviderConfigPort {
    async fn load_provider_config(
        &self,
        tenant_id: TenantId,
        provider_kind: OAuthProviderKind,
    ) -> NythosResult<Option<TenantOAuthProviderConfig>> {
        Ok(self
            .configs
            .borrow()
            .get(&(tenant_id, provider_kind))
            .cloned())
    }
}
