use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

use nythos_core::{NythosResult, TenantAuthPolicy, TenantId, TenantPolicyPort};

type PolicyStore = BTreeMap<TenantId, TenantAuthPolicy>;

#[derive(Clone)]
pub struct FakeTenantPolicyPort {
    default_policy: TenantAuthPolicy,
    policies: Rc<RefCell<PolicyStore>>,
}

impl FakeTenantPolicyPort {
    pub fn new(default_policy: TenantAuthPolicy) -> Self {
        Self {
            default_policy,
            policies: Rc::new(RefCell::new(BTreeMap::new())),
        }
    }

    pub fn insert_policy(&self, tenant_id: TenantId, policy: TenantAuthPolicy) {
        self.policies.borrow_mut().insert(tenant_id, policy);
    }
}

impl Default for FakeTenantPolicyPort {
    fn default() -> Self {
        Self::new(TenantAuthPolicy::default())
    }
}

impl TenantPolicyPort for FakeTenantPolicyPort {
    async fn load_auth_policy(&self, tenant_id: TenantId) -> NythosResult<TenantAuthPolicy> {
        Ok(self
            .policies
            .borrow()
            .get(&tenant_id)
            .copied()
            .unwrap_or(self.default_policy))
    }
}
