use crate::{NythosResult, RevocationChecker, SessionId, SessionStore, TenantId, UserId};

/// Input for revoking a single session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevokeSessionInput {
    session_id: SessionId,
}

impl RevokeSessionInput {
    pub const fn new(session_id: SessionId) -> Self {
        Self { session_id }
    }

    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }
}

/// Input for revoking all sessions for a user within a tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevokeAllSessionsInput {
    tenant_id: TenantId,
    user_id: UserId,
}

impl RevokeAllSessionsInput {
    pub const fn new(tenant_id: TenantId, user_id: UserId) -> Self {
        Self { tenant_id, user_id }
    }

    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    pub const fn user_id(&self) -> UserId {
        self.user_id
    }
}

/// Domain result for revoke operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevokeResult {
    revoked: bool,
}

impl RevokeResult {
    pub const fn new(revoked: bool) -> Self {
        Self { revoked }
    }

    pub const fn revoked(&self) -> bool {
        self.revoked
    }
}

/// Service for revoking a single session.
pub struct RevokeSessionService<'a, S, C> {
    session_store: &'a S,
    revocation_checker: &'a C,
}

impl<'a, S, C> RevokeSessionService<'a, S, C>
where
    S: SessionStore,
    C: RevocationChecker,
{
    pub fn new(session_store: &'a S, revocation_checker: &'a C) -> Self {
        Self {
            session_store,
            revocation_checker,
        }
    }

    pub fn revoke(&self, input: RevokeSessionInput) -> NythosResult<RevokeResult> {
        if self.revocation_checker.is_revoked(input.session_id())? {
            return Ok(RevokeResult::new(false));
        }

        self.session_store.revoke_session(input.session_id())?;
        Ok(RevokeResult::new(true))
    }
}

/// Service for revoking all sessions for a user within a tenant.
pub struct RevokeAllSessionsService<'a, S> {
    session_store: &'a S,
}

impl<'a, S> RevokeAllSessionsService<'a, S>
where
    S: SessionStore,
{
    pub fn new(session_store: &'a S) -> Self {
        Self { session_store }
    }

    pub fn revoke_all(&self, input: RevokeAllSessionsInput) -> NythosResult<RevokeResult> {
        self.session_store
            .revoke_all_for_user(input.tenant_id(), input.user_id())?;

        Ok(RevokeResult::new(true))
    }
}
