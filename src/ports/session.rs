use crate::{NythosResult, RefreshToken, Session, SessionId, TenantId, UserId};

/// Domain-facing session payload used when auth services persist or reload a
/// session together with its current opaque refresh token.
///
/// This keeps the contract focused on core session state instead of storage
/// rows, token tables, or transport-layer cookie shapes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    session: Session,
    refresh_token: RefreshToken,
}

impl SessionRecord {
    pub fn new(session: Session, refresh_token: RefreshToken) -> Self {
        Self {
            session,
            refresh_token,
        }
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn refresh_token(&self) -> &RefreshToken {
        &self.refresh_token
    }

    pub fn into_parts(self) -> (Session, RefreshToken) {
        (self.session, self.refresh_token)
    }
}

/// Refresh-token rotation command.
///
/// Makes one-time rotation semantics explicit at the contract boundary.
/// This is a domain-facing command, not a storage-specific mutation DTO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshTokenRotation {
    session_id: SessionId,
    previous: RefreshToken,
    next: RefreshToken,
}

impl RefreshTokenRotation {
    pub fn new(session_id: SessionId, previous: RefreshToken, next: RefreshToken) -> Self {
        Self {
            session_id,
            previous,
            next,
        }
    }

    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn previous(&self) -> &RefreshToken {
        &self.previous
    }

    pub fn next(&self) -> &RefreshToken {
        &self.next
    }

    pub fn into_parts(self) -> (SessionId, RefreshToken, RefreshToken) {
        (self.session_id, self.previous, self.next)
    }
}

/// Session store contract used by register, login, refresh, logout, and revoke flows.
///
/// Rotation semantics are explicit at the API boundary:
/// - sessions are created together with one opaque refresh token
/// - refresh-token lookup returns the owning session context
/// - successful rotation invalidates the previous refresh token in favor of the next one
/// - revoke-all is always tenant-scoped
pub trait SessionStore {
    /// Persists a newly issued session together with its initial refresh token.
    fn create_session(&self, record: SessionRecord) -> NythosResult<()>;

    /// Finds the session currently associated with an opaque refresh token.
    fn find_by_refresh_token(
        &self,
        refresh_token: &RefreshToken,
    ) -> NythosResult<Option<SessionRecord>>;

    /// Rotates a refresh token for a specific session.
    ///
    /// Implementations should treat the `previous` token as invalid after a
    /// successful rotation.
    fn rotate_refresh_token(&self, rotation: RefreshTokenRotation) -> NythosResult<()>;

    /// Revokes a single session by ID.
    fn revoke_session(&self, session_id: SessionId) -> NythosResult<()>;

    /// Revokes all sessions owned by a user within a specific tenant.
    fn revoke_all_for_user(&self, tenant_id: TenantId, user_id: UserId) -> NythosResult<()>;
}
