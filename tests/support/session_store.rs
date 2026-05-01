use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

use nythos_core::{
    AuthError, NythosResult, RefreshToken, RefreshTokenRotation, SessionId, SessionRecord,
    SessionStore,
};

type SessionStoreMap = BTreeMap<SessionId, SessionRecord>;
type RefreshIndex = BTreeMap<String, SessionId>;

#[derive(Clone)]
pub struct InMemorySessionStore {
    records: Rc<RefCell<SessionStoreMap>>,
    refresh_index: Rc<RefCell<RefreshIndex>>,
}

impl InMemorySessionStore {
    pub fn new() -> Self {
        Self {
            records: Rc::new(RefCell::new(BTreeMap::new())),
            refresh_index: Rc::new(RefCell::new(BTreeMap::new())),
        }
    }
}

impl Default for InMemorySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore for InMemorySessionStore {
    async fn create_session(&self, record: SessionRecord) -> NythosResult<()> {
        let session_id = record.session().id();
        let refresh_key = record.refresh_token().as_str().to_owned();

        self.refresh_index
            .borrow_mut()
            .insert(refresh_key, session_id);
        self.records.borrow_mut().insert(session_id, record);
        Ok(())
    }

    async fn find_by_refresh_token(
        &self,
        refresh_token: &RefreshToken,
    ) -> NythosResult<Option<SessionRecord>> {
        let index = self.refresh_index.borrow();
        let records = self.records.borrow();

        Ok(index
            .get(refresh_token.as_str())
            .and_then(|session_id| records.get(session_id))
            .cloned())
    }

    async fn rotate_refresh_token(&self, rotation: RefreshTokenRotation) -> NythosResult<()> {
        let (session_id, previous, next) = rotation.into_parts();

        let mut index = self.refresh_index.borrow_mut();
        let mut records = self.records.borrow_mut();

        let record = records
            .get_mut(&session_id)
            .ok_or(AuthError::SessionRevoked)?;

        let indexed_session = index
            .get(previous.as_str())
            .copied()
            .ok_or(AuthError::InvalidCredentials)?;

        if indexed_session != session_id {
            return Err(AuthError::InvalidCredentials);
        }

        index.remove(previous.as_str());
        index.insert(next.as_str().to_owned(), session_id);
        *record = SessionRecord::new(record.session().clone(), next);

        Ok(())
    }

    async fn revoke_session(&self, session_id: SessionId) -> NythosResult<()> {
        let mut records = self.records.borrow_mut();
        let record = records
            .get_mut(&session_id)
            .ok_or(AuthError::SessionRevoked)?;

        let refresh_key = record.refresh_token().as_str().to_owned();
        let mut session = record.session().clone();
        session.revoke();
        *record = SessionRecord::new(session, record.refresh_token().clone());
        self.refresh_index.borrow_mut().remove(&refresh_key);

        Ok(())
    }

    async fn revoke_all_for_user(
        &self,
        tenant_id: nythos_core::TenantId,
        user_id: nythos_core::UserId,
    ) -> NythosResult<()> {
        let mut records = self.records.borrow_mut();
        let mut index = self.refresh_index.borrow_mut();

        for record in records.values_mut() {
            if record.session().tenant_id() == tenant_id && record.session().user_id() == user_id {
                let refresh_key = record.refresh_token().as_str().to_owned();
                let mut session = record.session().clone();
                session.revoke();
                *record = SessionRecord::new(session, record.refresh_token().clone());
                index.remove(&refresh_key);
            }
        }

        Ok(())
    }
}
