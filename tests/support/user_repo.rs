use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

use nythos_core::{
    AuthError, Email, NewUser, NythosResult, PasswordHash, TenantId, User, UserCredentials, UserId,
    UserRepository, UserStatus,
};

use crate::support::fixtures::canonical_issued_at;

type UserStore = BTreeMap<(TenantId, UserId), (User, PasswordHash)>;

#[derive(Clone)]
pub struct InMemoryUserRepository {
    users: Rc<RefCell<UserStore>>,
}

impl InMemoryUserRepository {
    pub fn new() -> Self {
        Self {
            users: Rc::new(RefCell::new(BTreeMap::new())),
        }
    }
}

impl Default for InMemoryUserRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl UserRepository for InMemoryUserRepository {
    async fn find_by_email(
        &self,
        tenant_id: TenantId,
        email: &Email,
    ) -> NythosResult<Option<User>> {
        Ok(self
            .users
            .borrow()
            .iter()
            .find(|((stored_tenant, _), (user, _))| {
                *stored_tenant == tenant_id && user.email() == email
            })
            .map(|(_, (user, _))| user.clone()))
    }

    async fn find_by_username(
        &self,
        tenant_id: TenantId,
        username: &nythos_core::Username,
    ) -> NythosResult<Option<User>> {
        Ok(self
            .users
            .borrow()
            .iter()
            .find(|((stored_tenant, _), (user, _))| {
                *stored_tenant == tenant_id && user.username() == Some(username)
            })
            .map(|(_, (user, _))| user.clone()))
    }

    async fn find_by_id(&self, tenant_id: TenantId, user_id: UserId) -> NythosResult<Option<User>> {
        Ok(self
            .users
            .borrow()
            .get(&(tenant_id, user_id))
            .map(|(user, _)| user.clone()))
    }

    async fn find_credentials_by_email(
        &self,
        tenant_id: TenantId,
        email: &Email,
    ) -> NythosResult<Option<UserCredentials>> {
        Ok(self
            .users
            .borrow()
            .iter()
            .find(|((stored_tenant, _), (user, _))| {
                *stored_tenant == tenant_id && user.email() == email
            })
            .map(|(_, (user, hash))| UserCredentials::new(user.clone(), hash.clone())))
    }

    async fn find_credentials_by_username(
        &self,
        tenant_id: TenantId,
        username: &nythos_core::Username,
    ) -> NythosResult<Option<UserCredentials>> {
        Ok(self
            .users
            .borrow()
            .iter()
            .find(|((stored_tenant, _), (user, _))| {
                *stored_tenant == tenant_id && user.username() == Some(username)
            })
            .map(|(_, (user, hash))| UserCredentials::new(user.clone(), hash.clone())))
    }

    async fn create(
        &self,
        tenant_id: TenantId,
        new_user: NewUser,
        password_hash: PasswordHash,
    ) -> NythosResult<User> {
        if self
            .find_by_email(tenant_id, new_user.email())
            .await?
            .is_some()
        {
            return Err(AuthError::ValidationError(
                "user with email already exists in tenant".to_owned(),
            ));
        }

        if let Some(username) = new_user.username()
            && self.find_by_username(tenant_id, username).await?.is_some()
        {
            return Err(AuthError::ValidationError(
                "user with username already exists in tenant".to_owned(),
            ));
        }

        let (email, username, display_name) = new_user.into_parts();
        let user = User::with_profile(
            UserId::generate(),
            email,
            username,
            display_name,
            UserStatus::Active,
            canonical_issued_at(),
        );

        self.users
            .borrow_mut()
            .insert((tenant_id, user.id()), (user.clone(), password_hash));

        Ok(user)
    }

    async fn update_status(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        status: UserStatus,
    ) -> NythosResult<()> {
        let mut users = self.users.borrow_mut();
        let (user, _) = users
            .get_mut(&(tenant_id, user_id))
            .ok_or(AuthError::UserNotFound)?;
        user.set_status(status);
        Ok(())
    }
}
