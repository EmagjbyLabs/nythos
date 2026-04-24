use nythos_core::{
    Email, NewUser, PasswordHash, TenantId, User, UserId, UserRepository, UserStatus,
    ports::UserCredentials,
};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc, time::SystemTime};

type TestStore = BTreeMap<(TenantId, UserId), (User, PasswordHash)>;

#[derive(Clone)]
struct TestUserRepository {
    users: Rc<RefCell<TestStore>>,
}

impl TestUserRepository {
    fn new() -> Self {
        Self {
            users: Rc::new(RefCell::new(BTreeMap::new())),
        }
    }
}

impl UserRepository for TestUserRepository {
    fn find_by_email(
        &self,
        tenant_id: TenantId,
        email: &Email,
    ) -> nythos_core::NythosResult<Option<User>> {
        Ok(self
            .users
            .borrow()
            .iter()
            .find(|((stored_tenant, _), (user, _))| {
                *stored_tenant == tenant_id && user.email() == email
            })
            .map(|(_, (user, _))| user.clone()))
    }

    fn find_by_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> nythos_core::NythosResult<Option<User>> {
        Ok(self
            .users
            .borrow()
            .get(&(tenant_id, user_id))
            .map(|(user, _)| user.clone()))
    }

    fn find_credentials_by_email(
        &self,
        tenant_id: TenantId,
        email: &Email,
    ) -> nythos_core::NythosResult<Option<nythos_core::ports::UserCredentials>> {
        Ok(self
            .users
            .borrow()
            .iter()
            .find(|((stored_tenant, _), (user, _))| {
                *stored_tenant == tenant_id && user.email() == email
            })
            .map(|(_, (user, hash))| UserCredentials::new(user.clone(), hash.clone())))
    }

    fn create(
        &self,
        tenant_id: TenantId,
        new_user: NewUser,
        password_hash: PasswordHash,
    ) -> nythos_core::NythosResult<User> {
        let user = User::new(
            UserId::generate(),
            new_user.into_email(),
            SystemTime::UNIX_EPOCH,
        );
        self.users
            .borrow_mut()
            .insert((tenant_id, user.id()), (user.clone(), password_hash));
        Ok(user)
    }

    fn update_status(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        status: UserStatus,
    ) -> nythos_core::NythosResult<()> {
        let mut users = self.users.borrow_mut();
        let (user, _) = users
            .get_mut(&(tenant_id, user_id))
            .ok_or(nythos_core::AuthError::UserNotFound)?;
        user.set_status(status);
        Ok(())
    }
}

#[test]
fn contract_is_usable_for_login_and_registration_style_flows() {
    let repo = TestUserRepository::new();
    let tenant_id = TenantId::generate();
    let email = Email::parse("person@example.com").unwrap();

    let created = repo
        .create(
            tenant_id,
            NewUser::new(email.clone()),
            PasswordHash::new("hashed-password").unwrap(),
        )
        .unwrap();

    assert_eq!(
        repo.find_by_email(tenant_id, &email).unwrap().unwrap().id(),
        created.id()
    );
    assert_eq!(
        repo.find_by_id(tenant_id, created.id())
            .unwrap()
            .unwrap()
            .email(),
        &email
    );
}

#[test]
fn tenant_context_is_explicit_on_all_lookup_paths() {
    let repo = TestUserRepository::new();
    let tenant_a = TenantId::generate();
    let tenant_b = TenantId::generate();

    let created = repo
        .create(
            tenant_a,
            NewUser::new(Email::parse("person@example.com").unwrap()),
            PasswordHash::new("hashed-password").unwrap(),
        )
        .unwrap();

    assert!(repo.find_by_id(tenant_a, created.id()).unwrap().is_some());
    assert!(repo.find_by_id(tenant_b, created.id()).unwrap().is_none());
}
