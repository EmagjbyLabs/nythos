//! Pure trait contracts required by `nythos-core`.
//!
//! Implementations of these ports live outside the core crate.

use crate::{Email, NythosResult, PasswordHash, TenantId, User, UserId, UserStatus};

/// Domain-facing input used when creating a new user inside a tenant.
///
/// This keeps repository contracts focused on core data rather than storage
/// payloads or transport DTOs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewUser {
    email: Email,
}

impl NewUser {
    pub fn new(email: Email) -> Self {
        Self { email }
    }

    pub fn email(&self) -> &Email {
        &self.email
    }

    pub fn into_email(self) -> Email {
        self.email
    }
}

/// Tenant-scoped user repository contract used by registration and login flows.
///
/// All lookup and mutation methods that depend on tenant context require an
/// explicit `TenantId`. Implementations must not perform cross-tenant lookups
/// behind the scenes.
///
/// Duplicate-user and not-found behavior should be expressed through the core
/// result model and return shapes, rather than leaking database-specific errors.
pub trait UserRepository {
    /// Finds a user by normalized email within a specific tenant.
    fn find_by_email(&self, tenant_id: TenantId, email: &Email) -> NythosResult<Option<User>>;

    /// Finds a user by ID within a specific tenant.
    fn find_by_id(&self, tenant_id: TenantId, user_id: UserId) -> NythosResult<Option<User>>;

    /// Creates a new user in the given tenant using an already-validated email
    /// and an already-produced password hash.
    ///
    /// Implementations should make duplicate handling explicit through the core
    /// error model.
    fn create(
        &self,
        tenant_id: TenantId,
        new_user: NewUser,
        password_hash: PasswordHash,
    ) -> NythosResult<User>;

    /// Updates a user's status within a specific tenant boundary.
    fn update_status(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        status: UserStatus,
    ) -> NythosResult<()>;
}

#[cfg(test)]
mod tests {
    use super::{NewUser, UserRepository};
    use crate::{AuthError, Email, PasswordHash, TenantId, User, UserId, UserStatus};
    use std::{cell::RefCell, collections::BTreeMap, rc::Rc, time::SystemTime};

    type TestStore = BTreeMap<(TenantId, UserId), (User, PasswordHash)>;

    #[derive(Clone)]
    struct InMemoryUserRepository {
        users: Rc<RefCell<TestStore>>,
    }

    impl InMemoryUserRepository {
        fn new() -> Self {
            Self {
                users: Rc::new(RefCell::new(BTreeMap::new())),
            }
        }
    }

    impl UserRepository for InMemoryUserRepository {
        fn find_by_email(
            &self,
            tenant_id: TenantId,
            email: &Email,
        ) -> crate::NythosResult<Option<User>> {
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
        ) -> crate::NythosResult<Option<User>> {
            Ok(self
                .users
                .borrow()
                .get(&(tenant_id, user_id))
                .map(|(user, _)| user.clone()))
        }

        fn create(
            &self,
            tenant_id: TenantId,
            new_user: NewUser,
            password_hash: PasswordHash,
        ) -> crate::NythosResult<User> {
            if self.find_by_email(tenant_id, new_user.email())?.is_some() {
                return Err(AuthError::ValidationError(
                    "user with email already exists in tenant".to_owned(),
                ));
            }

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
        ) -> crate::NythosResult<()> {
            let mut users = self.users.borrow_mut();
            let (user, _) = users
                .get_mut(&(tenant_id, user_id))
                .ok_or(AuthError::UserNotFound)?;

            user.set_status(status);
            Ok(())
        }
    }

    #[test]
    fn new_user_wraps_domain_email() {
        let email = Email::parse("person@example.com").unwrap();
        let new_user = NewUser::new(email.clone());

        assert_eq!(new_user.email(), &email);
    }

    #[test]
    fn repository_lookups_are_tenant_scoped() {
        let repo = InMemoryUserRepository::new();
        let tenant_a = TenantId::generate();
        let tenant_b = TenantId::generate();
        let email = Email::parse("person@example.com").unwrap();

        let created = repo
            .create(
                tenant_a,
                NewUser::new(email.clone()),
                PasswordHash::new("hash".to_owned()).unwrap(),
            )
            .unwrap();

        assert!(repo.find_by_email(tenant_a, &email).unwrap().is_some());
        assert!(repo.find_by_email(tenant_b, &email).unwrap().is_none());
        assert!(repo.find_by_id(tenant_a, created.id()).unwrap().is_some());
    }

    #[test]
    fn duplicate_user_handling_is_expressible_through_core_errors() {
        let repo = InMemoryUserRepository::new();
        let tenant_id = TenantId::generate();
        let email = Email::parse("person@example.com").unwrap();

        repo.create(
            tenant_id,
            NewUser::new(email.clone()),
            PasswordHash::new("hash".to_owned()).unwrap(),
        )
        .unwrap();

        let result = repo.create(
            tenant_id,
            NewUser::new(email.clone()),
            PasswordHash::new("hash".to_owned()).unwrap(),
        );

        assert!(matches!(
            result,
            Err(AuthError::ValidationError(msg)) if msg.contains("already exists")
        ));
    }

    #[test]
    fn update_status_is_tenant_scoped_and_not_found_aware() {
        let repo = InMemoryUserRepository::new();
        let tenant_id = TenantId::generate();
        let other_tenant = TenantId::generate();

        let email = Email::parse("person@example.com").unwrap();
        let user = repo
            .create(
                tenant_id,
                NewUser::new(email.clone()),
                PasswordHash::new("hash".to_owned()).unwrap(),
            )
            .unwrap();

        repo.update_status(tenant_id, user.id(), UserStatus::Locked)
            .unwrap();

        let updated = repo.find_by_id(tenant_id, user.id()).unwrap().unwrap();
        assert_eq!(updated.status(), UserStatus::Locked);

        let result = repo.update_status(other_tenant, user.id(), UserStatus::Disabled);
        assert!(matches!(result, Err(AuthError::UserNotFound)));
    }
}
