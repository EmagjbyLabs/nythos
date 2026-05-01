use nythos_core::{
    AccessToken, AuthError, Claims, NythosResult, Password, PasswordHash, PasswordHasher,
    RevocationChecker, SessionId, TenantId, TokenSigner, UserId,
};
use std::{cell::RefCell, collections::BTreeSet, str::FromStr};

use crate::support::fixtures::{canonical_access_token_ttl, canonical_issued_at};

#[derive(Default)]
pub struct FakePasswordHasher;

impl PasswordHasher for FakePasswordHasher {
    async fn hash(&self, password: &Password) -> NythosResult<PasswordHash> {
        PasswordHash::new(format!("argon2id${}", password.as_str()))
    }

    async fn verify(&self, password: &Password, hash: &PasswordHash) -> NythosResult<bool> {
        Ok(hash.as_str() == format!("argon2id${}", password.as_str()))
    }
}

#[derive(Default)]
pub struct FakeTokenSigner;

impl TokenSigner for FakeTokenSigner {
    async fn sign(&self, claims: &Claims) -> NythosResult<AccessToken> {
        AccessToken::new(format!(
            "signed:{}:{}",
            claims.subject(),
            claims.tenant_id()
        ))
    }

    async fn verify(&self, token: &AccessToken) -> NythosResult<Claims> {
        if token.as_str().is_empty() {
            return Err(AuthError::InvalidCredentials);
        }

        let mut parts = token.as_str().splitn(3, ':');
        let Some("signed") = parts.next() else {
            return Err(AuthError::InvalidCredentials);
        };
        let Some(encoded_subject) = parts.next() else {
            return Err(AuthError::InvalidCredentials);
        };
        let Some(encoded_tenant) = parts.next() else {
            return Err(AuthError::InvalidCredentials);
        };

        let user_id =
            UserId::from_str(encoded_subject).map_err(|_| AuthError::InvalidCredentials)?;
        let tenant_id =
            TenantId::from_str(encoded_tenant).map_err(|_| AuthError::InvalidCredentials)?;

        Claims::access(
            user_id,
            tenant_id,
            canonical_issued_at(),
            canonical_access_token_ttl(),
        )
    }
}

#[derive(Default)]
pub struct FakeRevocationChecker {
    revoked: RefCell<BTreeSet<SessionId>>,
}

impl FakeRevocationChecker {
    pub fn mark_revoked(&self, session_id: SessionId) {
        self.revoked.borrow_mut().insert(session_id);
    }
}

impl RevocationChecker for FakeRevocationChecker {
    async fn is_revoked(&self, session_id: SessionId) -> NythosResult<bool> {
        Ok(self.revoked.borrow().contains(&session_id))
    }
}
