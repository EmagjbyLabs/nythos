use crate::{AccessToken, Claims, NythosResult, Password, PasswordHash, SessionId};

/// Password hashing port used by registration and login flows.
///
/// The expected outer implementation is Argon2id. This contract exists to keep
/// the core infrastructure-agnostic, not to treat weak hashing algorithms as
/// equivalent alternatives.
pub trait PasswordHasher {
    /// Hashes a validated raw password into a stored password-hash value.
    fn hash(&self, password: &Password) -> NythosResult<PasswordHash>;

    /// Verifies a validated raw password against a stored hash.
    fn verify(&self, password: &Password, hash: &PasswordHash) -> NythosResult<bool>;
}

/// Token signing port used to issue and verify signed access tokens.
///
/// This contract operates on core domain types only.  It must not expose HTTP,
/// bearer-header, or concrete JWT-library types at the boundary.
pub trait TokenSigner {
    /// Signs a structured claim set into an access token.
    fn sign(&self, claims: &Claims) -> NythosResult<AccessToken>;

    /// Verifies an access token and returns the structured claims it carries.
    fn verify(&self, token: &AccessToken) -> NythosResult<Claims>;
}

/// Revocation-checking port used by authenticated request flows.
///
/// Outer layers typically verify the access token first, then use this contract
/// to reject requests whose owning session has been revoked.
pub trait RevocationChecker {
    /// Returns whether the provided session has been revoked.
    fn is_revoked(&self, session_id: SessionId) -> NythosResult<bool>;
}
