//! Pure trait contracts required by `nythos-core`.
//!
//! Implementations of these ports live outside the core crate.

pub mod role;
pub mod security;
pub mod session;
pub mod user;

pub use role::{RoleAssignmentInput, RoleRepository};
pub use security::{PasswordHasher, RevocationChecker, TokenSigner};
pub use session::{RefreshTokenRotation, SessionRecord, SessionStore};
pub use user::{NewUser, UserCredentials, UserRepository};
