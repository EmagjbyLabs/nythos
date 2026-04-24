//!
//! Public core library for Nythos.
//!
//! `nythos-core` contains domain logic and trait contracts only.
//! It intentionally excludes HTTP, storage drivers, and other infrastructure.

pub mod auth;
pub mod domain;
pub mod error;
pub mod ports;
pub mod rbac;
pub mod session;

pub use auth::{AccessToken, Claims, PasswordHash, TokenPurpose};
pub use domain::{
    Email, Password, RoleId, SessionId, Tenant, TenantId, TenantSettings, User, UserId, UserStatus,
};
pub use error::{AuthError, NythosResult};
pub use ports::{NewUser, RoleAssignmentInput, RoleRepository, UserRepository};
pub use rbac::{Permission, Role, RoleAssignment, RoleRegistry};
pub use session::{RefreshToken, Session};
