//!
//! Public core library for Nythos.
//!
//! `nythos-core` contains implemented domain models, orchestration services,
//! and trait contracts only.
//! It intentionally excludes HTTP, storage drivers, and other infrastructure.
//! The crate root re-exports the main public surface, with grouped access also
//! available under `auth`, `domain`, `ports`, `rbac`, `session`, and `error`.

pub mod auth;
pub mod domain;
pub mod error;
pub mod ports;
pub mod rbac;
pub mod session;

pub use auth::{
    AccessToken, Claims, LoginAuthMaterial, LoginInput, LoginService, PasswordHash,
    RefreshAuthMaterial, RefreshInput, RefreshService, RegisterAuthMaterial, RegisterInput,
    RegisterResult, RegisterService, RevokeAllSessionsInput, RevokeAllSessionsService,
    RevokeResult, RevokeSessionInput, RevokeSessionService, TokenPurpose,
};
pub use domain::{
    Email, Password, RoleId, SessionId, Tenant, TenantId, TenantSettings, User, UserId, UserStatus,
};
pub use error::{AuthError, NythosResult};
pub use ports::{
    NewUser, PasswordHasher, RefreshTokenRotation, RevocationChecker, RoleAssignmentInput,
    RoleRepository, SessionRecord, SessionStore, TokenSigner, UserCredentials, UserRepository,
};
pub use rbac::{Permission, Role, RoleAssignment, RoleRegistry};
pub use session::{RefreshToken, Session};
