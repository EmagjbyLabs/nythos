//! Authentication domain concepts and orchestration services.
//!
//! This module contains types such as `PasswordHash`, `Claims`,
//! `AccessToken`, and auth flow services.

mod issuance;

pub mod login;
pub mod oauth;
pub mod refresh;
pub mod register;
pub mod revoke;
pub mod tokens;

pub use login::{LoginAuthMaterial, LoginInput, LoginService};
pub use oauth::{OAuthLoginOutcome, OAuthLoginService};
pub use refresh::{RefreshAuthMaterial, RefreshInput, RefreshService};
pub use register::{RegisterAuthMaterial, RegisterInput, RegisterResult, RegisterService};
pub use revoke::{
    RevokeAllSessionsInput, RevokeAllSessionsService, RevokeResult, RevokeSessionInput,
    RevokeSessionService,
};
pub use tokens::{AccessToken, Claims, PasswordHash, TokenPurpose};
