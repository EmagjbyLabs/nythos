//! Foundational domain types and identity models.
//!
//! This module is the home for shared primitives such as typed IDs,
//! value objects, and core identity entities.

pub mod identity;
pub mod ids;
pub mod oauth;
pub mod value_objects;

pub use identity::{Tenant, TenantAuthPolicy, TenantSettings, User, UserStatus};
pub use ids::{RoleId, SessionId, TenantId, UserId};
pub use oauth::{ExternalIdentity, OAuthProviderKind};
pub use value_objects::{DisplayName, Email, LoginIdentifier, Password, Username};
