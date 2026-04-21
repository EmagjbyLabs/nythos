//! Foundational domain types and identity models.
//!
//! This module is the home for shared primitives such as typed IDs,
//! value objects, and core identity entities.

/// Placeholdre for domain types such as typed IDs, `Email`, `User`, and `Tenant`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DomainMarker;
