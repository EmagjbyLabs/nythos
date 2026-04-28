use std::fmt;
use std::str::FromStr;

use uuid::Uuid;

macro_rules! typed_id {
    ($name:ident) => {
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            serde::Serialize,
            serde::Deserialize,
        )]
        pub struct $name(Uuid);

        impl $name {
            /// Creates a new typed ID from a raw UUID.
            pub const fn new(value: Uuid) -> Self {
                Self(value)
            }

            /// Generates a new random UUID.
            pub fn generate() -> Self {
                Self(Uuid::new_v4())
            }

            /// Returns the wrapped UUID by value.
            pub const fn into_uuid(self) -> Uuid {
                self.0
            }

            /// Returns a shared reference to the wrapped UUID.
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl From<Uuid> for $name {
            fn from(value: Uuid) -> Self {
                Self::new(value)
            }
        }

        impl From<$name> for Uuid {
            fn from(value: $name) -> Self {
                value.into_uuid()
            }
        }

        impl AsRef<Uuid> for $name {
            fn as_ref(&self) -> &Uuid {
                self.as_uuid()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(s).map(Self::new)
            }
        }
    };
}

typed_id!(UserId);
typed_id!(TenantId);
typed_id!(SessionId);
typed_id!(RoleId);

#[cfg(test)]
mod tests {
    use super::{RoleId, SessionId, TenantId, UserId};
    use std::str::FromStr;
    use uuid::Uuid;

    #[test]
    fn typed_ids_wrap_and_unwrap_uuid() {
        let raw = Uuid::new_v4();

        let user_id = UserId::new(raw);

        assert_eq!(user_id.as_uuid(), &raw);
        assert_eq!(user_id.into_uuid(), raw);
    }

    #[test]
    fn typed_ids_parse_and_format_round_trip() {
        let raw = Uuid::new_v4();

        let user_id = UserId::from_str(&raw.to_string()).unwrap();

        assert_eq!(user_id.to_string(), raw.to_string());
        assert_eq!(user_id.into_uuid(), raw);
    }

    #[test]
    fn typed_ids_support_equality_hashing_and_copy() {
        let raw = Uuid::new_v4();

        let a = TenantId::new(raw);
        let b = a;

        assert_eq!(a, b);

        let mut set = std::collections::HashSet::new();
        set.insert(a);

        assert!(set.contains(&b));
    }

    #[test]
    fn all_core_identity_types_exist_and_are_distinct() {
        let user_id = UserId::generate();
        let tenant_id = TenantId::generate();
        let session_id = SessionId::generate();
        let role_id = RoleId::generate();

        assert_ne!(user_id.to_string(), tenant_id.to_string());
        assert_ne!(session_id.to_string(), role_id.to_string());
    }
}
