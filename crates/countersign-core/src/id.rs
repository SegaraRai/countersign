//! Identifier newtypes.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! uuid_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            /// A new time-ordered (`UUIDv7`) identifier.
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl std::str::FromStr for $name {
            type Err = uuid::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(s).map(Self)
            }
        }
    };
}

macro_rules! name_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub fn new(s: impl Into<String>) -> Self {
                Self(s.into())
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self(s.to_owned())
            }
        }
    };
}

uuid_id!(
    /// Identifies an access request.
    RequestId
);
uuid_id!(
    /// Identifies an outbox entry.
    EventId
);

name_id!(
    /// Configured name of a backend instance (e.g. `"oct-main"`).
    BackendName
);
name_id!(
    /// Configured name of a channel instance (e.g. `"discord-ops"`).
    ChannelName
);
name_id!(
    /// Name of a policy rule.
    PolicyName
);
name_id!(
    /// Stable identifier of a person or workload known to countersign. Never
    /// reused, so old records keep pointing at the same actor.
    ActorId
);
name_id!(
    /// Configured name of a client of the intake API (e.g. a host).
    ClientId
);
