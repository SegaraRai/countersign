//! How strongly the person behind a decision has been verified.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Assurance level of a decision, ordered from weakest to strongest.
///
/// Channels declare the highest level they can vouch for; policies declare the
/// lowest level they accept for an approval. Denials are accepted at any level
/// from an eligible approver, because refusing access can never widen it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Assurance {
    /// An external account (chat user, signed callback URL) previously linked
    /// to the approver. Only as strong as that external account.
    Linked,
    /// An authenticated web session.
    Web,
    /// A web session whose identity-provider authentication happened within
    /// the freshness window (re-authenticated for this decision).
    FreshAuth,
}

impl fmt::Display for Assurance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Linked => "linked",
            Self::Web => "web",
            Self::FreshAuth => "fresh-auth",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_is_weakest_first() {
        assert!(Assurance::Linked < Assurance::Web);
        assert!(Assurance::Web < Assurance::FreshAuth);
    }

    #[test]
    fn serde_names() {
        let a: Assurance = serde_json::from_str("\"fresh-auth\"").unwrap();
        assert_eq!(a, Assurance::FreshAuth);
        assert_eq!(serde_json::to_string(&Assurance::Linked).unwrap(), "\"linked\"");
    }
}
