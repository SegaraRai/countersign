//! People and workloads involved in a request.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::id::ApproverId;

/// Who asked for access, as reported (and vouched for) by the backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Requester {
    /// Backend-local identifier (e.g. an Octelium user name).
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Backend-reported groups.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub groups: BTreeSet<String>,
    /// Globally namespaced identities of the requester, used to detect
    /// self-approval (e.g. `"oidc:https://id.example.com#<sub>"`).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub identities: BTreeSet<String>,
}

/// A person who may decide on requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approver {
    pub id: ApproverId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub groups: BTreeSet<String>,
    /// Identities that belong to the same person, in the same namespace as
    /// [`Requester::identities`].
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub identities: BTreeSet<String>,
}

impl Approver {
    /// Whether this approver is (as far as we can tell) the requester.
    pub fn is_same_person_as(&self, requester: &Requester) -> bool {
        !self.identities.is_disjoint(&requester.identities)
    }
}
