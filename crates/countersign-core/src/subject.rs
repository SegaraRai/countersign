//! What a request is about.

use std::collections::BTreeMap;
use std::time::Duration;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::id::BackendName;
use crate::principal::Requester;

/// A backend-side object whose access is being requested, such as a pending
/// Octelium session.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SubjectRef {
    pub backend: BackendName,
    /// Backend-defined kind (e.g. `"session"`).
    pub kind: String,
    /// Backend-defined identifier.
    pub id: String,
}

/// Facts about a subject that the backend vouches for. Never taken from the
/// requester's own claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectFacts {
    pub requester: Requester,
    /// What the access is for, if the backend knows (host, service, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "humantime_serde")]
    pub requested_ttl: Option<Duration>,
    /// Free text supplied by the requester. Displayed, never trusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Additional backend-defined attributes, usable in policy matchers.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
}

/// A subject the backend reports as waiting for a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingSubject {
    pub subject: SubjectRef,
    pub facts: SubjectFacts,
    pub observed_at: Timestamp,
}
