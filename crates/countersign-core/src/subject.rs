//! What a request is about, and who is involved in it.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::id::{ActorId, BackendName, ClientId};

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

/// The authenticated party that delivered a request.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    /// Pushed to the intake API with a client credential.
    Client(ClientId),
    /// Discovered by countersign polling a backend.
    Backend(BackendName),
}

impl Source {
    /// The client or backend name.
    pub fn name(&self) -> &str {
        match self {
            Self::Client(c) => c.as_str(),
            Self::Backend(b) => b.as_str(),
        }
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(c) => write!(f, "client {c}"),
            Self::Backend(b) => write!(f, "backend {b}"),
        }
    }
}

/// Whose action needs approval, as reported (and vouched for) by the source.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Requester {
    /// Source-local identifier (an Octelium user name, an OS user).
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Groups the source reports (e.g. Octelium groups).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub groups: BTreeSet<String>,
    /// The requester's identity in the source's namespace
    /// (`unix:<client>#<user>`, `octelium:<backend>#<user>`). Set by
    /// countersign, never by the source.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub identity: String,
    /// The actor that identity belongs to, if any, resolved when the request
    /// was opened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<ActorId>,
}

/// The person who caused a request, as far as the source can tell (the
/// `actor` of a CI run, the owner of an agent session).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Initiator {
    /// A recognition identity, e.g. `github:<user id>`.
    pub identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// The person it belongs to, resolved when the request was opened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<ActorId>,
}

/// What a request asks to do, as its source describes it, for showing to
/// approvers. Policies match on [`SubjectFacts::attributes`], not on this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Action {
    /// A command line, exactly as the program that asks received it (for
    /// `sudo`: the whole `sudo` command line).
    Command {
        line: Vec<String>,
        /// Who the command runs as.
        runas: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        /// Remarks for approvers from countersign's reading of the line
        /// (e.g. why command-specific policies did not apply).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        notes: Vec<String>,
    },
    /// A network session waiting to be let through (Octelium).
    Session {
        /// Backend-defined session type (`client`, `clientless`, ...).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device: Option<String>,
        /// The user agent of the connecting program.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client: Option<String>,
        /// The credential the session authenticated with.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        credential: Option<String>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        browser: bool,
    },
    /// Anything else: a title and a few labelled lines (exec backends).
    Generic {
        title: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        lines: Vec<Detail>,
    },
}

/// A labelled value, as shown to approvers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detail {
    pub label: String,
    pub value: String,
}

impl Detail {
    pub fn new(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self { label: label.into(), value: value.into() }
    }
}

/// Facts about a subject that its source vouches for. Never taken from the
/// requester's own claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectFacts {
    /// Set by countersign from the authenticated source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    pub requester: Requester,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiator: Option<Initiator>,
    /// What the access is for, if the backend knows (host, service, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "humantime_serde")]
    pub requested_ttl: Option<Duration>,
    /// Free text supplied by the requester. Displayed, never trusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// What the request asks to do, for approvers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,
    /// Additional backend-defined attributes, usable in policy matchers.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
    /// The requester asked to keep the details out of chat channels.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sensitive: bool,
    /// What the backend's answer must be bound to (for the intake API: the
    /// submission's invocation digest and nonce, see
    /// [`crate::approval_signing`]). Not displayed and not matched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<String>,
}

impl SubjectFacts {
    /// Facts with just a requester.
    pub fn new(requester: Requester) -> Self {
        Self {
            source: None,
            requester,
            initiator: None,
            target: None,
            requested_ttl: None,
            reason: None,
            action: None,
            attributes: BTreeMap::new(),
            sensitive: false,
            binding: None,
        }
    }
}

/// A subject the backend reports as waiting for a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingSubject {
    pub subject: SubjectRef,
    pub facts: SubjectFacts,
    pub observed_at: Timestamp,
}
