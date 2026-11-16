//! The system that actually holds access.

use std::time::Duration;

use async_trait::async_trait;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::id::BackendName;
use crate::subject::{PendingSubject, SubjectFacts, SubjectRef};

/// What a backend implementation supports.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct BackendCaps {
    /// Can list subjects waiting for a decision (pull model).
    pub discover: bool,
    /// Can take back an active grant before it expires.
    pub revoke: bool,
    /// Enforces grant expiry itself; otherwise countersign must call
    /// [`AccessBackend::revoke`] when the TTL elapses.
    pub native_expiry: bool,
}

/// Reference to an active grant, as returned by [`AccessBackend::grant`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantHandle {
    pub subject: SubjectRef,
    /// Backend-specific handle, if the subject id alone is not enough.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_ref: Option<String>,
    /// When the backend will end the grant on its own, if it does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
}

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// The subject no longer exists (e.g. the session was withdrawn).
    #[error("subject not found")]
    NotFound,
    /// The subject is not in a state that allows this operation.
    #[error("conflict: {0}")]
    Conflict(String),
    /// Temporary failure; the caller may retry.
    #[error("backend unavailable: {0}")]
    Unavailable(String),
    #[error("operation not supported by this backend")]
    Unsupported,
    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

impl BackendError {
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Unavailable(_))
    }
}

/// A system that can grant, deny, and revoke access for subjects.
///
/// Implementations must treat [`verify`](Self::verify) as the source of truth:
/// countersign re-reads facts from the backend before acting and never trusts
/// data supplied by the requester.
#[async_trait]
pub trait AccessBackend: Send + Sync {
    fn name(&self) -> &BackendName;

    /// The provider part of requester identities from this backend, e.g.
    /// `octelium`. countersign writes requester identities as
    /// `<scheme>:<backend name>#<requester id>`, so a backend can only vouch
    /// for identities in its own namespace.
    fn identity_scheme(&self) -> &'static str;

    fn capabilities(&self) -> BackendCaps;

    /// Subjects currently waiting for a decision. Only called when
    /// [`BackendCaps::discover`] is set.
    async fn discover_pending(&self) -> Result<Vec<PendingSubject>, BackendError>;

    /// Re-read the authoritative facts about a subject.
    async fn verify(&self, subject: &SubjectRef) -> Result<SubjectFacts, BackendError>;

    /// Grant access for at most `ttl`.
    async fn grant(&self, subject: &SubjectRef, ttl: Duration) -> Result<GrantHandle, BackendError>;

    async fn deny(&self, subject: &SubjectRef) -> Result<(), BackendError>;

    /// End an active grant. Only called when [`BackendCaps::revoke`] is set.
    async fn revoke(&self, grant: &GrantHandle) -> Result<(), BackendError>;
}
