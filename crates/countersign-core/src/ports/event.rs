//! Domain events, emitted by state transitions and delivered via the outbox.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::id::{ActorId, RequestId};
use crate::request::Decision;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum DomainEvent {
    Requested {
        request_id: RequestId,
        at: Timestamp,
    },
    DecisionRecorded {
        request_id: RequestId,
        decision: Decision,
    },
    /// Quorum reached; the grant is about to be applied.
    Approved {
        request_id: RequestId,
        at: Timestamp,
    },
    Denied {
        request_id: RequestId,
        by: ActorId,
        at: Timestamp,
    },
    Granted {
        request_id: RequestId,
        until: Timestamp,
        at: Timestamp,
    },
    GrantFailed {
        request_id: RequestId,
        error: String,
        at: Timestamp,
    },
    /// Nobody decided before the pending timeout.
    Expired {
        request_id: RequestId,
        at: Timestamp,
    },
    /// The requester or backend dropped the request while pending.
    Withdrawn {
        request_id: RequestId,
        at: Timestamp,
    },
    Revoked {
        request_id: RequestId,
        by: Option<ActorId>,
        at: Timestamp,
    },
    /// An active grant reached its end.
    Ended {
        request_id: RequestId,
        at: Timestamp,
    },
    /// A question was answered.
    Answered {
        request_id: RequestId,
        by: ActorId,
        at: Timestamp,
    },
    /// A responder declined to answer a question.
    Declined {
        request_id: RequestId,
        by: ActorId,
        at: Timestamp,
    },
}

impl DomainEvent {
    pub fn request_id(&self) -> RequestId {
        match self {
            Self::Requested { request_id, .. }
            | Self::DecisionRecorded { request_id, .. }
            | Self::Approved { request_id, .. }
            | Self::Denied { request_id, .. }
            | Self::Granted { request_id, .. }
            | Self::GrantFailed { request_id, .. }
            | Self::Expired { request_id, .. }
            | Self::Withdrawn { request_id, .. }
            | Self::Revoked { request_id, .. }
            | Self::Ended { request_id, .. }
            | Self::Answered { request_id, .. }
            | Self::Declined { request_id, .. } => *request_id,
        }
    }

    /// Short machine-readable name, matching the serde tag.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Requested { .. } => "requested",
            Self::DecisionRecorded { .. } => "decision-recorded",
            Self::Approved { .. } => "approved",
            Self::Denied { .. } => "denied",
            Self::Granted { .. } => "granted",
            Self::GrantFailed { .. } => "grant-failed",
            Self::Expired { .. } => "expired",
            Self::Withdrawn { .. } => "withdrawn",
            Self::Revoked { .. } => "revoked",
            Self::Ended { .. } => "ended",
            Self::Answered { .. } => "answered",
            Self::Declined { .. } => "declined",
        }
    }
}
