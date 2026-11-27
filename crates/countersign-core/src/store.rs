//! Durable state and the event outbox.
//!
//! Implementations must write a request and its events atomically, so that a
//! state change is never visible without the notifications it implies (and
//! vice versa).

use std::time::Duration;

use async_trait::async_trait;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;

use crate::actor::{IdpSnapshot, Standing, Suspension};
use crate::channel::MessageRef;
use crate::event::DomainEvent;
use crate::id::{ActorId, ChannelName, EventId, RequestId};
use crate::question::Question;
use crate::request::Request;
use crate::subject::SubjectRef;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Optimistic concurrency check failed: someone else updated the request.
    #[error("request {0} was modified concurrently")]
    Conflict(RequestId),
    #[error("request {0} not found")]
    NotFound(RequestId),
    /// An open (non-terminal) request already exists for this subject.
    #[error("an open request already exists for this subject")]
    Duplicate,
    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestFilter {
    /// Only requests that can still change.
    pub open_only: bool,
    pub limit: Option<u32>,
}

/// A chat account linked to a person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountLink {
    pub channel: ChannelName,
    pub external_id: String,
    pub person: ActorId,
    pub linked_at: Timestamp,
}

/// A browser Web Push subscription belonging to a person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushSubscription {
    pub id: String,
    pub person: ActorId,
    pub endpoint: String,
    pub p256dh: String,
    pub auth: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub created_at: Timestamp,
}

/// Something an admin did, kept as an audit record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminAction {
    pub at: Timestamp,
    pub by: ActorId,
    /// `suspend`, `reinstate`, `unlink`, `revoke-approved-by`, ...
    pub action: String,
    /// What it was done to (an actor id, a chat account).
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// An outbox entry claimed for delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxItem {
    pub id: EventId,
    pub event: DomainEvent,
    pub attempts: u32,
}

#[async_trait]
pub trait Store: Send + Sync {
    /// Insert a new request with its events. Fails with
    /// [`StoreError::Duplicate`] if an open request exists for the subject.
    async fn insert_request(&self, request: &Request, events: &[DomainEvent]) -> Result<(), StoreError>;

    /// Replace a request if its stored version is `expected_version`, and
    /// enqueue `events`, in one transaction.
    async fn update_request(
        &self,
        request: &Request,
        expected_version: u64,
        events: &[DomainEvent],
    ) -> Result<(), StoreError>;

    async fn get_request(&self, id: RequestId) -> Result<Option<Request>, StoreError>;

    /// The open request for a subject, if any.
    async fn find_open_by_subject(&self, subject: &SubjectRef) -> Result<Option<Request>, StoreError>;

    /// The most recently created request for a subject, open or not. Used to
    /// avoid re-opening a subject that was already decided.
    async fn find_latest_by_subject(&self, subject: &SubjectRef) -> Result<Option<Request>, StoreError>;

    /// Approvals only; see [`Store::list_questions`].
    async fn list_requests(&self, filter: &RequestFilter) -> Result<Vec<Request>, StoreError>;

    /// Insert a new question with its events.
    async fn insert_question(&self, question: &Question, events: &[DomainEvent]) -> Result<(), StoreError>;

    /// Replace a question if its stored version is `expected_version`, and
    /// enqueue `events`. The old body is overwritten, not kept.
    async fn update_question(
        &self,
        question: &Question,
        expected_version: u64,
        events: &[DomainEvent],
    ) -> Result<(), StoreError>;

    async fn get_question(&self, id: RequestId) -> Result<Option<Question>, StoreError>;

    async fn list_questions(&self, filter: &RequestFilter) -> Result<Vec<Question>, StoreError>;

    /// Closed questions that may still hold confidential content.
    async fn questions_holding_content(&self) -> Result<Vec<Question>, StoreError>;

    /// Lease up to `limit` due outbox items for `lease`. Leased items are not
    /// returned again until the lease expires or they are failed.
    async fn claim_outbox(&self, limit: u32, lease: Duration, now: Timestamp) -> Result<Vec<OutboxItem>, StoreError>;

    async fn complete_outbox(&self, id: EventId) -> Result<(), StoreError>;

    /// Record a failed delivery and schedule the next attempt.
    async fn fail_outbox(&self, id: EventId, retry_at: Timestamp, error: &str) -> Result<(), StoreError>;

    /// Record that `channel` has handled event `id`, so a retry caused by
    /// another channel does not deliver it twice.
    async fn mark_delivered(&self, id: EventId, channel: &ChannelName) -> Result<(), StoreError>;

    /// Channels that have already handled event `id`.
    async fn delivered_channels(&self, id: EventId) -> Result<Vec<ChannelName>, StoreError>;

    /// Remember a posted message so later events can update it.
    async fn save_message_ref(&self, request_id: RequestId, msg: &MessageRef) -> Result<(), StoreError>;

    async fn message_refs(&self, request_id: RequestId) -> Result<Vec<MessageRef>, StoreError>;

    /// Link an external account (e.g. a chat user id) to a person.
    async fn link_account(&self, channel: &ChannelName, external_id: &str, person: &ActorId) -> Result<(), StoreError>;

    async fn resolve_account(&self, channel: &ChannelName, external_id: &str) -> Result<Option<ActorId>, StoreError>;

    /// All account links, ordered by channel and external id.
    async fn list_account_links(&self) -> Result<Vec<AccountLink>, StoreError>;

    /// Remove a link. Returns whether one existed.
    async fn unlink_account(&self, channel: &ChannelName, external_id: &str) -> Result<bool, StoreError>;

    /// Suspend an actor (replacing an earlier suspension).
    async fn suspend(&self, actor: &ActorId, suspension: &Suspension) -> Result<(), StoreError>;

    /// Lift a suspension. Returns whether one existed.
    async fn reinstate(&self, actor: &ActorId) -> Result<bool, StoreError>;

    async fn suspensions(&self) -> Result<BTreeMap<ActorId, Suspension>, StoreError>;

    /// Remember the identity-provider groups from a person's latest sign-in.
    async fn save_idp_snapshot(&self, person: &ActorId, snapshot: &IdpSnapshot) -> Result<(), StoreError>;

    async fn idp_snapshots(&self) -> Result<BTreeMap<ActorId, IdpSnapshot>, StoreError>;

    async fn record_admin_action(&self, action: &AdminAction) -> Result<(), StoreError>;

    /// The most recent admin actions, newest first.
    async fn admin_actions(&self, limit: u32) -> Result<Vec<AdminAction>, StoreError>;

    /// Suspensions and identity-provider snapshots together.
    async fn standing(&self) -> Result<Standing, StoreError> {
        Ok(Standing { suspended: self.suspensions().await?, idp: self.idp_snapshots().await? })
    }

    /// Save or update a browser Web Push subscription for a person.
    async fn save_push_subscription(&self, sub: &PushSubscription) -> Result<(), StoreError> {
        let _ = sub;
        Ok(())
    }

    /// List Web Push subscriptions, optionally filtered to one person.
    async fn list_push_subscriptions(&self, person: Option<&ActorId>) -> Result<Vec<PushSubscription>, StoreError> {
        let _ = person;
        Ok(Vec::new())
    }

    /// Delete a Web Push subscription by its endpoint (e.g. after 404/410 Gone).
    async fn delete_push_subscription(&self, endpoint: &str) -> Result<bool, StoreError> {
        let _ = endpoint;
        Ok(false)
    }

    /// Delete one of `person`'s Web Push subscriptions by id.
    async fn delete_push_subscription_for_person(&self, person: &ActorId, id: &str) -> Result<bool, StoreError> {
        let _ = (person, id);
        Ok(false)
    }
}
