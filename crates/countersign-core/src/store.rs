//! Durable state and the event outbox.
//!
//! Implementations must write a request and its events atomically, so that a
//! state change is never visible without the notifications it implies (and
//! vice versa).

use std::time::Duration;

use async_trait::async_trait;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::channel::MessageRef;
use crate::event::DomainEvent;
use crate::id::{ApproverId, ChannelName, EventId, RequestId};
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

/// A chat account linked to an approver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountLink {
    pub channel: ChannelName,
    pub external_id: String,
    pub approver: ApproverId,
    pub linked_at: Timestamp,
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

    async fn list_requests(&self, filter: &RequestFilter) -> Result<Vec<Request>, StoreError>;

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

    /// Link an external account (e.g. a chat user id) to an approver.
    async fn link_account(
        &self,
        channel: &ChannelName,
        external_id: &str,
        approver: &ApproverId,
    ) -> Result<(), StoreError>;

    async fn resolve_account(&self, channel: &ChannelName, external_id: &str)
    -> Result<Option<ApproverId>, StoreError>;

    /// All account links, ordered by channel and external id.
    async fn list_account_links(&self) -> Result<Vec<AccountLink>, StoreError>;

    /// Remove a link. Returns whether one existed.
    async fn unlink_account(&self, channel: &ChannelName, external_id: &str) -> Result<bool, StoreError>;
}
