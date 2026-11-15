//! Where requests are announced and, for interactive channels, decided.
//!
//! Outbound, channels post and edit messages ([`Channel::notify`],
//! [`Channel::update`]). Inbound, interactive channels run a long-lived task
//! ([`Channel::run`]) that receives button presses over a connection the
//! channel itself opens (e.g. the Discord Gateway), authenticates the sender
//! by the platform's own means, resolves them to a linked approver through
//! the [`ActionSink`], and submits an [`ActionIntent`].

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::assurance::Assurance;
use crate::event::DomainEvent;
use crate::id::{ApproverId, ChannelName, RequestId};
use crate::request::{Request, Verdict};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelCaps {
    /// Can edit a message it sent earlier (to show the outcome).
    pub update: bool,
    /// Can carry decisions back (buttons, signed callbacks).
    pub interactive: bool,
    /// Highest assurance a decision made through this channel can claim.
    /// `None` for notify-only channels.
    pub max_assurance: Option<Assurance>,
}

/// How a channel should present the "approve" action for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApproveMode {
    /// Approve directly in the channel.
    Direct,
    /// The channel cannot meet the required assurance: link to the web UI.
    WebLink,
    /// No approve action (request no longer pending).
    None,
}

impl ApproveMode {
    pub fn for_request(caps: ChannelCaps, request: &Request) -> Self {
        if !request.state.is_pending() {
            return Self::None;
        }
        match caps.max_assurance {
            Some(max) if caps.interactive && max >= request.requirements.min_assurance => Self::Direct,
            _ => Self::WebLink,
        }
    }
}

/// Opaque reference to a message a channel posted, for later updates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageRef {
    pub channel: ChannelName,
    pub id: String,
}

/// What a channel is asked to render.
#[derive(Debug, Clone, Copy)]
pub struct Notification<'a> {
    /// Current snapshot of the request.
    pub request: &'a Request,
    /// The event that triggered this notification.
    pub event: &'a DomainEvent,
    /// Absolute URL of the request's page in the web UI.
    pub web_url: &'a str,
}

/// A decision received through a channel, after signature verification and
/// approver resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionIntent {
    pub request_id: RequestId,
    pub verdict: Verdict,
    pub approver: ApproverId,
    pub assurance: Assurance,
    pub via: ChannelName,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("channel unavailable: {0}")]
    Unavailable(String),
    #[error("rate limited")]
    RateLimited { retry_after: Option<std::time::Duration> },
    #[error("operation not supported by this channel")]
    Unsupported,
    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

impl ChannelError {
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Unavailable(_) | Self::RateLimited { .. })
    }
}

/// What an interactive channel can ask of the daemon.
#[async_trait]
pub trait ActionSink: Send + Sync {
    /// The approver linked to an external account on this channel, if any.
    async fn resolve_account(&self, channel: &ChannelName, external_id: &str) -> Result<Option<ApproverId>, String>;

    /// Redeem a one-time code issued in the web UI, linking `external_id` on
    /// `channel` to the approver who requested the code.
    async fn link_account(&self, channel: &ChannelName, external_id: &str, code: &str) -> Result<ApproverId, String>;

    /// Record a decision. Errors are human-readable reasons.
    async fn submit(&self, intent: ActionIntent) -> Result<Request, String>;
}

#[async_trait]
pub trait Channel: Send + Sync {
    fn name(&self) -> &ChannelName;

    fn capabilities(&self) -> ChannelCaps;

    /// Announce an event. Returns a reference if the message can be updated.
    async fn notify(&self, n: Notification<'_>) -> Result<Option<MessageRef>, ChannelError>;

    /// Rewrite an earlier message to reflect the request's new state.
    async fn update(&self, msg: &MessageRef, n: Notification<'_>) -> Result<(), ChannelError>;

    /// Receive actions until the connection ends for good. Only called when
    /// [`ChannelCaps::interactive`] is set; the daemon restarts it with a
    /// delay if it returns an error.
    async fn run(&self, sink: Arc<dyn ActionSink>) -> Result<(), ChannelError> {
        let _ = sink;
        Ok(())
    }
}
