//! Where requests are announced and, for interactive channels, decided.
//!
//! Outbound, channels post and edit messages ([`Channel::notify`],
//! [`Channel::update`]). Inbound, interactive channels run a long-lived task
//! ([`Channel::run`]) that receives button presses over a connection the
//! channel itself opens (e.g. the Discord Gateway), authenticates the sender
//! by the platform's own means, resolves them to a linked person through
//! the [`ActionSink`], and submits an [`ActionIntent`] (approvals) or an
//! [`AnswerIntent`] (questions).

use std::sync::Arc;

use async_trait::async_trait;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::assurance::Assurance;
use crate::event::DomainEvent;
use crate::id::{ActorId, ChannelName, EventId, RequestId};
use crate::question::{Question, Response};
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

/// What a notification is about.
#[derive(Debug, Clone, Copy)]
pub enum Item<'a> {
    Approval(&'a Request),
    Question(&'a Question),
}

impl Item<'_> {
    pub fn id(&self) -> RequestId {
        match self {
            Self::Approval(r) => r.id,
            Self::Question(q) => q.id,
        }
    }

    /// `pending`, `answered`, `denied`, ...
    pub fn state(&self) -> &'static str {
        match self {
            Self::Approval(r) => r.state.name(),
            Self::Question(q) => q.state(),
        }
    }

    pub fn is_pending(&self) -> bool {
        match self {
            Self::Approval(r) => r.state.is_pending(),
            Self::Question(q) => q.is_pending(),
        }
    }

    /// `approval` or `question`.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Approval(_) => "approval",
            Self::Question(_) => "question",
        }
    }

    /// The policy that governs it.
    pub fn policy(&self) -> &str {
        match self {
            Self::Approval(r) => r.requirements.policy.as_str(),
            Self::Question(q) => q.requirements.policy.as_str(),
        }
    }

    /// Channels this item is routed to; empty means all configured channels.
    pub fn channels(&self) -> &[ChannelName] {
        match self {
            Self::Approval(r) => &r.requirements.channels,
            Self::Question(q) => &q.requirements.channels,
        }
    }

    /// Whether channels may show only that it exists: a sensitive approval
    /// or a confidential question.
    pub fn withheld(&self) -> bool {
        match self {
            Self::Approval(r) => r.sensitive,
            Self::Question(q) => q.question_confidential(),
        }
    }

    /// Where it came from: the client or backend for an approval, the asking
    /// client for a question.
    pub fn origin(&self) -> String {
        match self {
            Self::Approval(r) => {
                r.facts.source.as_ref().map_or_else(|| r.subject.backend.to_string(), |s| s.name().to_owned())
            }
            Self::Question(q) => q.asker.client.to_string(),
        }
    }

    /// A one-line title any channel may show, whatever the item's
    /// confidentiality.
    pub fn safe_title(&self) -> String {
        match self {
            Self::Approval(r) if r.sensitive => {
                format!("Sensitive approval request from {} ({})", self.origin(), self.policy())
            }
            Self::Approval(_) => format!("Approval request from {} ({})", self.origin(), self.policy()),
            Self::Question(q) if q.question_confidential() => {
                format!("Confidential question from {} ({})", self.origin(), self.policy())
            }
            Self::Question(_) => format!("Question from {} ({})", self.origin(), self.policy()),
        }
    }

    /// Who answered or declined a closed question, safe to show anywhere
    /// (never the answer itself).
    pub fn question_result(q: &Question) -> Option<String> {
        use crate::question::QuestionOutcome as O;
        Some(match q.outcome.as_ref()? {
            O::Accepted { by, confidential: true, .. } => format!("Answered by {by} (confidential)"),
            O::Accepted { by, .. } => format!("Answered by {by}"),
            O::Declined { by, .. } => format!("Declined by {by}"),
            O::Expired { .. } => "No answer in time".to_owned(),
            O::Withdrawn { .. } => "Withdrawn by the asker".to_owned(),
        })
    }
}

/// What a channel is asked to render.
///
/// Channels must not show the details of a sensitive approval
/// ([`Request::sensitive`]), the text of a confidential question, or a
/// confidential answer: only that something happened, with the link.
#[derive(Debug, Clone, Copy)]
pub struct Notification<'a> {
    /// Current snapshot of the approval or question.
    pub item: Item<'a>,
    /// Outbox identity of the event: the same across delivery retries, so
    /// receivers can use it to drop duplicates.
    pub event_id: EventId,
    /// The event that triggered this notification.
    pub event: &'a DomainEvent,
    /// Absolute URL of the request's page in the web UI.
    pub web_url: &'a str,
}

/// A decision received through a channel, after signature verification and
/// resolution to a person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionIntent {
    pub request_id: RequestId,
    pub verdict: Verdict,
    pub approver: ActorId,
    pub assurance: Assurance,
    pub via: ChannelName,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// An answer to a question received through a channel or the web UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnswerIntent {
    pub question_id: RequestId,
    pub responder: ActorId,
    pub response: Response,
    pub assurance: Assurance,
    pub via: ChannelName,
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
    /// The active person linked to an external account on this channel, if any.
    async fn resolve_account(&self, channel: &ChannelName, external_id: &str) -> Result<Option<ActorId>, String>;

    /// Redeem a one-time code issued in the web UI, linking `external_id` on
    /// `channel` to the person who requested the code.
    async fn link_account(&self, channel: &ChannelName, external_id: &str, code: &str) -> Result<ActorId, String>;

    /// Record a decision. Errors are human-readable reasons.
    async fn submit(&self, intent: ActionIntent) -> Result<Request, String>;

    /// Record an answer to a question. Errors are human-readable reasons.
    async fn answer(&self, intent: AnswerIntent) -> Result<Question, String>;
}

/// High-visibility administrative notice (e.g. actor suspension or bulk
/// revoke), announced to all configured channels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminNotice {
    pub event_id: EventId,
    /// `suspend`, `revoke-approved-by`, ...
    pub action: String,
    pub by: ActorId,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub at: Timestamp,
    /// Absolute URL of the admin page in the web UI.
    pub web_url: String,
}

impl AdminNotice {
    /// Short headline for titles and push notifications.
    pub fn title(&self) -> String {
        match self.action.as_str() {
            "suspend" => format!("Admin notice: {} suspended", self.target),
            "revoke-approved-by" => format!("Admin notice: grants approved by {} revoked", self.target),
            "break-glass" => format!("BREAK-GLASS: request {} approved", self.target),
            other => format!("Admin notice: {other} on {}", self.target),
        }
    }

    /// Plain-text one-paragraph summary.
    pub fn summary(&self) -> String {
        let base = match self.action.as_str() {
            "suspend" => format!("{} suspended {}.", self.by, self.target),
            "revoke-approved-by" => format!("{} revoked active grants approved by {}.", self.by, self.target),
            "break-glass" => format!("{} invoked break-glass approval on request {}.", self.by, self.target),
            other => format!("{} ran {other} on {}.", self.by, self.target),
        };
        match self.detail.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(d) => format!("{base} ({})", crate::text::escape(d)),
            None => base,
        }
    }
}

#[async_trait]
pub trait Channel: Send + Sync {
    fn name(&self) -> &ChannelName;

    fn capabilities(&self) -> ChannelCaps;

    /// Announce an event. Returns a reference if the message can be updated.
    async fn notify(&self, n: Notification<'_>) -> Result<Option<MessageRef>, ChannelError>;

    /// Rewrite an earlier message to reflect the request's new state.
    async fn update(&self, msg: &MessageRef, n: Notification<'_>) -> Result<(), ChannelError>;

    /// Announce a high-visibility administrative action (e.g. suspension or
    /// bulk revoke) to this channel.
    async fn announce(&self, notice: &AdminNotice) -> Result<(), ChannelError> {
        let _ = notice;
        Ok(())
    }

    /// Receive actions until the connection ends for good. Only called when
    /// [`ChannelCaps::interactive`] is set; the daemon restarts it with a
    /// delay if it returns an error.
    async fn run(&self, sink: Arc<dyn ActionSink>) -> Result<(), ChannelError> {
        let _ = sink;
        Ok(())
    }
}

/// An inbound action from an interactive chat channel (Discord, Slack, …).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatAction {
    Decide { verdict: Verdict, request_id: RequestId },
    Answer { question_id: RequestId, content: serde_json::Map<String, serde_json::Value> },
    Decline { question_id: RequestId },
    Link { code: String },
}

/// Execute a validated [`ChatAction`] against `sink` at [`Assurance::Linked`]
/// and return the ephemeral reply message for the user.
///
/// Callers are responsible for platform-level authorization (checking channel
/// and workspace/guild scope) before invoking this for non-`Link` actions.
pub async fn execute_chat_action(
    sink: &dyn ActionSink,
    channel: &ChannelName,
    platform: &str,
    external_id: &str,
    link_hint: &str,
    action: &ChatAction,
) -> String {
    if let ChatAction::Link { code } = action {
        return match sink.link_account(channel, external_id, code).await {
            Ok(person) => format!("Linked your {platform} account to `{person}`."),
            Err(e) => format!("Could not link: {e}"),
        };
    }
    let approver = match sink.resolve_account(channel, external_id).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return format!(
                "Your {platform} account is not linked to a countersign person. Sign in to the web UI, \
                 choose \"Link chat account\", and run {link_hint}."
            );
        }
        Err(e) => return format!("Not recorded: {e}"),
    };
    match action {
        ChatAction::Answer { question_id, content } => {
            let intent = AnswerIntent {
                question_id: *question_id,
                responder: approver.clone(),
                response: Response::Accept { content: content.clone(), confidential: false },
                assurance: Assurance::Linked,
                via: channel.clone(),
            };
            match sink.answer(intent).await {
                Ok(_) => format!("Recorded your answer as `{approver}`."),
                Err(e) => format!("Not recorded: {e}"),
            }
        }
        ChatAction::Decline { question_id } => {
            let intent = AnswerIntent {
                question_id: *question_id,
                responder: approver.clone(),
                response: Response::Decline { note: None },
                assurance: Assurance::Linked,
                via: channel.clone(),
            };
            match sink.answer(intent).await {
                Ok(_) => format!("Recorded that `{approver}` declined to answer."),
                Err(e) => format!("Not recorded: {e}"),
            }
        }
        ChatAction::Decide { verdict, request_id } => {
            let intent = ActionIntent {
                request_id: *request_id,
                verdict: *verdict,
                approver: approver.clone(),
                assurance: Assurance::Linked,
                via: channel.clone(),
                comment: None,
            };
            let verb = match verdict {
                Verdict::Approve => "approval",
                Verdict::Deny => "denial",
            };
            match sink.submit(intent).await {
                Ok(r) => format!("Recorded your {verb} as `{approver}`. The request is now {}.", r.state.name()),
                Err(e) => format!("Not recorded: {e}"),
            }
        }
        ChatAction::Link { .. } => unreachable!("handled above"),
    }
}
