//! ntfy channel for countersign.
//!
//! Publishes a push notification for each request and for its outcome, with a
//! button that opens the request in the web UI. Notify-only: decisions are
//! made in the web UI, so nothing has to reach countersign from outside.
//!
//! ```toml
//! [channel.phone]
//! type = "ntfy"
//! server = "https://ntfy.example.com"
//! topic = "countersign-ops"
//! token_file = "/etc/countersign/ntfy-token"  # optional; or COUNTERSIGN_NTFY_TOKEN
//! details = true                              # false: say only that something needs attention
//! priority = 4                                # for new requests (1-5)
//! ```
//!
//! With `details = true`, requester, target and reason go to the ntfy server.
//! Use a server you trust (or `details = false`) and a hard-to-guess topic
//! protected by an access token.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use countersign_core::present::{Audience, Presentation, Shown};
use countersign_core::{
    Channel, ChannelCaps, ChannelError, ChannelName, DomainEvent, Item, MessageRef, Notification, Question, Request,
};

/// Environment variable holding the access token when `token_file` is unset.
pub const TOKEN_ENV: &str = "COUNTERSIGN_NTFY_TOKEN";
const TIMEOUT: Duration = Duration::from_secs(15);
const MAX_MESSAGE_CHARS: usize = 3000;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NtfyConfig {
    /// Base URL of the ntfy server, e.g. `https://ntfy.sh`.
    pub server: String,
    pub topic: String,
    /// Access token (`tk_...`). Without it (and without the environment
    /// variable), messages are published anonymously.
    #[serde(default)]
    pub token_file: Option<PathBuf>,
    /// Include requester, target, policy and reason in the notification.
    #[serde(default = "yes")]
    pub details: bool,
    /// Priority of new-request notifications; outcomes use the default (3).
    #[serde(default = "high")]
    pub priority: u8,
}

fn yes() -> bool {
    true
}

fn high() -> u8 {
    4
}

/// The JSON body ntfy accepts at its root URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Publish {
    pub topic: String,
    pub title: String,
    pub message: String,
    pub tags: Vec<String>,
    pub priority: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub click: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<ViewAction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewAction {
    pub action: String,
    pub label: String,
    pub url: String,
    pub clear: bool,
}

pub struct NtfyChannel {
    name: ChannelName,
    config: NtfyConfig,
    endpoint: String,
    token: Option<String>,
    http: reqwest::Client,
}

impl std::fmt::Debug for NtfyChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NtfyChannel")
            .field("name", &self.name)
            .field("endpoint", &self.endpoint)
            .field("topic", &self.config.topic)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

impl NtfyChannel {
    /// Validates the configuration and reads the token; does not connect.
    pub fn new(name: ChannelName, config: NtfyConfig) -> Result<Self, ChannelError> {
        let bad = |m: String| ChannelError::Other(m.into());
        let server = config.server.trim_end_matches('/');
        if !countersign_core::url::is_secure(server) {
            return Err(bad(format!(
                "ntfy server must be an https:// URL (http:// only for localhost), got {:?}",
                config.server
            )));
        }
        if !valid_topic(&config.topic) {
            return Err(bad("ntfy topic must be 1-64 characters of A-Z, a-z, 0-9, '-' or '_'".to_owned()));
        }
        if !(1..=5).contains(&config.priority) {
            return Err(bad(format!("ntfy priority must be 1-5, got {}", config.priority)));
        }
        let token = match &config.token_file {
            Some(path) => Some(
                std::fs::read_to_string(path)
                    .map_err(|e| bad(format!("ntfy token {}: {e}", path.display())))?
                    .trim()
                    .to_owned(),
            ),
            None => std::env::var(TOKEN_ENV).ok().map(|t| t.trim().to_owned()),
        }
        .filter(|t| !t.is_empty());
        let http = reqwest::Client::builder()
            .https_only(!countersign_core::url::is_local_http(server))
            .timeout(TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| ChannelError::Other(Box::new(e)))?;
        Ok(Self { endpoint: format!("{server}/"), name, config, token, http })
    }
}

fn valid_topic(t: &str) -> bool {
    (1..=64).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl NtfyChannel {
    async fn send(&self, body: &Publish, kind: &str) -> Result<(), ChannelError> {
        let mut req = self.http.post(&self.endpoint).json(body);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        let res = req.send().await.map_err(|e| {
            // Never echo the URL with credentials; reqwest errors do not include headers.
            ChannelError::Unavailable(format!("ntfy: {}", e.without_url()))
        })?;
        let status = res.status();
        if status.is_success() {
            return Ok(());
        }
        let retry_after =
            res.headers().get("retry-after").and_then(|v| v.to_str().ok()?.parse().ok()).map(Duration::from_secs);
        Err(match status.as_u16() {
            429 => ChannelError::RateLimited { retry_after },
            s if status.is_server_error() => ChannelError::Unavailable(format!("ntfy returned {s}")),
            s => ChannelError::Other(format!("ntfy refused the {kind} ({s})").into()),
        })
    }
}

#[async_trait]
impl Channel for NtfyChannel {
    fn name(&self) -> &ChannelName {
        &self.name
    }

    fn capabilities(&self) -> ChannelCaps {
        ChannelCaps::default()
    }

    async fn notify(&self, n: Notification<'_>) -> Result<Option<MessageRef>, ChannelError> {
        let body = publish(&self.config, n);
        self.send(&body, "message").await?;
        Ok(None)
    }

    async fn update(&self, _: &MessageRef, _: Notification<'_>) -> Result<(), ChannelError> {
        Err(ChannelError::Unsupported)
    }

    async fn announce(&self, notice: &countersign_core::AdminNotice) -> Result<(), ChannelError> {
        let web = (notice.web_url.starts_with("https://") || notice.web_url.starts_with("http://"))
            .then(|| notice.web_url.clone());
        let body = Publish {
            topic: self.config.topic.clone(),
            title: clean(&notice.title(), 200),
            message: clean(&notice.summary(), MAX_MESSAGE_CHARS),
            tags: vec!["warning".to_owned()],
            priority: 4,
            click: web.clone(),
            actions: web
                .map(|url| ViewAction { action: "view".to_owned(), label: "Admin".to_owned(), url, clear: true })
                .into_iter()
                .collect(),
        };
        self.send(&body, "notice").await
    }
}

/// The notification for an event.
pub fn publish(config: &NtfyConfig, n: Notification<'_>) -> Publish {
    let (title, tag, priority, message) = match n.item {
        Item::Approval(r) => approval(config, n.event, r),
        Item::Question(q) => question(config, n.event, q),
    };
    let message = if message.trim().is_empty() { "Open countersign for details.".to_owned() } else { message };
    let message: String = message.trim_end().chars().take(MAX_MESSAGE_CHARS).collect();

    let web = (n.web_url.starts_with("https://") || n.web_url.starts_with("http://")).then(|| n.web_url.to_owned());
    let label = match n.item {
        Item::Question(_) if n.item.is_pending() => "Answer",
        _ if n.item.is_pending() => "Review",
        _ => "Open",
    };
    Publish {
        topic: config.topic.clone(),
        title,
        message,
        tags: vec![tag.to_owned()],
        priority,
        click: web.clone(),
        actions: web
            .map(|url| ViewAction { action: "view".to_owned(), label: label.to_owned(), url, clear: true })
            .into_iter()
            .collect(),
    }
}

/// A question never shows its text here, confidential or not: push
/// notifications land on lock screens and in third-party logs. Only who asked,
/// under which policy, and how it ended.
fn question(config: &NtfyConfig, event: &DomainEvent, q: &Question) -> (String, &'static str, u8, String) {
    let item = Item::Question(q);
    let (title, tag, priority) = match event {
        DomainEvent::Requested { .. } => (item.safe_title(), "question", config.priority),
        DomainEvent::Answered { .. } => (format!("Question answered ({})", item.origin()), "speech_balloon", 3),
        DomainEvent::Declined { .. } => (format!("Question declined ({})", item.origin()), "no_entry", 3),
        DomainEvent::Expired { .. } => (format!("Question unanswered ({})", item.origin()), "hourglass", 3),
        _ => (format!("Question closed ({})", item.origin()), "leftwards_arrow_with_hook", 2),
    };
    let mut message = String::new();
    if q.is_pending() {
        let _ = writeln!(message, "Answer by {}", time(q.pending_until));
    } else if let Some(r) = Item::question_result(q) {
        let _ = writeln!(message, "{}", clean(&r, 200));
    }
    (title, tag, priority, message)
}

fn approval(config: &NtfyConfig, event: &DomainEvent, r: &Request) -> (String, &'static str, u8, String) {
    let p = Presentation::approval(r, Audience::Chat);
    let details = config.details && !p.withheld;
    let (what, tag, priority) = match event {
        DomainEvent::Requested { .. } => ("Access request", "key", config.priority),
        DomainEvent::Granted { .. } => ("Access granted", "white_check_mark", 3),
        DomainEvent::Denied { .. } => ("Access denied", "no_entry", 3),
        DomainEvent::GrantFailed { .. } => ("Grant failed", "warning", 4),
        DomainEvent::Expired { .. } => ("Request expired", "hourglass", 3),
        DomainEvent::Revoked { .. } => ("Access revoked", "x", 3),
        DomainEvent::Withdrawn { .. } => ("Request withdrawn", "leftwards_arrow_with_hook", 2),
        DomainEvent::Ended { .. } => ("Access ended", "checkered_flag", 2),
        DomainEvent::Approved { .. }
        | DomainEvent::DecisionRecorded { .. }
        | DomainEvent::Answered { .. }
        | DomainEvent::Declined { .. } => ("Request updated", "memo", 2),
    };
    let requested = matches!(event, DomainEvent::Requested { .. });
    let title = if details && requested {
        clean(&p.headline, 200)
    } else if details {
        format!("{what}: {}", clean(&p.headline, 200))
    } else if requested && p.withheld {
        clean(&p.headline, 200)
    } else {
        what.to_owned()
    };

    let mut message = String::new();
    if details {
        let _ = writeln!(message, "If you approve: {}", clean(&p.grant, 300));
        match &p.action {
            Some(Shown::Command { line }) => {
                let _ = writeln!(message, "$ {}", clean(line, 1000));
            }
            Some(Shown::Lines { title, .. }) => {
                let _ = writeln!(message, "{}", clean(title, 200));
            }
            Some(Shown::Question { .. }) | None => {}
        }
        for note in &p.notes {
            let _ = writeln!(message, "Note: {}", clean(note, 300));
        }
        for c in &p.claims {
            let _ = writeln!(message, "{} ({}): {}", clean(&c.label, 80), p.claims_note(), clean(&c.value, 1000));
        }
    }
    match event {
        DomainEvent::Requested { .. } => {
            let _ = writeln!(message, "Decide by {}", time(r.pending_until));
        }
        DomainEvent::Granted { until, .. } => {
            let _ = writeln!(message, "Active until {}", time(*until));
        }
        DomainEvent::GrantFailed { .. } if details => {
            if let Some(detail) = &p.status.detail {
                let _ = writeln!(message, "{}", clean(detail, 500));
            }
        }
        _ => {}
    }
    (title, tag, priority, message)
}

/// Text on one line, bounded. Presentation text has its hidden characters
/// written out already; only line breaks are left to flatten.
fn clean(s: &str, max: usize) -> String {
    let one_line: String = s.chars().map(|c| if countersign_core::text::is_hidden(c) { ' ' } else { c }).collect();
    let t = one_line.trim();
    match t.char_indices().nth(max) {
        Some((i, _)) => format!("{}…", &t[..i]),
        None => t.to_owned(),
    }
}

fn time(t: jiff::Timestamp) -> String {
    t.strftime("%Y-%m-%d %H:%M UTC").to_string()
}

#[cfg(test)]
mod tests;
