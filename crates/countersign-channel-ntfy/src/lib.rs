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
use countersign_core::{Channel, ChannelCaps, ChannelError, ChannelName, DomainEvent, MessageRef, Notification};
use serde::{Deserialize, Serialize};

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
        if !(server.starts_with("https://") || server.starts_with("http://")) {
            return Err(bad(format!("ntfy server must be an http(s) URL, got {:?}", config.server)));
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
        let mut req = self.http.post(&self.endpoint).json(&body);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        let res = req.send().await.map_err(|e| {
            // Never echo the URL with credentials; reqwest errors do not include headers.
            ChannelError::Unavailable(format!("ntfy: {}", e.without_url()))
        })?;
        let status = res.status();
        if status.is_success() {
            return Ok(None);
        }
        let retry_after =
            res.headers().get("retry-after").and_then(|v| v.to_str().ok()?.parse().ok()).map(Duration::from_secs);
        Err(match status.as_u16() {
            429 => ChannelError::RateLimited { retry_after },
            s if status.is_server_error() => ChannelError::Unavailable(format!("ntfy returned {s}")),
            s => ChannelError::Other(format!("ntfy refused the message ({s})").into()),
        })
    }

    async fn update(&self, _: &MessageRef, _: Notification<'_>) -> Result<(), ChannelError> {
        Err(ChannelError::Unsupported)
    }
}

/// The notification for an event.
pub fn publish(config: &NtfyConfig, n: Notification<'_>) -> Publish {
    let r = n.request;
    let who = if config.details { clean(&r.facts.requester.id, 80) } else { String::new() };
    let about = |what: &str| if who.is_empty() { what.to_owned() } else { format!("{what}: {who}") };
    let (title, tag, priority) = match n.event {
        DomainEvent::Requested { .. } => (about("Access request"), "key", config.priority),
        DomainEvent::Granted { .. } => (about("Access granted"), "white_check_mark", 3),
        DomainEvent::Denied { .. } => (about("Access denied"), "no_entry", 3),
        DomainEvent::GrantFailed { .. } => (about("Grant failed"), "warning", 4),
        DomainEvent::Expired { .. } => (about("Request expired"), "hourglass", 3),
        DomainEvent::Revoked { .. } => (about("Access revoked"), "x", 3),
        DomainEvent::Withdrawn { .. } => (about("Request withdrawn"), "leftwards_arrow_with_hook", 2),
        DomainEvent::Ended { .. } => (about("Access ended"), "checkered_flag", 2),
        DomainEvent::Approved { .. } | DomainEvent::DecisionRecorded { .. } => (about("Request updated"), "memo", 2),
    };

    let mut message = String::new();
    if config.details {
        let f = &r.facts;
        if let Some(name) = &f.requester.display_name {
            let _ = writeln!(message, "Requester: {} ({})", clean(&f.requester.id, 80), clean(name, 80));
        } else {
            let _ = writeln!(message, "Requester: {}", clean(&f.requester.id, 80));
        }
        if let Some(t) = &f.target {
            let _ = writeln!(message, "Target: {}", clean(t, 200));
        }
        if let Some(c) = f.attributes.get("command") {
            let _ = writeln!(message, "Command: {}", clean(c, 1000));
        }
        let _ = writeln!(message, "Policy: {}", clean(r.requirements.policy.as_str(), 80));
        let _ = writeln!(message, "Duration: {}", duration(r.requirements.ttl));
        if let Some(reason) = &f.reason {
            let _ = writeln!(message, "Reason: {}", clean(reason, 1000));
        }
    }
    match n.event {
        DomainEvent::Requested { .. } => {
            let _ = writeln!(message, "Decide by {}", time(r.pending_until));
        }
        DomainEvent::Granted { until, .. } => {
            let _ = writeln!(message, "Active until {}", time(*until));
        }
        DomainEvent::GrantFailed { error, .. } if config.details => {
            let _ = writeln!(message, "Error: {}", clean(error, 500));
        }
        _ => {}
    }
    if message.is_empty() {
        message.push_str("Open countersign for details.");
    }
    let message: String = message.trim_end().chars().take(MAX_MESSAGE_CHARS).collect();

    let web = (n.web_url.starts_with("https://") || n.web_url.starts_with("http://")).then(|| n.web_url.to_owned());
    let label = if r.state.is_pending() { "Review" } else { "Open" };
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

/// Untrusted text on one line, bounded.
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

fn duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        return format!("{secs}s");
    }
    let (days, hours, mins) = (secs / 86_400, secs / 3600 % 24, secs / 60 % 60);
    let parts: Vec<String> = [(days, "d"), (hours, "h"), (mins, "m")]
        .into_iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, u)| format!("{n}{u}"))
        .collect();
    parts.join(" ")
}

#[cfg(test)]
mod tests;
