//! Webhook channel for countersign.
//!
//! POSTs a JSON event for each new request and each outcome, signed the way
//! [Standard Webhooks](https://www.standardwebhooks.com/) specifies, so
//! receivers can use an existing verifier library:
//!
//! - `webhook-id`: the outbox event ID, stable across retries (deduplicate on it)
//! - `webhook-timestamp`: Unix seconds at sending time (reject stale ones)
//! - `webhook-signature`: `v1,<base64 HMAC-SHA256 of "{id}.{timestamp}.{body}">`
//!
//! Notify-only: nothing is accepted back.
//!
//! ```toml
//! [channel.automation]
//! type = "webhook"
//! url = "https://hooks.example.com/countersign"
//! secret_file = "/etc/countersign/webhook-secret"   # "whsec_<base64>" or raw bytes (>= 16)
//! bearer_token_file = "/etc/countersign/hook-token" # optional Authorization header
//! # unsigned = true                                 # instead of secret_file, if you really mean it
//! ```

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use hmac::{Hmac, Mac};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use countersign_core::present::{Audience, Presentation};
use countersign_core::{
    Channel, ChannelCaps, ChannelError, ChannelName, DomainEvent, EventId, Item, MessageRef, Notification, Question,
    Request,
};

const TIMEOUT: Duration = Duration::from_secs(15);
const MIN_SECRET_BYTES: usize = 16;
const SECRET_PREFIX: &str = "whsec_";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    pub url: String,
    /// Signing secret: `whsec_<base64>` (Standard Webhooks) or raw bytes.
    #[serde(default)]
    pub secret_file: Option<PathBuf>,
    /// Sent as `Authorization: Bearer <token>`.
    #[serde(default)]
    pub bearer_token_file: Option<PathBuf>,
    /// Send without a signature. Required to be explicit when there is no secret.
    #[serde(default)]
    pub unsigned: bool,
}

/// The JSON body.
#[derive(Debug, Serialize)]
pub struct Payload<'a> {
    /// Same as the `webhook-id` header.
    pub id: EventId,
    /// The event kind, e.g. `requested`, `granted`, `denied`.
    #[serde(rename = "type")]
    pub event_type: &'static str,
    pub timestamp: Timestamp,
    /// The request's page in the web UI.
    pub url: &'a str,
    pub event: &'a DomainEvent,
    /// `approval` or `question`.
    pub kind: &'static str,
    /// Snapshot of the approval after the event (for `approval`). A
    /// sensitive one keeps only its source, policy and state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<Request>,
    /// Snapshot of the question after the event (for `question`), without
    /// confidential text or answers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub question: Option<Question>,
    /// How countersign shows it to people (headline, grant, action, status
    /// in words), withheld like the snapshot, so receivers need not rebuild
    /// the wording.
    pub presentation: Presentation,
}

impl<'a> Payload<'a> {
    pub fn new(n: Notification<'a>, timestamp: Timestamp) -> Self {
        let (request, question) = match n.item {
            Item::Approval(r) => (Some(r.for_chat()), None),
            Item::Question(q) => (None, Some(q.for_chat())),
        };
        Self {
            id: n.event_id,
            event_type: n.event.kind(),
            timestamp,
            url: n.web_url,
            event: n.event,
            kind: n.item.kind(),
            request,
            question,
            presentation: Presentation::of(n.item, Audience::Chat),
        }
    }
}

pub struct WebhookChannel {
    name: ChannelName,
    url: String,
    key: Option<Vec<u8>>,
    bearer: Option<String>,
    http: reqwest::Client,
}

impl std::fmt::Debug for WebhookChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookChannel")
            .field("name", &self.name)
            .field("url", &self.url)
            .field("signed", &self.key.is_some())
            .finish_non_exhaustive()
    }
}

fn config_error(m: String) -> ChannelError {
    ChannelError::Other(m.into())
}

fn read_secret_file(path: &Path, what: &str) -> Result<String, ChannelError> {
    let s = std::fs::read_to_string(path).map_err(|e| config_error(format!("{what} {}: {e}", path.display())))?;
    let s = s.trim().to_owned();
    if s.is_empty() {
        return Err(config_error(format!("{what} {} is empty", path.display())));
    }
    Ok(s)
}

/// The HMAC key from a secret as written in the file.
pub fn parse_secret(s: &str) -> Result<Vec<u8>, String> {
    let key = match s.strip_prefix(SECRET_PREFIX) {
        Some(b64) => B64.decode(b64).map_err(|e| format!("secret is not valid base64 after {SECRET_PREFIX}: {e}"))?,
        None => s.as_bytes().to_vec(),
    };
    if key.len() < MIN_SECRET_BYTES {
        return Err(format!("secret must be at least {MIN_SECRET_BYTES} bytes"));
    }
    Ok(key)
}

/// `v1,<signature>` for a message, as in the `webhook-signature` header.
///
/// # Panics
///
/// Never: HMAC accepts keys of any length.
pub fn sign(key: &[u8], id: &str, timestamp: i64, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(id.as_bytes());
    mac.update(b".");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    format!("v1,{}", B64.encode(mac.finalize().into_bytes()))
}

impl WebhookChannel {
    /// Validates the configuration and reads secrets; does not connect.
    pub fn new(name: ChannelName, config: &WebhookConfig) -> Result<Self, ChannelError> {
        if !countersign_core::url::is_secure(&config.url) {
            return Err(config_error(format!(
                "webhook url must be an https:// URL (http:// only for localhost), got {:?}",
                config.url
            )));
        }
        let key = match (&config.secret_file, config.unsigned) {
            (Some(_), true) => return Err(config_error("set either secret_file or unsigned, not both".to_owned())),
            (None, false) => {
                return Err(config_error(
                    "set secret_file (or unsigned = true to send without a signature)".to_owned(),
                ));
            }
            (Some(path), false) => {
                Some(parse_secret(&read_secret_file(path, "webhook secret")?).map_err(config_error)?)
            }
            (None, true) => None,
        };
        let bearer = config.bearer_token_file.as_deref().map(|p| read_secret_file(p, "bearer token")).transpose()?;
        let http = reqwest::Client::builder()
            .https_only(!countersign_core::url::is_local_http(&config.url))
            .timeout(TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("countersign/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| ChannelError::Other(Box::new(e)))?;
        Ok(Self { name, url: config.url.clone(), key, bearer, http })
    }
}

#[async_trait]
impl Channel for WebhookChannel {
    fn name(&self) -> &ChannelName {
        &self.name
    }

    fn capabilities(&self) -> ChannelCaps {
        ChannelCaps::default()
    }

    async fn notify(&self, n: Notification<'_>) -> Result<Option<MessageRef>, ChannelError> {
        let now = Timestamp::now();
        let payload = Payload::new(n, now);
        let body = serde_json::to_vec(&payload).map_err(|e| ChannelError::Other(Box::new(e)))?;
        self.send(&n.event_id.to_string(), now.as_second(), body, "event").await?;
        Ok(None)
    }

    async fn update(&self, _: &MessageRef, _: Notification<'_>) -> Result<(), ChannelError> {
        Err(ChannelError::Unsupported)
    }

    async fn announce(&self, notice: &countersign_core::AdminNotice) -> Result<(), ChannelError> {
        let now = Timestamp::now();
        let body = serde_json::to_vec(&serde_json::json!({
            "id": notice.event_id,
            "type": "admin-notice",
            "timestamp": now,
            "url": notice.web_url,
            "notice": notice,
        }))
        .map_err(|e| ChannelError::Other(Box::new(e)))?;
        self.send(&notice.event_id.to_string(), now.as_second(), body, "notice").await
    }
}

impl WebhookChannel {
    async fn send(&self, id: &str, ts: i64, body: Vec<u8>, kind: &str) -> Result<(), ChannelError> {
        let mut req = self
            .http
            .post(&self.url)
            .header("content-type", "application/json")
            .header("webhook-id", id)
            .header("webhook-timestamp", ts.to_string());
        if let Some(key) = &self.key {
            req = req.header("webhook-signature", sign(key, id, ts, &body));
        }
        if let Some(token) = &self.bearer {
            req = req.bearer_auth(token);
        }
        let res = req
            .body(body)
            .send()
            .await
            .map_err(|e| ChannelError::Unavailable(format!("webhook: {}", e.without_url())))?;
        let status = res.status();
        if status.is_success() {
            return Ok(());
        }
        let retry_after =
            res.headers().get("retry-after").and_then(|v| v.to_str().ok()?.parse().ok()).map(Duration::from_secs);
        Err(match status.as_u16() {
            408 | 429 => ChannelError::RateLimited { retry_after },
            s if status.is_server_error() => ChannelError::Unavailable(format!("webhook returned {s}")),
            s => ChannelError::Other(format!("webhook refused the {kind} ({s})").into()),
        })
    }
}

#[cfg(test)]
mod tests;
