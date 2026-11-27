//! Slack channel for countersign.
//!
//! Requests and questions are posted to one Slack channel using Block Kit
//! (inside a status-coloured attachment) and updated as they progress. Button
//! presses and the `/countersign-link` slash command arrive over Slack Socket
//! Mode (an outbound WebSocket), so no inbound HTTP endpoint is needed.
//!
//! A press counts as [`countersign_core::Assurance::Linked`]: Slack vouches
//! for the account, and an earlier one-time code ties it to a person. When a
//! policy requires more, the approve button becomes a link to the web UI.
//!
//! ```toml
//! [channel.slack]
//! type = "slack"
//! channel_id = "C0123456789"
//! team_id = "T0123456789"                           # optional: accept actions only from this workspace
//! bot_token_file = "/etc/countersign/slack-bot"     # xoxb-... (or COUNTERSIGN_SLACK_BOT_TOKEN)
//! app_token_file = "/etc/countersign/slack-app"     # xapp-... (or COUNTERSIGN_SLACK_APP_TOKEN)
//! mention_users = ["U0123456789"]                   # optional: pinged on new requests
//! mention_groups = ["S0123456789"]                  # optional: user groups pinged on new requests
//! ```

mod interact;
mod render;
#[cfg(test)]
mod tests;

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::{SinkExt as _, StreamExt as _};
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio_websockets::{ClientBuilder, Message};

use countersign_core::{
    ActionSink, AdminNotice, Assurance, Channel, ChannelCaps, ChannelError, ChannelName, DomainEvent, MessageRef,
    Notification,
};

pub use crate::interact::{Action, Envelope, LINK_COMMAND, Scope, action_id, parse_action_id};
pub use crate::render::{View, view};

/// Environment variable holding the bot token (`xoxb-...`) when `bot_token_file` is unset.
pub const BOT_TOKEN_ENV: &str = "COUNTERSIGN_SLACK_BOT_TOKEN";

/// Environment variable holding the app-level token (`xapp-...`) when `app_token_file` is unset.
pub const APP_TOKEN_ENV: &str = "COUNTERSIGN_SLACK_APP_TOKEN";

const DEFAULT_API_BASE: &str = "https://slack.com/api";
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlackConfig {
    /// Where requests are posted, and the only channel decisions are taken from.
    pub channel_id: String,
    /// Accept actions only from this workspace (team), if set.
    #[serde(default)]
    pub team_id: Option<String>,
    /// File containing the Slack Bot User OAuth Token (`xoxb-...`).
    #[serde(default)]
    pub bot_token_file: Option<PathBuf>,
    /// File containing the Slack App-Level Token (`xapp-...`, `connections:write` scope).
    #[serde(default)]
    pub app_token_file: Option<PathBuf>,
    /// Slack user IDs (`U...`) mentioned when a new request is posted.
    #[serde(default)]
    pub mention_users: Vec<String>,
    /// Slack user group IDs (`S...`) mentioned when a new request is posted.
    #[serde(default)]
    pub mention_groups: Vec<String>,
}

impl SlackConfig {
    fn bot_token(&self) -> Result<String, ChannelError> {
        read_secret(self.bot_token_file.as_deref(), BOT_TOKEN_ENV, "bot_token_file", "Slack bot token")
    }

    fn app_token(&self) -> Result<String, ChannelError> {
        read_secret(self.app_token_file.as_deref(), APP_TOKEN_ENV, "app_token_file", "Slack app token")
    }
}

fn read_secret(
    path: Option<&std::path::Path>,
    env_name: &str,
    field_name: &str,
    label: &str,
) -> Result<String, ChannelError> {
    let raw = match path {
        Some(p) => std::fs::read_to_string(p)
            .map_err(|e| ChannelError::Other(format!("{label} {}: {e}", p.display()).into()))?,
        None => std::env::var(env_name)
            .map_err(|_| ChannelError::Other(format!("set {field_name} or {env_name}").into()))?,
    };
    let trimmed = raw.trim().to_owned();
    if trimmed.is_empty() {
        return Err(ChannelError::Other(format!("the {label} is empty").into()));
    }
    Ok(trimmed)
}

pub struct SlackChannel {
    scope: Scope,
    config: SlackConfig,
    bot_token: String,
    app_token: String,
    api_base: String,
    http: reqwest::Client,
}

impl fmt::Debug for SlackChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlackChannel").field("scope", &self.scope).finish_non_exhaustive()
    }
}

impl SlackChannel {
    /// Reads the bot and app tokens; does not touch the network.
    pub fn new(name: ChannelName, config: SlackConfig) -> Result<Self, ChannelError> {
        if config.channel_id.trim().is_empty() {
            return Err(ChannelError::Other("Slack channel_id must not be empty".into()));
        }
        let bot_token = config.bot_token()?;
        let app_token = config.app_token()?;
        Self::with_tokens(name, config, bot_token, app_token, DEFAULT_API_BASE.to_owned())
    }

    fn with_tokens(
        name: ChannelName,
        config: SlackConfig,
        bot_token: String,
        app_token: String,
        api_base: String,
    ) -> Result<Self, ChannelError> {
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(other)?;
        let scope = Scope { name, channel_id: config.channel_id.clone(), team_id: config.team_id.clone() };
        Ok(Self { scope, config, bot_token, app_token, api_base, http })
    }

    async fn post_api(&self, method: &str, token: &str, body: &Value) -> Result<Value, ChannelError> {
        let url = format!("{}/{method}", self.api_base.trim_end_matches('/'));
        let resp = self.http.post(&url).bearer_auth(token).json(body).send().await.map_err(reqwest_error)?;
        let status = resp.status();
        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = resp
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .map(Duration::from_secs);
            return Err(ChannelError::RateLimited { retry_after });
        }
        if status.is_server_error() {
            return Err(ChannelError::Unavailable(format!("Slack returned {status}")));
        }
        if !status.is_success() {
            return Err(ChannelError::Other(format!("Slack {method} returned {status}").into()));
        }
        let parsed: Value = resp.json().await.map_err(other)?;
        if parsed.get("ok").and_then(Value::as_bool) != Some(true) {
            let err = parsed.get("error").and_then(Value::as_str).unwrap_or("unknown_error");
            return Err(slack_api_error(method, err));
        }
        Ok(parsed)
    }

    async fn open_socket_url(&self) -> Result<String, ChannelError> {
        let parsed = self.post_api("apps.connections.open", &self.app_token, &json!({})).await?;
        parsed
            .get("url")
            .and_then(Value::as_str)
            .filter(|u| u.starts_with("wss://"))
            .map(str::to_owned)
            .ok_or_else(|| ChannelError::Other("Slack apps.connections.open returned no wss:// url".into()))
    }

    fn mentions_prefix(&self, event: &DomainEvent) -> Option<String> {
        if !matches!(event, DomainEvent::Requested { .. }) {
            return None;
        }
        let mut parts = Vec::new();
        for u in &self.config.mention_users {
            if !u.is_empty() {
                parts.push(format!("<@{u}>"));
            }
        }
        for g in &self.config.mention_groups {
            if !g.is_empty() {
                parts.push(format!("<!subteam^{g}>"));
            }
        }
        (!parts.is_empty()).then(|| parts.join(" "))
    }
}

#[async_trait]
impl Channel for SlackChannel {
    fn name(&self) -> &ChannelName {
        &self.scope.name
    }

    fn capabilities(&self) -> ChannelCaps {
        ChannelCaps { update: true, interactive: true, max_assurance: Some(Assurance::Linked) }
    }

    async fn notify(&self, n: Notification<'_>) -> Result<Option<MessageRef>, ChannelError> {
        let v = view(n, self.capabilities());
        let text = match self.mentions_prefix(n.event) {
            Some(m) => format!("{m} {}", v.text),
            None => v.text,
        };
        let body = json!({
            "channel": self.config.channel_id,
            "text": text,
            "attachments": v.attachments,
            "unfurl_links": false,
            "unfurl_media": false,
        });
        let resp = self.post_api("chat.postMessage", &self.bot_token, &body).await?;
        let channel = resp.get("channel").and_then(Value::as_str).unwrap_or(&self.config.channel_id);
        let ts = resp
            .get("ts")
            .and_then(Value::as_str)
            .ok_or_else(|| ChannelError::Other("Slack chat.postMessage returned no ts".into()))?;
        Ok(Some(MessageRef { channel: self.scope.name.clone(), id: format!("{channel}:{ts}") }))
    }

    async fn update(&self, msg: &MessageRef, n: Notification<'_>) -> Result<(), ChannelError> {
        let (channel, ts) = parse_message_ref(&msg.id)
            .ok_or_else(|| ChannelError::Other(format!("malformed message reference {:?}", msg.id).into()))?;
        let v = view(n, self.capabilities());
        let body = json!({
            "channel": channel,
            "ts": ts,
            "text": v.text,
            "attachments": v.attachments,
        });
        let _ = self.post_api("chat.update", &self.bot_token, &body).await?;
        Ok(())
    }

    async fn announce(&self, notice: &AdminNotice) -> Result<(), ChannelError> {
        let title = notice.title();
        let summary = render::mrkdwn(&notice.summary());
        let mut blocks = vec![
            json!({
                "type": "header",
                "text": { "type": "plain_text", "text": title, "emoji": true }
            }),
            json!({
                "type": "section",
                "text": { "type": "mrkdwn", "text": summary }
            }),
        ];
        if notice.web_url.starts_with("https://") || notice.web_url.starts_with("http://") {
            blocks.push(json!({
                "type": "actions",
                "elements": [{
                    "type": "button",
                    "text": { "type": "plain_text", "text": "Open admin page", "emoji": true },
                    "url": notice.web_url,
                    "action_id": format!("cs:admin:{}", notice.event_id),
                }]
            }));
        }
        blocks.push(json!({
            "type": "context",
            "elements": [{ "type": "mrkdwn", "text": format!("countersign · admin · `{}`", notice.event_id) }]
        }));
        let body = json!({
            "channel": self.config.channel_id,
            "text": notice.summary(),
            "attachments": [{ "color": "#e74c3c", "blocks": blocks }],
            "unfurl_links": false,
            "unfurl_media": false,
        });
        let _ = self.post_api("chat.postMessage", &self.bot_token, &body).await?;
        Ok(())
    }

    async fn run(&self, sink: Arc<dyn ActionSink>) -> Result<(), ChannelError> {
        let url = self.open_socket_url().await?;
        tracing::info!(channel = %self.scope.name, "connecting to Slack Socket Mode");
        let (mut ws, _) = ClientBuilder::new()
            .uri(&url)
            .map_err(other)?
            .connect()
            .await
            .map_err(|e| ChannelError::Unavailable(format!("Slack Socket Mode connect failed: {e}")))?;

        while let Some(frame) = ws.next().await {
            let msg = match frame {
                Ok(m) => m,
                Err(e) => return Err(ChannelError::Unavailable(format!("Slack Socket Mode error: {e}"))),
            };
            if msg.is_ping() {
                if let Err(e) = ws.send(Message::pong(msg.into_payload())).await {
                    return Err(ChannelError::Unavailable(format!("Slack Socket Mode pong failed: {e}")));
                }
                continue;
            }
            if msg.is_close() {
                return Err(ChannelError::Unavailable("Slack Socket Mode connection closed".to_owned()));
            }
            let Some(text) = msg.as_text() else { continue };
            let envelope: Envelope = match serde_json::from_str(text) {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(channel = %self.scope.name, error = %e, "ignoring malformed Slack Socket Mode frame");
                    continue;
                }
            };
            if envelope.kind == "disconnect" {
                tracing::info!(channel = %self.scope.name, "Slack Socket Mode requested reconnect");
                return Err(ChannelError::Unavailable("Slack Socket Mode requested reconnect".to_owned()));
            }
            if let Some(id) = &envelope.envelope_id {
                let ack = json!({ "envelope_id": id }).to_string();
                if let Err(e) = ws.send(Message::text(ack)).await {
                    return Err(ChannelError::Unavailable(format!("Slack Socket Mode ack failed: {e}")));
                }
            }
            if envelope.kind == "hello" {
                tracing::info!(channel = %self.scope.name, "Slack Socket Mode connected");
                continue;
            }
            let http = self.http.clone();
            let scope = self.scope.clone();
            let sink = Arc::clone(&sink);
            tokio::spawn(async move {
                respond(&http, &scope, sink.as_ref(), envelope).await;
            });
        }
        Err(ChannelError::Unavailable("Slack Socket Mode stream ended".to_owned()))
    }
}

async fn respond(http: &reqwest::Client, scope: &Scope, sink: &dyn ActionSink, envelope: Envelope) {
    let Some(parsed) = interact::parse_envelope(&envelope) else { return };
    let reply = interact::perform(scope, sink, &parsed).await;
    if let Some(url) = &parsed.response_url {
        if !is_allowed_response_url(url) {
            tracing::warn!(channel = %scope.name, "refusing unexpected Slack response_url");
            return;
        }
        let body = json!({
            "response_type": "ephemeral",
            "replace_original": false,
            "text": reply,
        });
        if let Err(e) = http.post(url).json(&body).send().await {
            tracing::warn!(channel = %scope.name, error = %e, "could not send Slack ephemeral reply");
        }
    }
}

fn is_allowed_response_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else { return false };
    let host = rest.split('/').next().unwrap_or("");
    host == "hooks.slack.com" || host.ends_with(".slack.com")
}

fn parse_message_ref(s: &str) -> Option<(&str, &str)> {
    let (c, ts) = s.split_once(':')?;
    if c.is_empty() || ts.is_empty() {
        return None;
    }
    Some((c, ts))
}

fn reqwest_error(e: reqwest::Error) -> ChannelError {
    if e.is_timeout() || e.is_connect() || e.is_request() {
        ChannelError::Unavailable(e.to_string())
    } else {
        ChannelError::Other(Box::new(e))
    }
}

fn slack_api_error(method: &str, code: &str) -> ChannelError {
    match code {
        "ratelimited" => ChannelError::RateLimited { retry_after: None },
        "internal_error" | "service_unavailable" | "request_timeout" | "fatal_error" => {
            ChannelError::Unavailable(format!("Slack {method}: {code}"))
        }
        _ => ChannelError::Other(format!("Slack {method}: {code}").into()),
    }
}

fn other(e: impl std::error::Error + Send + Sync + 'static) -> ChannelError {
    ChannelError::Other(Box::new(e))
}
