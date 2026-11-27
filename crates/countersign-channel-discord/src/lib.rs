//! Discord channel for countersign.
//!
//! Requests are posted to one Discord channel as an embed with buttons, and
//! edited as they progress. Button presses and the `/countersign-link` command
//! arrive over the bot's own Gateway connection (an outbound WebSocket), so no
//! inbound HTTP endpoint is needed.
//!
//! A press counts as [`countersign_core::Assurance::Linked`]: Discord vouches
//! for the account, and an earlier one-time code ties it to an approver. When
//! a policy requires more, the approve button becomes a link to the web UI.
//!
//! ```toml
//! [channel.discord]
//! type = "discord"
//! channel_id = "123456789012345678"
//! guild_id = "234567890123456789"       # optional: accept decisions only there, register the command there
//! bot_token_file = "/etc/countersign/discord-token"   # or COUNTERSIGN_DISCORD_BOT_TOKEN
//! mention_roles = ["345678901234567890"]               # optional: pinged on new requests
//! ```

mod interact;
mod render;
#[cfg(test)]
mod tests;

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use twilight_gateway::{Event, EventTypeFlags, Intents, Shard, ShardId, StreamExt as _};
use twilight_http::Client;
use twilight_http::error::ErrorType;
use twilight_model::application::interaction::Interaction;
use twilight_model::channel::message::{AllowedMentions, MessageFlags};
use twilight_model::http::interaction::{InteractionResponse, InteractionResponseData, InteractionResponseType};
use twilight_model::id::Id;
use twilight_model::id::marker::{ChannelMarker, GuildMarker, MessageMarker, RoleMarker};

use countersign_core::{
    ActionSink, AdminNotice, Assurance, Channel, ChannelCaps, ChannelError, ChannelName, DomainEvent, MessageRef,
    Notification,
};

pub use crate::interact::{Action, LINK_COMMAND, Scope, custom_id, parse_custom_id};
pub use crate::render::{View, view};

/// Environment variable holding the bot token when `bot_token_file` is unset.
pub const TOKEN_ENV: &str = "COUNTERSIGN_DISCORD_BOT_TOKEN";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscordConfig {
    /// Where requests are posted, and the only channel decisions are taken from.
    pub channel_id: Id<ChannelMarker>,
    /// Accept decisions only from this server; also registers the link
    /// command there (instant) rather than globally.
    #[serde(default)]
    pub guild_id: Option<Id<GuildMarker>>,
    #[serde(default)]
    pub bot_token_file: Option<PathBuf>,
    /// Roles mentioned when a new request is posted.
    #[serde(default)]
    pub mention_roles: Vec<Id<RoleMarker>>,
}

impl DiscordConfig {
    fn token(&self) -> Result<String, ChannelError> {
        let token = match &self.bot_token_file {
            Some(path) => std::fs::read_to_string(path)
                .map_err(|e| ChannelError::Other(format!("bot token {}: {e}", path.display()).into()))?,
            None => std::env::var(TOKEN_ENV)
                .map_err(|_| ChannelError::Other(format!("set bot_token_file or {TOKEN_ENV}").into()))?,
        };
        let token = token.trim().to_owned();
        if token.is_empty() {
            return Err(ChannelError::Other("the Discord bot token is empty".into()));
        }
        Ok(token)
    }
}

pub struct DiscordChannel {
    scope: Scope,
    config: DiscordConfig,
    token: String,
    http: Arc<Client>,
}

impl fmt::Debug for DiscordChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiscordChannel").field("scope", &self.scope).finish_non_exhaustive()
    }
}

impl DiscordChannel {
    /// Reads the bot token; does not touch the network.
    pub fn new(name: ChannelName, config: DiscordConfig) -> Result<Self, ChannelError> {
        let token = config.token()?;
        let http = Client::builder().token(token.clone()).default_allowed_mentions(AllowedMentions::default()).build();
        let scope = Scope { name, channel_id: config.channel_id, guild_id: config.guild_id };
        Ok(Self { scope, config, token, http: Arc::new(http) })
    }

    async fn register_commands(&self) -> Result<(), ChannelError> {
        let app = self.http.current_user_application().await.map_err(http_error)?.model().await.map_err(other)?;
        let commands = [interact::link_command()];
        let client = self.http.interaction(app.id);
        match self.config.guild_id {
            Some(guild) => client.set_guild_commands(guild, &commands).await.map(drop),
            None => client.set_global_commands(&commands).await.map(drop),
        }
        .map_err(http_error)
    }
}

#[async_trait]
impl Channel for DiscordChannel {
    fn name(&self) -> &ChannelName {
        &self.scope.name
    }

    fn capabilities(&self) -> ChannelCaps {
        ChannelCaps { update: true, interactive: true, max_assurance: Some(Assurance::Linked) }
    }

    async fn notify(&self, n: Notification<'_>) -> Result<Option<MessageRef>, ChannelError> {
        let v = view(n, self.capabilities());
        let mut req = self.http.create_message(self.config.channel_id).embeds(&v.embeds).components(&v.components);
        let mentions;
        let content;
        if matches!(n.event, DomainEvent::Requested { .. }) && !self.config.mention_roles.is_empty() {
            mentions = AllowedMentions { roles: self.config.mention_roles.clone(), ..AllowedMentions::default() };
            content = self.config.mention_roles.iter().map(|r| format!("<@&{r}>")).collect::<Vec<_>>().join(" ");
            req = req.content(&content).allowed_mentions(Some(&mentions));
        }
        let msg = req.await.map_err(http_error)?.model().await.map_err(other)?;
        Ok(Some(MessageRef { channel: self.scope.name.clone(), id: format!("{}:{}", msg.channel_id, msg.id) }))
    }

    async fn update(&self, msg: &MessageRef, n: Notification<'_>) -> Result<(), ChannelError> {
        let (channel, message) = parse_message_ref(&msg.id)
            .ok_or_else(|| ChannelError::Other(format!("malformed message reference {:?}", msg.id).into()))?;
        let v = view(n, self.capabilities());
        self.http
            .update_message(channel, message)
            .embeds(Some(&v.embeds))
            .components(Some(&v.components))
            .await
            .map_err(http_error)?;
        Ok(())
    }

    async fn announce(&self, notice: &AdminNotice) -> Result<(), ChannelError> {
        use twilight_model::channel::message::embed::{Embed, EmbedFooter};
        let web = (notice.web_url.starts_with("https://") || notice.web_url.starts_with("http://"))
            .then(|| notice.web_url.clone());
        let embed = Embed {
            author: None,
            color: Some(0x00e7_4c3c),
            description: Some(render::markdown(&notice.summary())),
            fields: Vec::new(),
            flags: None,
            footer: Some(EmbedFooter {
                icon_url: None,
                proxy_icon_url: None,
                text: format!("countersign · admin · {}", notice.event_id),
            }),
            image: None,
            kind: "rich".to_owned(),
            provider: None,
            thumbnail: None,
            timestamp: None,
            title: Some(render::markdown(&notice.title())),
            url: web,
            video: None,
        };
        let embeds = [embed];
        self.http.create_message(self.config.channel_id).embeds(&embeds).await.map_err(http_error)?;
        Ok(())
    }

    async fn run(&self, sink: Arc<dyn ActionSink>) -> Result<(), ChannelError> {
        // Without the command users cannot link, but buttons still work for
        // those already linked, so keep going.
        if let Err(e) = self.register_commands().await {
            tracing::warn!(channel = %self.scope.name, error = %e, "could not register the Discord link command");
        }
        let mut shard = Shard::new(ShardId::ONE, self.token.clone(), Intents::empty());
        tracing::info!(channel = %self.scope.name, "connecting to the Discord Gateway");
        while let Some(item) = shard.next_event(EventTypeFlags::INTERACTION_CREATE).await {
            match item {
                Ok(Event::InteractionCreate(i)) => {
                    let (http, scope, sink) = (Arc::clone(&self.http), self.scope.clone(), Arc::clone(&sink));
                    tokio::spawn(async move { respond(&http, &scope, sink.as_ref(), i.0).await });
                }
                Ok(_) => {}
                // The shard reconnects by itself; these are informational.
                Err(e) => tracing::warn!(channel = %self.scope.name, error = %e, "Discord Gateway"),
            }
        }
        Err(ChannelError::Unavailable("the Discord Gateway connection closed".to_owned()))
    }
}

/// Acknowledge at once (Discord allows 3 seconds; a decision may take longer
/// because approving applies the grant), then fill in the reply.
async fn respond(http: &Client, scope: &Scope, sink: &dyn ActionSink, i: Interaction) {
    let Some(action) = interact::action(&i) else { return };
    let client = http.interaction(i.application_id);
    let defer = InteractionResponse {
        kind: InteractionResponseType::DeferredChannelMessageWithSource,
        data: Some(InteractionResponseData {
            flags: Some(MessageFlags::EPHEMERAL),
            ..InteractionResponseData::default()
        }),
    };
    if let Err(e) = client.create_response(i.id, &i.token, &defer).await {
        // Not acknowledged means the user sees "interaction failed"; do not act
        // on something they will believe did not happen.
        tracing::warn!(channel = %scope.name, error = %e, "could not acknowledge a Discord interaction");
        return;
    }
    let text = interact::perform(scope, sink, &i, action).await;
    let none = AllowedMentions::default();
    if let Err(e) = client.update_response(&i.token).content(Some(&text)).allowed_mentions(Some(&none)).await {
        tracing::warn!(channel = %scope.name, error = %e, "could not reply to a Discord interaction");
    }
}

fn parse_message_ref(s: &str) -> Option<(Id<ChannelMarker>, Id<MessageMarker>)> {
    let (c, m) = s.split_once(':')?;
    Some((c.parse().ok()?, m.parse().ok()?))
}

fn http_error(e: twilight_http::Error) -> ChannelError {
    match e.kind() {
        ErrorType::Response { status, .. } if status.get() == 429 => ChannelError::RateLimited { retry_after: None },
        ErrorType::Response { status, .. } if status.is_server_error() => {
            ChannelError::Unavailable(format!("Discord returned {}", status.get()))
        }
        ErrorType::RequestError | ErrorType::RequestTimedOut | ErrorType::RequestCanceled => {
            ChannelError::Unavailable(e.to_string())
        }
        _ => ChannelError::Other(Box::new(e)),
    }
}

fn other(e: impl std::error::Error + Send + Sync + 'static) -> ChannelError {
    ChannelError::Other(Box::new(e))
}
