//! Interpreting interactions (button presses, the link command).
//!
//! Discord authenticates the presser for us: interactions arrive over the bot's
//! own Gateway connection and carry the Discord user ID. That ID only becomes
//! a person through an account link made with a one-time code from the web
//! UI, so a decision or answer made here is worth [`Assurance::Linked`].

use serde_json::{Map, Value};
use twilight_model::application::command::{Command, CommandOption, CommandOptionType, CommandType};
use twilight_model::application::interaction::application_command::CommandOptionValue;
use twilight_model::application::interaction::{Interaction, InteractionContextType, InteractionData, InteractionType};
use twilight_model::id::Id;
use twilight_model::id::marker::{ChannelMarker, GuildMarker};

pub use countersign_core::channel::ChatAction as Action;
use countersign_core::channel::execute_chat_action;
use countersign_core::{ActionSink, ChannelName, RequestId, Verdict};

pub const LINK_COMMAND: &str = "countersign-link";

const CODE_OPTION: &str = "code";
const PREFIX: &str = "cs";
/// Discord's limit on a component's `custom_id`.
const MAX_CUSTOM_ID: usize = 100;

/// Where this channel accepts actions from.
#[derive(Debug, Clone)]
pub struct Scope {
    pub name: ChannelName,
    pub channel_id: Id<ChannelMarker>,
    pub guild_id: Option<Id<GuildMarker>>,
}

/// The `custom_id` of a button answering `question` with `field = value`, if
/// it fits. The engine checks the answer against the form like any other.
pub fn answer_custom_id(question: RequestId, field: &str, value: &Value) -> Option<String> {
    let mut content = Map::new();
    content.insert(field.to_owned(), value.clone());
    let id = format!("{PREFIX}:answer:{question}:{}", Value::Object(content));
    (id.len() <= MAX_CUSTOM_ID).then_some(id)
}

pub fn decline_custom_id(question: RequestId) -> String {
    format!("{PREFIX}:decline:{question}")
}

fn parse_question_custom_id(s: &str) -> Option<Action> {
    let mut parts = s.splitn(4, ':');
    if parts.next()? != PREFIX {
        return None;
    }
    match parts.next()? {
        "answer" => {
            let question_id = parts.next()?.parse().ok()?;
            let Value::Object(content) = serde_json::from_str(parts.next()?).ok()? else { return None };
            Some(Action::Answer { question_id, content })
        }
        "decline" => {
            let rest = parts.next()?;
            parts.next().is_none().then_some(())?;
            Some(Action::Decline { question_id: rest.parse().ok()? })
        }
        _ => None,
    }
}

pub fn custom_id(verdict: Verdict, id: RequestId) -> String {
    let verb = match verdict {
        Verdict::Approve => "approve",
        Verdict::Deny => "deny",
    };
    format!("{PREFIX}:{verb}:{id}")
}

pub fn parse_custom_id(s: &str) -> Option<(Verdict, RequestId)> {
    let mut parts = s.splitn(3, ':');
    if parts.next()? != PREFIX {
        return None;
    }
    let verdict = match parts.next()? {
        "approve" => Verdict::Approve,
        "deny" => Verdict::Deny,
        _ => return None,
    };
    Some((verdict, parts.next()?.parse().ok()?))
}

/// The action an interaction asks for, if it is one of ours.
pub fn action(i: &Interaction) -> Option<Action> {
    match (&i.kind, i.data.as_ref()?) {
        (InteractionType::MessageComponent, InteractionData::MessageComponent(d)) => {
            if let Some((verdict, request_id)) = parse_custom_id(&d.custom_id) {
                return Some(Action::Decide { verdict, request_id });
            }
            parse_question_custom_id(&d.custom_id)
        }
        (InteractionType::ApplicationCommand, InteractionData::ApplicationCommand(d)) if d.name == LINK_COMMAND => {
            let code = d.options.iter().find(|o| o.name == CODE_OPTION).and_then(|o| match &o.value {
                CommandOptionValue::String(s) => Some(s.trim().to_owned()),
                _ => None,
            })?;
            Some(Action::Link { code })
        }
        _ => None,
    }
}

/// Carry out an action and produce the (ephemeral) reply text.
pub async fn perform(scope: &Scope, sink: &dyn ActionSink, i: &Interaction, action: Action) -> String {
    let Some(user) = i.author_id() else {
        return "Could not tell who you are.".to_owned();
    };
    let external_id = user.to_string();
    // Linking is allowed anywhere (e.g. in a DM with the bot): the code is the proof.
    // Everything else only from our own channel (and guild, if pinned).
    if !matches!(action, Action::Link { .. }) {
        let from = i.message.as_ref().map(|m| m.channel_id).or_else(|| i.channel.as_ref().map(|c| c.id));
        if from != Some(scope.channel_id) || scope.guild_id.is_some_and(|g| i.guild_id != Some(g)) {
            return "countersign does not accept actions here.".to_owned();
        }
    }
    let hint = format!("`/{LINK_COMMAND}` with the code shown there");
    execute_chat_action(sink, &scope.name, "Discord", &external_id, &hint, &action).await
}

/// The slash command that redeems a link code.
#[allow(deprecated)] // `dm_permission` must still be set when constructing.
pub fn link_command() -> Command {
    Command {
        application_id: None,
        contexts: Some(vec![InteractionContextType::Guild, InteractionContextType::BotDm]),
        default_member_permissions: None,
        description: "Link your Discord account to your countersign person".to_owned(),
        description_localizations: None,
        dm_permission: None,
        guild_id: None,
        id: None,
        integration_types: None,
        kind: CommandType::ChatInput,
        name: LINK_COMMAND.to_owned(),
        name_localizations: None,
        nsfw: None,
        options: vec![CommandOption {
            autocomplete: None,
            channel_types: None,
            choices: None,
            description: "One-time code from the countersign web UI".to_owned(),
            description_localizations: None,
            kind: CommandOptionType::String,
            max_length: Some(64),
            max_value: None,
            min_length: Some(4),
            min_value: None,
            name: CODE_OPTION.to_owned(),
            name_localizations: None,
            options: None,
            file_types: None,
            required: Some(true),
        }],
        version: Id::new(1),
    }
}
