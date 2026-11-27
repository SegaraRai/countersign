//! Interpreting Slack Socket Mode envelopes (button presses, `/countersign-link`).
//!
//! Slack authenticates the presser for us: envelopes arrive over the app's own
//! Socket Mode WebSocket and carry the Slack user ID. That ID only becomes a
//! person through an account link made with a one-time code from the web UI,
//! so a decision or answer made here is worth [`Assurance::Linked`].

use serde::Deserialize;
use serde_json::{Map, Value};

use countersign_core::{ActionIntent, ActionSink, AnswerIntent, Assurance, ChannelName, RequestId, Response, Verdict};

pub const LINK_COMMAND: &str = "/countersign-link";

const PREFIX: &str = "cs";

/// Where this channel accepts actions from.
#[derive(Debug, Clone)]
pub struct Scope {
    pub name: ChannelName,
    pub channel_id: String,
    pub team_id: Option<String>,
}

/// Top-level Socket Mode envelope from Slack.
#[derive(Debug, Clone, Deserialize)]
pub struct Envelope {
    #[serde(default)]
    pub envelope_id: Option<String>,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub payload: Value,
}

/// What a user asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Decide { verdict: Verdict, request_id: RequestId },
    Answer { question_id: RequestId, content: Map<String, Value> },
    Decline { question_id: RequestId },
    Link { code: String },
}

/// Parsed inbound Slack event ready to authorize and execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedInteraction {
    pub user_id: String,
    pub channel_id: Option<String>,
    pub team_id: Option<String>,
    pub response_url: Option<String>,
    pub action: Action,
}

pub fn action_id(verdict: Verdict, id: RequestId) -> String {
    let verb = match verdict {
        Verdict::Approve => "approve",
        Verdict::Deny => "deny",
    };
    format!("{PREFIX}:{verb}:{id}")
}

pub fn open_action_id(id: RequestId) -> String {
    format!("{PREFIX}:open:{id}")
}

pub fn answer_action_id(question: RequestId, index: usize) -> String {
    format!("{PREFIX}:answer:{question}:{index}")
}

pub fn decline_action_id(question: RequestId) -> String {
    format!("{PREFIX}:decline:{question}")
}

pub fn parse_action_id(s: &str) -> Option<(Verdict, RequestId)> {
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

fn parse_button_action(id: &str, value: Option<&str>) -> Option<Action> {
    if let Some((verdict, request_id)) = parse_action_id(id) {
        return Some(Action::Decide { verdict, request_id });
    }
    let mut parts = id.splitn(4, ':');
    if parts.next()? != PREFIX {
        return None;
    }
    match parts.next()? {
        "answer" => {
            let question_id: RequestId = parts.next()?.parse().ok()?;
            let _index: usize = parts.next()?.parse().ok()?;
            let Value::Object(content) = serde_json::from_str(value?).ok()? else { return None };
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

/// Extract a countersign action from a Socket Mode envelope, if it is one of ours.
pub fn parse_envelope(env: &Envelope) -> Option<ParsedInteraction> {
    match env.kind.as_str() {
        "interactive" => {
            if env.payload.get("type").and_then(Value::as_str) != Some("block_actions") {
                return None;
            }
            let user_id = env.payload.pointer("/user/id").and_then(Value::as_str)?.to_owned();
            let channel_id = env.payload.pointer("/channel/id").and_then(Value::as_str).map(str::to_owned);
            let team_id = env
                .payload
                .pointer("/team/id")
                .or_else(|| env.payload.pointer("/user/team_id"))
                .and_then(Value::as_str)
                .map(str::to_owned);
            let response_url = env.payload.get("response_url").and_then(Value::as_str).map(str::to_owned);
            let first = env.payload.get("actions")?.as_array()?.first()?;
            let id = first.get("action_id").and_then(Value::as_str)?;
            let value = first.get("value").and_then(Value::as_str);
            let action = parse_button_action(id, value)?;
            Some(ParsedInteraction { user_id, channel_id, team_id, response_url, action })
        }
        "slash_commands" => {
            let command = env.payload.get("command").and_then(Value::as_str)?;
            if command != LINK_COMMAND {
                return None;
            }
            let user_id = env.payload.get("user_id").and_then(Value::as_str)?.to_owned();
            let channel_id = env.payload.get("channel_id").and_then(Value::as_str).map(str::to_owned);
            let team_id = env.payload.get("team_id").and_then(Value::as_str).map(str::to_owned);
            let response_url = env.payload.get("response_url").and_then(Value::as_str).map(str::to_owned);
            let code = env.payload.get("text").and_then(Value::as_str).unwrap_or("").trim().to_owned();
            Some(ParsedInteraction { user_id, channel_id, team_id, response_url, action: Action::Link { code } })
        }
        _ => None,
    }
}

/// Carry out an action and produce the ephemeral reply text.
pub async fn perform(scope: &Scope, sink: &dyn ActionSink, p: &ParsedInteraction) -> String {
    if let Some(expected_team) = &scope.team_id
        && p.team_id.as_deref() != Some(expected_team.as_str())
    {
        return "countersign does not accept actions from this workspace.".to_owned();
    }
    if let Action::Link { code } = &p.action {
        if code.is_empty() {
            return format!("Usage: `{LINK_COMMAND} <code>` (get a one-time code from the countersign web UI).");
        }
        // Linking is allowed from any channel or DM in the workspace: the code is the proof.
        return match sink.link_account(&scope.name, &p.user_id, code).await {
            Ok(person) => format!("Linked your Slack account to `{person}`."),
            Err(e) => format!("Could not link: {e}"),
        };
    }
    // Decisions and answers are accepted only from our configured channel.
    if p.channel_id.as_deref() != Some(scope.channel_id.as_str()) {
        return "countersign does not accept actions here.".to_owned();
    }
    let approver = match sink.resolve_account(&scope.name, &p.user_id).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return format!(
                "Your Slack account is not linked to a countersign person. Sign in to the web UI, \
                 choose \"Link chat account\", and run `{LINK_COMMAND} <code>`."
            );
        }
        Err(e) => return format!("Not recorded: {e}"),
    };
    match &p.action {
        Action::Answer { question_id, content } => {
            let intent = AnswerIntent {
                question_id: *question_id,
                responder: approver.clone(),
                response: Response::Accept { content: content.clone(), confidential: false },
                assurance: Assurance::Linked,
                via: scope.name.clone(),
            };
            match sink.answer(intent).await {
                Ok(_) => format!("Recorded your answer as `{approver}`."),
                Err(e) => format!("Not recorded: {e}"),
            }
        }
        Action::Decline { question_id } => {
            let intent = AnswerIntent {
                question_id: *question_id,
                responder: approver.clone(),
                response: Response::Decline { note: None },
                assurance: Assurance::Linked,
                via: scope.name.clone(),
            };
            match sink.answer(intent).await {
                Ok(_) => format!("Recorded that `{approver}` declined to answer."),
                Err(e) => format!("Not recorded: {e}"),
            }
        }
        Action::Decide { verdict, request_id } => {
            let intent = ActionIntent {
                request_id: *request_id,
                verdict: *verdict,
                approver: approver.clone(),
                assurance: Assurance::Linked,
                via: scope.name.clone(),
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
        Action::Link { .. } => unreachable!("handled above"),
    }
}
