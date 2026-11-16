//! Turning an approval or a question into a Discord message (embed + buttons).
//!
//! Everything the backend, requester or asker supplied is shown inside code
//! spans or blocks so it cannot render as links, mentions, or formatting;
//! mentions are additionally suppressed through `allowed_mentions` when
//! sending.
//!
//! A sensitive approval or a confidential question shows only that it exists,
//! where it came from and its policy, with a link to the web UI. Answers are
//! never shown here, only who answered.

use std::fmt::Write as _;
use std::time::Duration;

use countersign_core::{
    ApproveMode, ChannelCaps, FieldKind, GrantMode, Item, Notification, Question, QuestionOutcome, Request,
    RequestState, Verdict,
};
use twilight_model::channel::message::Component;
use twilight_model::channel::message::component::{ActionRow, Button, ButtonStyle};
use twilight_model::channel::message::embed::{Embed, EmbedField, EmbedFooter};

use crate::interact::{answer_custom_id, custom_id, decline_custom_id};

/// The parts of a message that reflect a request's current state.
#[derive(Debug, Clone, PartialEq)]
pub struct View {
    pub embeds: Vec<Embed>,
    pub components: Vec<Component>,
}

const PENDING: u32 = 0x00f1_c40f;
const GOOD: u32 = 0x002e_cc71;
/// Approved and since finished: still green, darker than a live approval.
const DONE: u32 = 0x001f_8b4c;
const BAD: u32 = 0x00e7_4c3c;
const MUTED: u32 = 0x0095_a5a6;
/// Questions, while waiting for an answer.
const QUESTION: u32 = 0x006f_42c1;
/// Most options a question can offer as buttons (one row, plus Decline).
const MAX_OPTION_BUTTONS: usize = 4;
/// Longest question text and context shown; within Discord's 6000-character
/// embed total.
const MAX_MESSAGE: usize = 2000;
const MAX_CONTEXT_SHOWN: usize = 2400;
const MAX_DECISIONS: usize = 10;
/// Longest command and reason shown in full. Together they stay within
/// Discord's 4096-character embed description.
const MAX_COMMAND: usize = 3200;
const MAX_REASON: usize = 600;

pub fn view(n: Notification<'_>, caps: ChannelCaps) -> View {
    let web = web_link(n.web_url);
    match n.item {
        Item::Approval(r) if r.sensitive => {
            View { embeds: vec![withheld_approval_embed(r, web)], components: link_only(r.state.is_pending(), web) }
        }
        Item::Approval(r) => View { embeds: vec![embed(r, web)], components: components(r, web, caps) },
        Item::Question(q) => {
            let (embed, complete) = question_embed(q, web);
            View { embeds: vec![embed], components: question_components(q, web, caps, complete) }
        }
    }
}

fn base_embed(title: String, color: u32, id: impl std::fmt::Display, web: Option<&str>) -> Embed {
    Embed {
        author: None,
        color: Some(color),
        description: None,
        fields: Vec::new(),
        flags: None,
        footer: Some(EmbedFooter { icon_url: None, proxy_icon_url: None, text: format!("countersign · {id}") }),
        image: None,
        kind: "rich".to_owned(),
        provider: None,
        thumbnail: None,
        timestamp: None,
        title: Some(title),
        url: web.map(str::to_owned),
        video: None,
    }
}

fn field(e: &mut Embed, name: &str, value: String, inline: bool) {
    e.fields.push(EmbedField { inline, name: name.to_owned(), value });
}

/// A sensitive approval: no requester, target, command or reason.
fn withheld_approval_embed(r: &Request, web: Option<&str>) -> Embed {
    let item = Item::Approval(r);
    let mut e = base_embed(format!("Sensitive access request — {}", r.state.name()), color(&r.state), r.id, web);
    e.description = Some(format!("{}\nThe details are only in the web UI.", code(&item.safe_title())));
    field(&mut e, "From", code(&item.origin()), true);
    field(&mut e, "Policy", code(item.policy()), true);
    field(
        &mut e,
        "Approvals",
        format!("{}/{} (min. assurance: {})", r.approvals().len(), r.requirements.quorum, r.requirements.min_assurance),
        true,
    );
    if r.state.is_pending() {
        field(&mut e, "Decide by", format!("<t:{0}:f> (<t:{0}:R>)", r.pending_until.as_second()), false);
    }
    e
}

fn link_only(pending: bool, web: Option<&str>) -> Vec<Component> {
    match web {
        Some(url) if pending => row(vec![link_button("Review in web UI", url)]),
        _ => Vec::new(),
    }
}

fn row(buttons: Vec<Component>) -> Vec<Component> {
    if buttons.is_empty() {
        return Vec::new();
    }
    vec![Component::ActionRow(ActionRow { components: buttons, id: None })]
}

pub(crate) fn question_color(q: &Question) -> u32 {
    match &q.outcome {
        None => QUESTION,
        Some(QuestionOutcome::Accepted { .. }) => DONE,
        Some(QuestionOutcome::Declined { .. }) => BAD,
        Some(QuestionOutcome::Expired { .. } | QuestionOutcome::Withdrawn { .. }) => MUTED,
    }
}

/// The question's embed, and whether everything a responder needs to answer
/// is on it.
fn question_embed(q: &Question, web: Option<&str>) -> (Embed, bool) {
    let item = Item::Question(q);
    let state = if q.state() == "expired" { "no answer" } else { q.state() };
    let mut e = base_embed(format!("Question — {state}"), question_color(q), q.id, web);
    let mut complete = true;
    if q.question_confidential() {
        e.description = Some(format!("{}\nConfidential: read and answer it in the web UI.", code(&item.safe_title())));
        complete = false;
    } else if !q.message.is_empty() {
        complete &= block_text(&q.message).chars().count() <= MAX_MESSAGE;
        e.description = Some(code_block(&q.message, MAX_MESSAGE));
    }
    let mut asker = code(q.asker.client.as_str());
    if let Some(a) = &q.asker.actor {
        let _ = write!(asker, " for {}", code(a.as_str()));
    }
    field(&mut e, "From", asker, true);
    field(&mut e, "Policy", code(item.policy()), true);
    if !q.question_confidential() {
        let mut shown = 0;
        for (k, v) in &q.context {
            shown += k.chars().count() + v.chars().count();
            if shown > MAX_CONTEXT_SHOWN {
                complete = false;
                field(&mut e, "…", "More context in the web UI.".to_owned(), false);
                break;
            }
            complete &= block_text(v).chars().count() <= CODE_MAX;
            field(&mut e, &clean_name(k), code(v), true);
        }
    }
    if q.is_pending() {
        field(&mut e, "Answer by", format!("<t:{0}:f> (<t:{0}:R>)", q.pending_until.as_second()), false);
    } else if let Some(result) = Item::question_result(q) {
        field(&mut e, "Result", result, false);
    }
    (e, complete)
}

/// Field names come from the asker: one line, no formatting, bounded.
fn clean_name(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(
            |c| if c.is_control() || countersign_core::text::is_hidden(c) || "*_~|`>#[]".contains(c) { ' ' } else { c },
        )
        .collect();
    let t = truncate(cleaned.trim(), 60);
    if t.is_empty() { "—".to_owned() } else { t }
}

/// The buttons answering a question in place: one per option of a single
/// required choice, or Yes/No. Only when the whole question is on screen, it
/// is not confidential, the asker did not say the answer may be, and Discord's
/// assurance is enough.
fn answer_buttons(q: &Question, caps: ChannelCaps, complete: bool) -> Option<Vec<Component>> {
    if !caps.interactive || !complete || q.confidentiality.question || q.confidentiality.answer_may_be {
        return None;
    }
    if caps.max_assurance.is_none_or(|max| max < q.required_assurance()) {
        return None;
    }
    let form = q.form().ok()?;
    let f = form.single_button_field()?;
    let options: Vec<(String, serde_json::Value)> = match &f.kind {
        FieldKind::Boolean { .. } => {
            vec![("Yes".to_owned(), serde_json::Value::Bool(true)), ("No".to_owned(), serde_json::Value::Bool(false))]
        }
        FieldKind::Choice { options, .. } if options.len() <= MAX_OPTION_BUTTONS => {
            options.iter().map(|o| (o.label().to_owned(), serde_json::Value::String(o.value.clone()))).collect()
        }
        _ => return None,
    };
    let mut buttons = Vec::new();
    for (label, value) in options {
        let id = answer_custom_id(q.id, &f.name, &value)?;
        buttons.push(Component::Button(Button {
            custom_id: Some(id),
            disabled: false,
            emoji: None,
            id: None,
            label: Some(truncate(&clean_name(&label), 80)),
            sku_id: None,
            style: ButtonStyle::Primary,
            url: None,
        }));
    }
    Some(buttons)
}

fn question_components(q: &Question, web: Option<&str>, caps: ChannelCaps, complete: bool) -> Vec<Component> {
    if !q.is_pending() {
        return Vec::new();
    }
    let mut buttons = match answer_buttons(q, caps, complete) {
        Some(b) => b,
        None => web.map(|url| vec![link_button("Answer in web UI", url)]).unwrap_or_default(),
    };
    if caps.interactive && !q.confidentiality.question {
        buttons.push(Component::Button(Button {
            custom_id: Some(decline_custom_id(q.id)),
            disabled: false,
            emoji: None,
            id: None,
            label: Some("Decline".to_owned()),
            sku_id: None,
            style: ButtonStyle::Danger,
            url: None,
        }));
    }
    row(buttons)
}

fn embed(r: &Request, web: Option<&str>) -> Embed {
    let facts = &r.facts;
    let mut fields = Vec::new();
    let mut field = |name: &str, value: String, inline: bool| {
        fields.push(EmbedField { inline, name: name.to_owned(), value });
    };

    let mut requester = code(&facts.requester.id);
    if let Some(name) = &facts.requester.display_name {
        let _ = write!(requester, " ({})", code(name));
    }
    field("Requester", requester, true);
    if let Some(target) = &facts.target {
        field("Target", code(target), true);
    }
    if let Some(runas) = facts.attributes.get("runas") {
        field("Run as", code(runas), true);
    }
    let window = if r.requirements.grant == GrantMode::Window { " (window)" } else { "" };
    field("Duration", format!("{}{window}", duration(r.requirements.ttl)), true);
    field("Policy", code(r.requirements.policy.as_str()), true);
    field(
        "Approvals",
        format!("{}/{} (min. assurance: {})", r.approvals().len(), r.requirements.quorum, r.requirements.min_assurance),
        true,
    );
    field("Subject", code(&format!("{}/{}/{}", r.subject.backend, r.subject.kind, r.subject.id)), true);
    match &r.state {
        RequestState::Pending => {
            field("Decide by", format!("<t:{0}:f> (<t:{0}:R>)", r.pending_until.as_second()), false);
        }
        RequestState::Active { until } => {
            field("Active until", format!("<t:{0}:f> (<t:{0}:R>)", until.as_second()), false);
        }
        RequestState::Failed { error } => field("Error", code(error), false),
        _ => {}
    }
    if !r.decisions.is_empty() {
        let mut lines = String::new();
        for d in r.decisions.iter().take(MAX_DECISIONS) {
            let mark = match d.verdict {
                Verdict::Approve => "✅",
                Verdict::Deny => "⛔",
            };
            let _ =
                writeln!(lines, "{mark} {} via {} ({})", code(d.approver.as_str()), code(d.via.as_str()), d.assurance);
        }
        if r.decisions.len() > MAX_DECISIONS {
            let _ = writeln!(lines, "… and {} more", r.decisions.len() - MAX_DECISIONS);
        }
        field("Decisions", lines, false);
    }

    let mut e = base_embed(format!("Access request — {}", r.state.name()), color(&r.state), r.id, web);
    e.description = description(facts);
    e.fields = fields;
    e
}

fn components(r: &Request, web: Option<&str>, caps: ChannelCaps) -> Vec<Component> {
    let mut buttons = Vec::new();
    let mode = match ApproveMode::for_request(caps, r) {
        // Approving here needs everything the approver is approving to be
        // on screen; otherwise send them to the web UI.
        ApproveMode::Direct if !shown_in_full(&r.facts) => ApproveMode::WebLink,
        mode => mode,
    };
    match mode {
        ApproveMode::Direct => {
            buttons.push(action_button(r, Verdict::Approve));
            buttons.push(action_button(r, Verdict::Deny));
            if let Some(url) = web {
                buttons.push(link_button("Details", url));
            }
        }
        ApproveMode::WebLink => {
            if let Some(url) = web {
                buttons.push(link_button("Approve in web UI", url));
            }
            if caps.interactive {
                buttons.push(action_button(r, Verdict::Deny));
            }
        }
        ApproveMode::None => {}
    }
    row(buttons)
}

fn action_button(r: &Request, verdict: Verdict) -> Component {
    let (label, style) = match verdict {
        Verdict::Approve => ("Approve", ButtonStyle::Success),
        Verdict::Deny => ("Deny", ButtonStyle::Danger),
    };
    Component::Button(Button {
        custom_id: Some(custom_id(verdict, r.id)),
        disabled: false,
        emoji: None,
        id: None,
        label: Some(label.to_owned()),
        sku_id: None,
        style,
        url: None,
    })
}

fn link_button(label: &str, url: &str) -> Component {
    Component::Button(Button {
        custom_id: None,
        disabled: false,
        emoji: None,
        id: None,
        label: Some(label.to_owned()),
        sku_id: None,
        style: ButtonStyle::Link,
        url: Some(url.to_owned()),
    })
}

/// Discord only accepts http(s) URLs for links.
fn web_link(url: &str) -> Option<&str> {
    (url.starts_with("https://") || url.starts_with("http://")).then_some(url)
}

pub(crate) fn color(state: &RequestState) -> u32 {
    match state {
        RequestState::Pending => PENDING,
        RequestState::Approved | RequestState::Active { .. } => GOOD,
        RequestState::Denied | RequestState::Failed { .. } | RequestState::Revoked => BAD,
        RequestState::Ended => DONE,
        RequestState::Expired | RequestState::Withdrawn => MUTED,
    }
}

/// Longest inline code span.
const CODE_MAX: usize = 200;

/// Untrusted text as an inline code span, on one line.
pub(crate) fn code(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c == '`' {
                'ˋ'.to_string()
            } else if c.is_control() {
                ' '.to_string()
            } else if countersign_core::text::is_hidden(c) {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect();
    let cleaned = truncate(cleaned.trim(), CODE_MAX);
    if cleaned.is_empty() { "—".to_owned() } else { format!("`{cleaned}`") }
}

/// The command (if the backend reports one) and the requester's reason.
fn description(facts: &countersign_core::SubjectFacts) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(command) = facts.attributes.get("command") {
        parts.push(format!("**Command**\n{}", code_block(command, MAX_COMMAND)));
    }
    if let Some(reason) = &facts.reason {
        parts.push(format!("**Reason**\n{}", code_block(reason, MAX_REASON)));
    }
    (!parts.is_empty()).then(|| parts.join("\n"))
}

/// Whether [`description`] shows the command and reason without cutting them.
fn shown_in_full(facts: &countersign_core::SubjectFacts) -> bool {
    let fits = |s: &str, max: usize| block_text(s).chars().count() <= max;
    facts.attributes.get("command").is_none_or(|c| fits(c, MAX_COMMAND))
        && facts.reason.as_deref().is_none_or(|r| fits(r, MAX_REASON))
}

/// Untrusted multi-line text as it appears inside a code block: no way out of
/// the block, and hidden characters written out (line breaks are kept).
fn block_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.trim().chars() {
        match c {
            '`' => out.push('ˋ'),
            '\n' => out.push(c),
            c if countersign_core::text::is_hidden(c) => out.extend(c.escape_default()),
            c => out.push(c),
        }
    }
    out
}

/// Untrusted multi-line text as a code block, cut after `max` characters.
pub(crate) fn code_block(s: &str, max: usize) -> String {
    format!("```\n{}\n```", truncate(&block_text(s), max))
}

fn truncate(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        Some((i, _)) => format!("{}…", &s[..i]),
        None => s.to_owned(),
    }
}

pub(crate) fn duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        return format!("{secs}s");
    }
    let (days, hours, mins) = (secs / 86_400, secs / 3600 % 24, secs / 60 % 60);
    let mut out = String::new();
    for (n, unit) in [(days, "d"), (hours, "h"), (mins, "m")] {
        if n > 0 {
            let _ = write!(out, "{}{n}{unit}", if out.is_empty() { "" } else { " " });
        }
    }
    out
}
