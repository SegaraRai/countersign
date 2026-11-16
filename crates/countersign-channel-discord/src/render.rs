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

use countersign_core::present::{Audience, Presentation, Shown, Tone, When};
use countersign_core::{ApproveMode, ChannelCaps, FieldKind, Item, Notification, Question, Request, Verdict};
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
/// Most window uses listed.
const MAX_USES: usize = 5;
/// Longest command and reason shown in full. Together they stay within
/// Discord's 4096-character embed description.
const MAX_COMMAND: usize = 3200;
const MAX_REASON: usize = 600;

pub fn view(n: Notification<'_>, caps: ChannelCaps) -> View {
    let web = web_link(n.web_url);
    match n.item {
        Item::Approval(r) => {
            let p = Presentation::approval(r, Audience::Chat);
            if p.withheld {
                View { embeds: vec![withheld_embed(r, &p, web)], components: link_only(r.state.is_pending(), web) }
            } else {
                View { embeds: vec![embed(r, &p, web)], components: components(r, web, caps, shown_in_full(&p)) }
            }
        }
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
fn withheld_embed(r: &Request, p: &Presentation, web: Option<&str>) -> Embed {
    let mut e = base_embed(title(p), tone_color(p.status.tone), r.id, web);
    e.description = Some("The details are only in the web UI.".to_owned());
    for d in &p.facts {
        field(&mut e, &d.label, code(&d.value), true);
    }
    status_fields(&mut e, p);
    e
}

/// `<state> — <headline>`, within Discord's title limit.
fn title(p: &Presentation) -> String {
    truncate(&markdown(&format!("{} — {}", p.status.label, p.headline)), 250)
}

/// Needs, the time that matters, and how it stands.
fn status_fields(e: &mut Embed, p: &Presentation) {
    if let Some(needs) = &p.status.needs {
        field(e, "Needs", markdown(needs), true);
    }
    if let Some(When { label, at }) = p.status.time {
        field(e, label, format!("<t:{0}:f> (<t:{0}:R>)", at.as_second()), true);
    }
    if let Some(detail) = &p.status.detail {
        field(e, "Status", markdown(detail), false);
    }
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

/// The question's embed, and whether everything a responder needs to answer
/// is on it.
fn question_embed(q: &Question, web: Option<&str>) -> (Embed, bool) {
    let item = Item::Question(q);
    let p = Presentation::question(q, Audience::Chat);
    let mut e = base_embed(title(&p), tone_color(p.status.tone), q.id, web);
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

fn embed(r: &Request, p: &Presentation, web: Option<&str>) -> Embed {
    let mut e = base_embed(title(p), tone_color(p.status.tone), r.id, web);
    e.description = Some(description(p));
    for d in &p.facts {
        field(&mut e, &d.label, code(&d.value), true);
    }
    status_fields(&mut e, p);
    if !p.status.decisions.is_empty() {
        let mut lines = String::new();
        for d in p.status.decisions.iter().take(MAX_DECISIONS) {
            let mark = if d.approved { "✅" } else { "⛔" };
            let _ = writeln!(lines, "{mark} {} via {} ({})", code(&d.who), code(&d.via), d.assurance);
        }
        if p.status.decisions.len() > MAX_DECISIONS {
            let _ = writeln!(lines, "… and {} more", p.status.decisions.len() - MAX_DECISIONS);
        }
        field(&mut e, "Decisions", lines, false);
    }
    if !p.status.uses.is_empty() {
        let mut lines = String::new();
        let skipped = p.status.uses.len().saturating_sub(MAX_USES);
        if skipped > 0 {
            let _ = writeln!(lines, "… {skipped} earlier");
        }
        for u in p.status.uses.iter().skip(skipped) {
            let _ = writeln!(lines, "<t:{}:t> {}", u.at.as_second(), code(&u.what));
        }
        field(&mut e, "Used for", lines, false);
    }
    e
}

fn components(r: &Request, web: Option<&str>, caps: ChannelCaps, complete: bool) -> Vec<Component> {
    let mut buttons = Vec::new();
    let mode = match ApproveMode::for_request(caps, r) {
        // Approving here needs everything the approver is approving to be
        // on screen; otherwise send them to the web UI.
        ApproveMode::Direct if !complete => ApproveMode::WebLink,
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

pub(crate) fn tone_color(tone: Tone) -> u32 {
    match tone {
        Tone::Waiting => PENDING,
        Tone::Asking => QUESTION,
        Tone::Good => GOOD,
        Tone::Done => DONE,
        Tone::Bad => BAD,
        Tone::Muted => MUTED,
    }
}

/// Text that may contain names, with Discord markdown escaped outside the
/// code spans countersign itself wrote (globs in the grant sentence).
pub(crate) fn markdown(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for (i, part) in s.split('`').enumerate() {
        if i > 0 {
            out.push('`');
        }
        if i % 2 == 1 {
            out.push_str(part);
            continue;
        }
        for c in part.chars() {
            if "\\*_~|>#[]()<".contains(c) {
                out.push('\\');
            }
            out.push(if c.is_control() { ' ' } else { c });
        }
    }
    out
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

/// What approving allows, then the action, countersign's notes and the
/// requester's claims.
fn description(p: &Presentation) -> String {
    let mut parts = vec![format!("**If you approve:** {}", markdown(&p.grant))];
    match &p.action {
        Some(Shown::Command { line }) => parts.push(code_block(&format!("$ {line}"), MAX_COMMAND)),
        Some(Shown::Lines { title, lines }) => {
            let mut s = format!("**{}**", markdown(title));
            for d in lines {
                let _ = write!(s, "\n{}: {}", markdown(&d.label), code(&d.value));
            }
            parts.push(s);
        }
        Some(Shown::Question { .. }) | None => {}
    }
    for note in &p.notes {
        parts.push(format!("⚠️ {}", markdown(note)));
    }
    for c in &p.claims {
        parts.push(format!("**{}** _({})_\n{}", markdown(&c.label), p.claims_note(), code_block(&c.value, MAX_REASON)));
    }
    parts.join("\n")
}

/// Whether [`description`] shows the action and claims without cutting them.
fn shown_in_full(p: &Presentation) -> bool {
    let fits = |s: &str, max: usize| block_text(s).chars().count() <= max;
    let action = match &p.action {
        Some(Shown::Command { line }) => fits(&format!("$ {line}"), MAX_COMMAND),
        Some(Shown::Lines { lines, .. }) => lines.iter().all(|d| d.value.chars().count() <= CODE_MAX),
        Some(Shown::Question { .. }) | None => true,
    };
    action && p.claims.iter().all(|c| fits(&c.value, MAX_REASON))
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
