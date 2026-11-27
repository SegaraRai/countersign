//! Turning an approval or a question into a Slack Block Kit message.
//!
//! Everything the backend, requester or asker supplied is escaped for Slack's
//! `mrkdwn` (`&`, `<`, `>`) and shown inside code spans or code blocks so it
//! cannot render as links, mentions, or formatting.
//!
//! A sensitive approval or a confidential question shows only that it exists,
//! where it came from and its policy, with a link to the web UI. Answers are
//! never shown here, only who answered.

use std::fmt::Write as _;

use serde_json::{Value, json};

use countersign_core::present::{Audience, Presentation, Shown, Tone, When};
use countersign_core::{ApproveMode, ChannelCaps, FieldKind, Item, Notification, Question, Request, Verdict};

use crate::interact::{action_id, answer_action_id, decline_action_id, open_action_id};

/// The parts of a Slack message that reflect a request's current state.
#[derive(Debug, Clone, PartialEq)]
pub struct View {
    /// Plain fallback text (shown in OS/mobile push previews).
    pub text: String,
    /// Single status-coloured attachment carrying the Block Kit blocks.
    pub attachments: Vec<Value>,
}

const PENDING: &str = "#f1c40f";
const GOOD: &str = "#2ecc71";
const DONE: &str = "#1f8b4c";
const BAD: &str = "#e74c3c";
const MUTED: &str = "#95a5a6";
const QUESTION: &str = "#6f42c1";

/// Most options a question can offer as buttons (one actions row, plus Decline).
const MAX_OPTION_BUTTONS: usize = 4;
/// Longest question text and context shown.
const MAX_MESSAGE: usize = 2000;
const MAX_CONTEXT_SHOWN: usize = 2000;
const MAX_DECISIONS: usize = 10;
const MAX_USES: usize = 5;
/// Slack section `mrkdwn` text limit is 3000 characters.
const MAX_SECTION_TEXT: usize = 2900;
const MAX_COMMAND: usize = 2400;
const MAX_REASON: usize = 600;
/// Longest inline code span.
const CODE_MAX: usize = 200;

pub fn view(n: Notification<'_>, caps: ChannelCaps) -> View {
    let web = web_link(n.web_url);
    match n.item {
        Item::Approval(r) => {
            let p = Presentation::approval(r, Audience::Chat);
            let fallback = fallback_text(&p);
            let blocks = if p.withheld { withheld_blocks(r, &p, web) } else { approval_blocks(r, &p, web, caps) };
            View { text: fallback, attachments: vec![json!({ "color": tone_color(p.status.tone), "blocks": blocks })] }
        }
        Item::Question(q) => {
            let p = Presentation::question(q, Audience::Chat);
            let fallback = fallback_text(&p);
            let blocks = question_blocks(q, &p, web, caps);
            View { text: fallback, attachments: vec![json!({ "color": tone_color(p.status.tone), "blocks": blocks })] }
        }
    }
}

fn fallback_text(p: &Presentation) -> String {
    truncate(&plain_text(&format!("{} — {}", p.status.label, p.headline)), 200)
}

fn header_block(p: &Presentation) -> Value {
    // Slack header block text limit is 150 characters, plain_text only.
    let title = truncate(&plain_text(&format!("{} — {}", p.status.label, p.headline)), 148);
    json!({
        "type": "header",
        "text": { "type": "plain_text", "text": title, "emoji": true }
    })
}

fn mrkdwn_section(text: &str) -> Value {
    json!({
        "type": "section",
        "text": { "type": "mrkdwn", "text": truncate(text, MAX_SECTION_TEXT) }
    })
}

fn fields_sections(fields: &[String]) -> Vec<Value> {
    // Slack allows at most 10 fields per section block.
    fields
        .chunks(10)
        .map(|chunk| {
            let list: Vec<Value> =
                chunk.iter().map(|t| json!({ "type": "mrkdwn", "text": truncate(t, 1900) })).collect();
            json!({ "type": "section", "fields": list })
        })
        .collect()
}

fn footer_block(id: impl std::fmt::Display) -> Value {
    json!({
        "type": "context",
        "elements": [{ "type": "mrkdwn", "text": format!("countersign · `{id}`") }]
    })
}

fn withheld_blocks(r: &Request, p: &Presentation, web: Option<&str>) -> Vec<Value> {
    let mut blocks = vec![header_block(p), mrkdwn_section("The details are only in the web UI.")];
    let mut fields: Vec<String> =
        p.facts.iter().map(|d| format!("*{}*\n{}", mrkdwn(&d.label), code(&d.value))).collect();
    append_status_fields(&mut fields, p);
    blocks.extend(fields_sections(&fields));
    if let Some(detail) = &p.status.detail {
        blocks.push(mrkdwn_section(&format!("*Status*\n{}", mrkdwn(detail))));
    }
    if r.state.is_pending()
        && let Some(url) = web
    {
        blocks.push(actions_block(&[link_button("Review in web UI", url, &open_action_id(r.id))]));
    }
    blocks.push(footer_block(r.id));
    blocks
}

fn approval_blocks(r: &Request, p: &Presentation, web: Option<&str>, caps: ChannelCaps) -> Vec<Value> {
    let mut blocks = vec![header_block(p)];
    let complete = shown_in_full(p);

    blocks.push(mrkdwn_section(&format!("*If you approve:* {}", mrkdwn(&p.grant))));

    match &p.action {
        Some(Shown::Command { line }) => {
            blocks.push(mrkdwn_section(&code_block(&format!("$ {line}"), MAX_COMMAND)));
        }
        Some(Shown::Lines { title, lines }) => {
            let mut s = format!("*{}*", mrkdwn(title));
            for d in lines {
                let _ = write!(s, "\n{}: {}", mrkdwn(&d.label), code(&d.value));
            }
            blocks.push(mrkdwn_section(&s));
        }
        Some(Shown::Question { .. }) | None => {}
    }

    for note in &p.notes {
        blocks.push(mrkdwn_section(&format!(":warning: {}", mrkdwn(note))));
    }

    for c in &p.claims {
        blocks.push(mrkdwn_section(&format!(
            "*{}* _({})_\n{}",
            mrkdwn(&c.label),
            mrkdwn(p.claims_note()),
            code_block(&c.value, MAX_REASON)
        )));
    }

    let mut fields: Vec<String> =
        p.facts.iter().map(|d| format!("*{}*\n{}", mrkdwn(&d.label), code(&d.value))).collect();
    append_status_fields(&mut fields, p);
    if !fields.is_empty() {
        blocks.extend(fields_sections(&fields));
    }
    if let Some(detail) = &p.status.detail {
        blocks.push(mrkdwn_section(&format!("*Status*\n{}", mrkdwn(detail))));
    }

    if !p.status.decisions.is_empty() {
        let mut lines = String::from("*Decisions*\n");
        for d in p.status.decisions.iter().take(MAX_DECISIONS) {
            let mark = if d.approved { ":white_check_mark:" } else { ":no_entry:" };
            let _ = writeln!(lines, "{mark} {} via {} ({})", code(&d.who), code(&d.via), d.assurance);
        }
        if p.status.decisions.len() > MAX_DECISIONS {
            let _ = writeln!(lines, "… and {} more", p.status.decisions.len() - MAX_DECISIONS);
        }
        blocks.push(mrkdwn_section(&lines));
    }

    if !p.status.uses.is_empty() {
        let mut lines = String::from("*Used for*\n");
        let skipped = p.status.uses.len().saturating_sub(MAX_USES);
        if skipped > 0 {
            let _ = writeln!(lines, "… {skipped} earlier");
        }
        for u in p.status.uses.iter().skip(skipped) {
            let _ = writeln!(lines, "{} {}", slack_time(u.at.as_second()), code(&u.what));
        }
        blocks.push(mrkdwn_section(&lines));
    }

    let buttons = approval_buttons(r, web, caps, complete);
    if !buttons.is_empty() {
        blocks.push(actions_block(&buttons));
    }

    blocks.push(footer_block(r.id));
    blocks
}

fn append_status_fields(fields: &mut Vec<String>, p: &Presentation) {
    if let Some(needs) = &p.status.needs {
        fields.push(format!("*Needs*\n{}", mrkdwn(needs)));
    }
    if let Some(When { label, at }) = p.status.time {
        fields.push(format!("*{label}*\n{}", slack_date(at.as_second())));
    }
}

fn approval_buttons(r: &Request, web: Option<&str>, caps: ChannelCaps, complete: bool) -> Vec<Value> {
    let mut buttons = Vec::new();
    let mode = match ApproveMode::for_request(caps, r) {
        ApproveMode::Direct if !complete => ApproveMode::WebLink,
        mode => mode,
    };
    match mode {
        ApproveMode::Direct => {
            buttons.push(verdict_button(r, Verdict::Approve));
            buttons.push(verdict_button(r, Verdict::Deny));
            if let Some(url) = web {
                buttons.push(link_button("Details", url, &open_action_id(r.id)));
            }
        }
        ApproveMode::WebLink => {
            if let Some(url) = web {
                buttons.push(link_button("Approve in web UI", url, &open_action_id(r.id)));
            }
            if caps.interactive {
                buttons.push(verdict_button(r, Verdict::Deny));
            }
        }
        ApproveMode::None => {}
    }
    buttons
}

fn question_blocks(q: &Question, p: &Presentation, web: Option<&str>, caps: ChannelCaps) -> Vec<Value> {
    let item = Item::Question(q);
    let mut blocks = vec![header_block(p)];
    let mut complete = true;

    if q.question_confidential() {
        blocks.push(mrkdwn_section(&format!(
            "{}\nConfidential: read and answer it in the web UI.",
            code(&item.safe_title())
        )));
        complete = false;
    } else if !q.message.is_empty() {
        complete &= block_text(&q.message).chars().count() <= MAX_MESSAGE;
        blocks.push(mrkdwn_section(&code_block(&q.message, MAX_MESSAGE)));
    }

    let mut fields = Vec::new();
    let mut asker = code(q.asker.client.as_str());
    if let Some(a) = &q.asker.actor {
        let _ = write!(asker, " for {}", code(a.as_str()));
    }
    fields.push(format!("*From*\n{asker}"));
    fields.push(format!("*Policy*\n{}", code(item.policy())));

    if !q.question_confidential() {
        let mut shown = 0;
        for (k, v) in &q.context {
            shown += k.chars().count() + v.chars().count();
            if shown > MAX_CONTEXT_SHOWN {
                complete = false;
                fields.push("*…*\nMore context in the web UI.".to_owned());
                break;
            }
            complete &= block_text(v).chars().count() <= CODE_MAX;
            fields.push(format!("*{}*\n{}", mrkdwn(&clean_name(k)), code(v)));
        }
    }

    if q.is_pending() {
        fields.push(format!("*Answer by*\n{}", slack_date(q.pending_until.as_second())));
    } else if let Some(result) = Item::question_result(q) {
        fields.push(format!("*Result*\n{}", mrkdwn(&result)));
    }
    blocks.extend(fields_sections(&fields));

    let buttons = question_buttons(q, web, caps, complete);
    if !buttons.is_empty() {
        blocks.push(actions_block(&buttons));
    }

    blocks.push(footer_block(q.id));
    blocks
}

fn answer_buttons(q: &Question, caps: ChannelCaps, complete: bool) -> Option<Vec<Value>> {
    if !caps.interactive || !complete || q.confidentiality.question || q.confidentiality.answer_may_be {
        return None;
    }
    if caps.max_assurance.is_none_or(|max| max < q.required_assurance()) {
        return None;
    }
    let form = q.form().ok()?;
    let f = form.single_button_field()?;
    let options: Vec<(String, Value)> = match &f.kind {
        FieldKind::Boolean { .. } => vec![("Yes".to_owned(), Value::Bool(true)), ("No".to_owned(), Value::Bool(false))],
        FieldKind::Choice { options, .. } if options.len() <= MAX_OPTION_BUTTONS => {
            options.iter().map(|o| (o.label().to_owned(), Value::String(o.value.clone()))).collect()
        }
        _ => return None,
    };
    let mut buttons = Vec::new();
    for (idx, (label, value)) in options.into_iter().enumerate() {
        let mut map = serde_json::Map::new();
        map.insert(f.name.clone(), value);
        let payload = Value::Object(map).to_string();
        if payload.len() > 1900 {
            return None;
        }
        buttons.push(json!({
            "type": "button",
            "text": { "type": "plain_text", "text": truncate(&clean_name(&label), 72), "emoji": true },
            "style": "primary",
            "action_id": answer_action_id(q.id, idx),
            "value": payload,
        }));
    }
    Some(buttons)
}

fn question_buttons(q: &Question, web: Option<&str>, caps: ChannelCaps, complete: bool) -> Vec<Value> {
    if !q.is_pending() {
        return Vec::new();
    }
    let mut buttons = match answer_buttons(q, caps, complete) {
        Some(b) => b,
        None => web.map_or_default(|url| vec![link_button("Answer in web UI", url, &open_action_id(q.id))]),
    };
    if caps.interactive && !q.confidentiality.question {
        buttons.push(json!({
            "type": "button",
            "text": { "type": "plain_text", "text": "Decline", "emoji": true },
            "style": "danger",
            "action_id": decline_action_id(q.id),
            "value": q.id.to_string(),
        }));
    }
    buttons
}

fn verdict_button(r: &Request, verdict: Verdict) -> Value {
    let (label, style) = match verdict {
        Verdict::Approve => ("Approve", "primary"),
        Verdict::Deny => ("Deny", "danger"),
    };
    json!({
        "type": "button",
        "text": { "type": "plain_text", "text": label, "emoji": true },
        "style": style,
        "action_id": action_id(verdict, r.id),
        "value": r.id.to_string(),
    })
}

fn link_button(label: &str, url: &str, id: &str) -> Value {
    json!({
        "type": "button",
        "text": { "type": "plain_text", "text": label, "emoji": true },
        "url": url,
        "action_id": id,
    })
}

fn actions_block(elements: &[Value]) -> Value {
    json!({ "type": "actions", "elements": elements })
}

fn web_link(url: &str) -> Option<&str> {
    (url.starts_with("https://") || url.starts_with("http://")).then_some(url)
}

fn slack_date(unix: i64) -> String {
    format!("<!date^{unix}^{{date_short_pretty}} {{time}}|{unix}>")
}

fn slack_time(unix: i64) -> String {
    format!("<!date^{unix}^{{time}}|{unix}>")
}

pub(crate) fn tone_color(tone: Tone) -> &'static str {
    match tone {
        Tone::Waiting => PENDING,
        Tone::Asking => QUESTION,
        Tone::Good => GOOD,
        Tone::Done => DONE,
        Tone::Bad => BAD,
        Tone::Muted => MUTED,
    }
}

/// Plain text for Slack `plain_text` fields (no control/hidden chars).
fn plain_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() {
            out.push(' ');
        } else if countersign_core::text::is_hidden(c) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// Escape `&`, `<`, `>` for Slack `mrkdwn` (required everywhere in `mrkdwn`
/// so untrusted text cannot inject mentions or links).
fn escape_slack_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

/// Escape untrusted prose for Slack `mrkdwn`, keeping backtick code spans
/// written by countersign itself intact (still entity-escaped).
pub(crate) fn mrkdwn(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for (i, part) in s.split('`').enumerate() {
        if i > 0 {
            out.push('`');
        }
        if i % 2 == 1 {
            out.push_str(&escape_slack_entities(part));
            continue;
        }
        for c in part.chars() {
            match c {
                '&' => out.push_str("&amp;"),
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                c if c.is_control() => out.push(' '),
                c if countersign_core::text::is_hidden(c) => out.extend(c.escape_default()),
                c => out.push(c),
            }
        }
    }
    out
}

/// Untrusted text as an inline code span, on one line.
pub(crate) fn code(s: &str) -> String {
    let mut cleaned = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '`' => cleaned.push('ˋ'),
            '&' => cleaned.push_str("&amp;"),
            '<' => cleaned.push_str("&lt;"),
            '>' => cleaned.push_str("&gt;"),
            c if c.is_control() => cleaned.push(' '),
            c if countersign_core::text::is_hidden(c) => cleaned.extend(c.escape_default()),
            c => cleaned.push(c),
        }
    }
    let cleaned = truncate(cleaned.trim(), CODE_MAX);
    if cleaned.is_empty() { "—".to_owned() } else { format!("`{cleaned}`") }
}

fn clean_name(s: &str) -> String {
    let cleaned: String =
        s.chars()
            .map(|c| {
                if c.is_control() || countersign_core::text::is_hidden(c) || "*_~|`>#[]<>".contains(c) {
                    ' '
                } else {
                    c
                }
            })
            .collect();
    let t = truncate(cleaned.trim(), 60);
    if t.is_empty() { "—".to_owned() } else { t }
}

fn shown_in_full(p: &Presentation) -> bool {
    let fits = |s: &str, max: usize| block_text(s).chars().count() <= max;
    let action = match &p.action {
        Some(Shown::Command { line }) => fits(&format!("$ {line}"), MAX_COMMAND),
        Some(Shown::Lines { lines, .. }) => lines.iter().all(|d| d.value.chars().count() <= CODE_MAX),
        Some(Shown::Question { .. }) | None => true,
    };
    action && p.claims.iter().all(|c| fits(&c.value, MAX_REASON))
}

fn block_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.trim().chars() {
        match c {
            '`' => out.push('ˋ'),
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\n' => out.push(c),
            c if countersign_core::text::is_hidden(c) => out.extend(c.escape_default()),
            c => out.push(c),
        }
    }
    out
}

pub(crate) fn code_block(s: &str, max: usize) -> String {
    format!("```\n{}\n```", truncate(&block_text(s), max))
}

fn truncate(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        Some((i, _)) => format!("{}…", &s[..i]),
        None => s.to_owned(),
    }
}
