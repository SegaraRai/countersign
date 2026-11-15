//! Turning a request into a Discord message (embed + buttons).
//!
//! Everything the backend or requester supplied is shown inside code spans or
//! blocks so it cannot render as links, mentions, or formatting; mentions are
//! additionally suppressed through `allowed_mentions` when sending.

use std::fmt::Write as _;
use std::time::Duration;

use countersign_core::{ApproveMode, ChannelCaps, GrantMode, Notification, Request, RequestState, Verdict};
use twilight_model::channel::message::Component;
use twilight_model::channel::message::component::{ActionRow, Button, ButtonStyle};
use twilight_model::channel::message::embed::{Embed, EmbedField, EmbedFooter};

use crate::interact::custom_id;

/// The parts of a message that reflect a request's current state.
#[derive(Debug, Clone, PartialEq)]
pub struct View {
    pub embeds: Vec<Embed>,
    pub components: Vec<Component>,
}

const PENDING: u32 = 0x00f1_c40f;
const GOOD: u32 = 0x002e_cc71;
const BAD: u32 = 0x00e7_4c3c;
const MUTED: u32 = 0x0095_a5a6;
const MAX_DECISIONS: usize = 10;

pub fn view(n: Notification<'_>, caps: ChannelCaps) -> View {
    View { embeds: vec![embed(n)], components: components(n, caps) }
}

fn embed(n: Notification<'_>) -> Embed {
    let r = n.request;
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

    Embed {
        author: None,
        color: Some(color(&r.state)),
        description: description(facts),
        fields,
        flags: None,
        footer: Some(EmbedFooter { icon_url: None, proxy_icon_url: None, text: format!("countersign · {}", r.id) }),
        image: None,
        kind: "rich".to_owned(),
        provider: None,
        thumbnail: None,
        timestamp: None,
        title: Some(format!("Access request — {}", r.state.name())),
        url: web_link(n.web_url).map(str::to_owned),
        video: None,
    }
}

fn components(n: Notification<'_>, caps: ChannelCaps) -> Vec<Component> {
    let r = n.request;
    let web = web_link(n.web_url);
    let mut buttons = Vec::new();
    match ApproveMode::for_request(caps, r) {
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
    if buttons.is_empty() {
        return Vec::new();
    }
    vec![Component::ActionRow(ActionRow { components: buttons, id: None })]
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

fn color(state: &RequestState) -> u32 {
    match state {
        RequestState::Pending => PENDING,
        RequestState::Approved | RequestState::Active { .. } => GOOD,
        RequestState::Denied | RequestState::Failed { .. } | RequestState::Revoked => BAD,
        RequestState::Expired | RequestState::Withdrawn | RequestState::Ended => MUTED,
    }
}

/// Untrusted text as an inline code span, on one line.
pub(crate) fn code(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c == '`' {
                'ˋ'
            } else if c.is_control() {
                ' '
            } else {
                c
            }
        })
        .collect();
    let cleaned = truncate(cleaned.trim(), 200);
    if cleaned.is_empty() { "—".to_owned() } else { format!("`{cleaned}`") }
}

/// Untrusted multi-line text as a code block.
/// The command (if the backend reports one) and the requester's reason.
fn description(facts: &countersign_core::SubjectFacts) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(command) = facts.attributes.get("command") {
        parts.push(format!("**Command**\n{}", code_block(command)));
    }
    if let Some(reason) = &facts.reason {
        parts.push(format!("**Reason**\n{}", code_block(reason)));
    }
    (!parts.is_empty()).then(|| parts.join("\n"))
}

pub(crate) fn code_block(s: &str) -> String {
    let cleaned = s.replace('`', "ˋ");
    format!("```\n{}\n```", truncate(cleaned.trim(), 1000))
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
