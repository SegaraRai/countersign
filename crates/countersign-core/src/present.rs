//! How approvals and questions are shown to people, on every surface.
//!
//! A [`Presentation`] is built from a stored [`Request`] or [`Question`]
//! for an [`Audience`]. Channels, the web UI and the CLI only lay it out:
//! the wording, the order of facts, the escaping of untrusted text and what
//! is withheld from chat are decided here, once.
//!
//! - Untrusted single-line values go through [`text::escape`], multi-line
//!   text through [`text::escape_lines`], command lines through
//!   [`text::shell_join`]. Renderers add only their own syntax escaping
//!   (Discord markdown, HTML).
//! - A presentation built for [`Audience::Chat`] of a sensitive approval or a
//!   confidential question is *withheld*: it has no action, facts beyond
//!   origin and policy, claims or audit, so a renderer cannot leak what it
//!   never receives.
//! - Answers to questions are never part of a presentation; the web UI shows
//!   them to the asker's responders itself.

use std::fmt::Write as _;
use std::time::Duration;

use jiff::Timestamp;
use serde::Serialize;

use crate::channel::Item;
use crate::form::{FieldKind, TextFormat};
use crate::policy::{Exclusion, GrantMode};
use crate::question::{Question, QuestionOutcome};
use crate::request::{Request, RequestState, Verdict};
use crate::subject::{Action, Detail, Source};
use crate::text;

/// Who will see the presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Audience {
    /// Chat channels and webhooks: sensitive and confidential items are
    /// withheld.
    Chat,
    /// Signed-in approvers and operators (web UI, CLI): everything.
    Full,
}

/// An approval or question, ready to lay out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Presentation {
    /// `approval` or `question`.
    pub kind: &'static str,
    /// One line saying who wants what, where.
    pub headline: String,
    /// Only the headline, facts (origin and policy) and status are present.
    pub withheld: bool,
    /// What approving allows, in words. Leads every layout.
    pub grant: String,
    /// What the request is about.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<Shown>,
    /// Facts the source vouches for: host, run as, directory, ...
    pub facts: Vec<Detail>,
    /// Text the requester or asker wrote; unverified.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<Detail>,
    /// Remarks from countersign (e.g. why a command-specific policy did not
    /// apply).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    pub status: Status,
    /// Identifiers, identities and the policy match, for audit; shown folded
    /// or on request.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub audit: Vec<Detail>,
}

/// Label renderers put next to [`Presentation::claims`].
pub const CLAIMS_NOTE: &str = "from the requester, unverified";
/// Label renderers put next to the claims of a question.
pub const QUESTION_CLAIMS_NOTE: &str = "from the asker, unverified";

/// What the request is about, as shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Shown {
    /// A command line, shell-quoted, exactly as it will run.
    Command { line: String },
    /// A session or another backend's subject: a title and labelled lines.
    Lines { title: String, lines: Vec<Detail> },
    /// A question's text and a summary of its form.
    Question { message: String, fields: Vec<Detail> },
}

impl Shown {
    /// The first line, for lists.
    pub fn summary(&self) -> String {
        let first = match self {
            Self::Command { line } => line.as_str(),
            Self::Lines { title, .. } => title.as_str(),
            Self::Question { message, .. } => message.as_str(),
        };
        first.lines().next().unwrap_or_default().to_owned()
    }
}

/// How the item stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Status {
    /// The machine state (`pending`, `active`, `answered`, ...).
    pub state: &'static str,
    /// The state in words: "Waiting for approval", "Approved, used", ...
    pub label: String,
    /// One more line, without times: "by alice via discord", ...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The time that matters now ("Decide by", "Active until", "Ran at").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<When>,
    /// What deciding takes: "1 approval at linked".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs: Option<String>,
    pub tone: Tone,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub decisions: Vec<DecisionLine>,
    /// Later subjects covered by an approved window.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub uses: Vec<UseLine>,
}

/// A labelled instant; renderers format it for their surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct When {
    pub label: &'static str,
    pub at: Timestamp,
}

/// The broad colour of a state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tone {
    /// An approval waiting for a decision.
    Waiting,
    /// A question waiting for an answer.
    Asking,
    /// Approved and in effect.
    Good,
    /// Approved or answered, and finished.
    Done,
    /// Denied, declined, revoked or failed.
    Bad,
    /// Nobody decided, or the requester gave up.
    Muted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionLine {
    pub who: String,
    pub approved: bool,
    pub via: String,
    pub assurance: String,
    pub at: Timestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl DecisionLine {
    /// `Approved` or `Denied`.
    pub fn verdict(&self) -> &'static str {
        if self.approved { "Approved" } else { "Denied" }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UseLine {
    pub at: Timestamp,
    /// The command line or another one-line description.
    pub what: String,
}

impl Presentation {
    /// An approval request, for `audience`.
    pub fn approval(r: &Request, audience: Audience) -> Self {
        let withheld = audience == Audience::Chat && r.sensitive;
        let status = approval_status(r, withheld);
        if withheld {
            let item = Item::Approval(r);
            return Self {
                kind: "approval",
                headline: item.safe_title(),
                withheld,
                grant: "Details only in the web UI".to_owned(),
                action: None,
                facts: vec![
                    Detail::new("From", text::escape(&item.origin())),
                    Detail::new("Policy", text::escape(item.policy())),
                ],
                claims: Vec::new(),
                notes: Vec::new(),
                status,
                audit: Vec::new(),
            };
        }

        let facts = &r.facts;
        let who = requester_name(r);
        let target = facts.target.as_deref().map(text::escape);
        let host_request = matches!(facts.source, Some(Source::Client(_)));
        let mut details = Vec::new();
        let mut notes = Vec::new();
        let (headline, action) = match &facts.action {
            Some(Action::Command { line, runas, cwd, notes: n }) => {
                let runas = text::escape(runas);
                if let Some(t) = &target {
                    details.push(Detail::new(if host_request { "Host" } else { "Target" }, t.clone()));
                }
                details.push(Detail::new("Run as", runas.clone()));
                if let Some(cwd) = cwd {
                    details.push(Detail::new("Directory", text::escape(cwd)));
                }
                notes.extend(n.iter().map(|n| text::escape(n)));
                let place = target.as_ref().map_or_default(|t| format!(" on {t}"));
                (format!("{who} wants {runas}{place}"), Some(Shown::Command { line: text::shell_join(line) }))
            }
            Some(Action::Session { kind, device, client, credential, browser }) => {
                if let Some(t) = &target {
                    details.push(Detail::new("Target", t.clone()));
                }
                let mut lines = Vec::new();
                let mut put = |label: &str, v: &Option<String>| {
                    if let Some(v) = v {
                        lines.push(Detail::new(label, text::escape(v)));
                    }
                };
                put("Type", kind);
                put("Device", device);
                put("Client", client);
                put("Credential", credential);
                if *browser {
                    lines.push(Detail::new("Browser", "yes"));
                }
                let backend = text::escape(r.subject.backend.as_str());
                let place = target.as_ref().map_or_default(|t| format!(" to {t}"));
                (
                    format!("{who} wants a session{place}"),
                    Some(Shown::Lines { title: format!("Session on {backend}"), lines }),
                )
            }
            Some(Action::Generic { title, lines }) => {
                if let Some(t) = &target {
                    details.push(Detail::new("Target", t.clone()));
                }
                let title = text::escape(title);
                let lines = lines.iter().map(|d| Detail::new(text::escape(&d.label), text::escape(&d.value))).collect();
                (format!("{who} requests {title}"), Some(Shown::Lines { title, lines }))
            }
            None => {
                if let Some(t) = &target {
                    details.push(Detail::new("Target", t.clone()));
                }
                let place = target.as_ref().map_or_default(|t| format!(" to {t}"));
                (format!("{who} wants access{place}"), None)
            }
        };
        if let Some(i) = &facts.initiator {
            let name = i.display_name.as_deref().unwrap_or(&i.identity);
            details.push(Detail::new("On behalf of", text::escape(name)));
        }
        let claims =
            facts.reason.iter().map(|reason| Detail::new("Reason", text::escape_lines(reason.trim()))).collect();

        Self {
            kind: "approval",
            headline,
            withheld,
            grant: grant(r, &who, target.as_deref()),
            action,
            facts: details,
            claims,
            notes,
            status,
            audit: if audience == Audience::Full { approval_audit(r) } else { Vec::new() },
        }
    }

    /// A question, for `audience`.
    pub fn question(q: &Question, audience: Audience) -> Self {
        let withheld = audience == Audience::Chat && q.question_confidential();
        let item = Item::Question(q);
        let status = question_status(q);
        let mut facts = vec![Detail::new("Asked by", asker_name(q))];
        if withheld {
            facts.push(Detail::new("Policy", text::escape(item.policy())));
            return Self {
                kind: "question",
                headline: item.safe_title(),
                withheld,
                grant: GRANT_QUESTION.to_owned(),
                action: None,
                facts,
                claims: Vec::new(),
                notes: vec!["Confidential: read and answer it in the web UI.".to_owned()],
                status,
                audit: Vec::new(),
            };
        }
        let action = (!q.message.is_empty() || !q.content_removed)
            .then(|| Shown::Question { message: text::escape_lines(q.message.trim()), fields: form_summary(q) });
        let claims = q.context.iter().map(|(k, v)| Detail::new(text::escape(k), text::escape_lines(v))).collect();
        let mut audit = Vec::new();
        if audience == Audience::Full {
            audit.push(Detail::new("Question", q.id.to_string()));
            audit.push(Detail::new("Client", text::escape(q.asker.client.as_str())));
            if let Some(a) = &q.asker.actor {
                audit.push(Detail::new("On behalf of", text::escape(a.as_str())));
            }
            audit.push(Detail::new("Policy", text::escape(q.requirements.policy.as_str())));
            let mut rules = format!(
                "answer at {} within {}",
                q.requirements.min_assurance,
                duration_words(q.requirements.answer_timeout)
            );
            if q.question_confidential() {
                rules.push_str(" · confidential");
            } else if q.confidentiality.answer_may_be {
                rules.push_str(" · the answer may be confidential");
            }
            audit.push(Detail::new("Rules", rules));
            audit.push(Detail::new("Asked at", q.created_at.to_string()));
        }
        Self {
            kind: "question",
            headline: format!("{} asks a question", asker_name(q)),
            withheld,
            grant: GRANT_QUESTION.to_owned(),
            action,
            facts,
            claims,
            notes: Vec::new(),
            status,
            audit,
        }
    }

    /// The presentation of a notification's item.
    pub fn of(item: Item<'_>, audience: Audience) -> Self {
        match item {
            Item::Approval(r) => Self::approval(r, audience),
            Item::Question(q) => Self::question(q, audience),
        }
    }

    /// `label: value` of the first fact with `label`.
    pub fn fact(&self, label: &str) -> Option<&str> {
        self.facts.iter().find(|d| d.label == label).map(|d| d.value.as_str())
    }

    /// The claims' note: from the requester or from the asker.
    pub fn claims_note(&self) -> &'static str {
        if self.kind == "question" { QUESTION_CLAIMS_NOTE } else { CLAIMS_NOTE }
    }
}

const GRANT_QUESTION: &str = "Answering grants nothing; the answer goes back to the asker";

/// The requester as approvers know them: the actor, else the name the source
/// gave.
fn requester_name(r: &Request) -> String {
    let req = &r.facts.requester;
    let name = req.actor.as_ref().map_or(req.id.as_str(), |a| a.as_str());
    if name.is_empty() { "Someone".to_owned() } else { text::escape(name) }
}

fn asker_name(q: &Question) -> String {
    match &q.asker.actor {
        Some(a) if a.as_str() != q.asker.client.as_str() => {
            format!("{} (via {})", text::escape(a.as_str()), text::escape(q.asker.client.as_str()))
        }
        _ => text::escape(q.asker.client.as_str()),
    }
}

/// What approving allows, in one sentence.
fn grant(r: &Request, who: &str, target: Option<&str>) -> String {
    let d = duration_words(r.requirements.ttl);
    let scope = &r.requirements.scope;
    let glob = |k: &str| scope.get(k).map(|v| format!("`{}`", text::escape(v)));
    match (&r.facts.action, r.requirements.grant) {
        (Some(Action::Command { runas, .. }), GrantMode::Once) => {
            format!("Runs this command once, as {}, within {d}", text::escape(runas))
        }
        (Some(Action::Command { .. }), GrantMode::Window) => {
            let commands =
                glob("command").map_or_else(|| "any command".to_owned(), |g| format!("commands matching {g}"));
            let runas = glob("runas").map_or_else(|| "as any user".to_owned(), |g| format!("as {g}"));
            let mut more = String::new();
            for (k, v) in scope.iter().filter(|(k, _)| !matches!(k.as_str(), "command" | "runas" | "host" | "user")) {
                let _ = write!(more, ", with {} `{}`", text::escape(k), text::escape(v));
            }
            let place = target.map_or_default(|t| format!(", on {t}"));
            format!("Allows {who} to run {commands}, {runas}{more}{place}, for {d}")
        }
        (Some(Action::Session { .. }), GrantMode::Once) => format!("Lets this session through for up to {d}"),
        (_, GrantMode::Once) => format!("Grants this access for up to {d}"),
        (_, GrantMode::Window) => {
            let mut matching = String::new();
            for (k, v) in scope {
                let _ = write!(
                    matching,
                    "{} {} `{}`",
                    if matching.is_empty() { " with" } else { "," },
                    text::escape(k),
                    text::escape(v)
                );
            }
            let place = target.map_or_default(|t| format!(" for {t}"));
            format!("Allows further requests from {who}{place}{matching} for {d}")
        }
    }
}

fn approval_status(r: &Request, withheld: bool) -> Status {
    let window = r.requirements.grant == GrantMode::Window;
    let command = matches!(r.facts.action, Some(Action::Command { .. }));
    let first_deny = r.decisions.iter().find(|d| d.verdict == Verdict::Deny);
    let by = |d: &crate::request::Decision| {
        format!("by {} via {}", text::escape(d.approver.as_str()), text::escape(d.via.as_str()))
    };
    let at = |label, at| Some(When { label, at });
    let use_count = r.uses.len();
    let used = |noun: &str| match use_count {
        0 => format!("No other {noun} used it"),
        1 => format!("1 more {noun} used it"),
        n => format!("{n} more {noun}s used it"),
    };
    let noun = if command { "command" } else { "request" };
    let (label, detail, time, tone): (&str, Option<String>, Option<When>, Tone) = match &r.state {
        RequestState::Pending => ("Waiting for approval", None, at("Decide by", r.pending_until), Tone::Waiting),
        RequestState::Approved => ("Approved", Some("Being applied".to_owned()), None, Tone::Good),
        RequestState::Active { until } if window => {
            ("Approved", Some(format!("Window open · {}", used(noun))), at("Active until", *until), Tone::Good)
        }
        RequestState::Active { until } if command => {
            ("Approved", Some("Ready to run once".to_owned()), at("Use by", *until), Tone::Good)
        }
        RequestState::Active { until } => ("Approved", None, at("Active until", *until), Tone::Good),
        RequestState::Ended if window => {
            ("Approved, window closed", Some(used(noun)), at("Closed at", r.updated_at), Tone::Done)
        }
        RequestState::Ended if command => match r.collected_at {
            Some(t) => ("Approved, used", None, at("Ran at", t), Tone::Done),
            None => ("Approved, not used", Some("It was not picked up in time".to_owned()), None, Tone::Muted),
        },
        RequestState::Ended => ("Approved, ended", None, at("Ended at", r.updated_at), Tone::Done),
        RequestState::Denied => {
            ("Denied", first_deny.map(by), first_deny.and_then(|d| at("Denied at", d.at)), Tone::Bad)
        }
        RequestState::Expired => ("No decision", Some("Nobody decided in time".to_owned()), None, Tone::Muted),
        RequestState::Withdrawn => ("Withdrawn", Some("The requester gave up".to_owned()), None, Tone::Muted),
        RequestState::Revoked => ("Revoked", None, at("Revoked at", r.updated_at), Tone::Bad),
        RequestState::Failed { error } => (
            "Failed",
            Some(format!("countersign could not apply the decision: {}", text::escape(error))),
            None,
            Tone::Bad,
        ),
    };
    let reqs = &r.requirements;
    let plural = if reqs.quorum == 1 { "" } else { "s" };
    let mut needs = format!("{} approval{plural} at {}", reqs.quorum, reqs.min_assurance);
    let approvals = r.approvals().len();
    if r.state.is_pending() && approvals > 0 {
        let _ = write!(needs, " · {approvals} so far");
    }
    Status {
        state: r.state.name(),
        label: label.to_owned(),
        detail,
        time,
        needs: Some(needs),
        tone,
        decisions: r
            .decisions
            .iter()
            .map(|d| DecisionLine {
                who: text::escape(d.approver.as_str()),
                approved: d.verdict == Verdict::Approve,
                via: text::escape(d.via.as_str()),
                assurance: d.assurance.to_string(),
                at: d.at,
                comment: d.comment.as_deref().filter(|_| !withheld).map(text::escape_lines),
            })
            .collect(),
        uses: if withheld {
            Vec::new()
        } else {
            r.uses
                .iter()
                .map(|u| UseLine {
                    at: u.at,
                    what: match &u.action {
                        Some(Action::Command { line, .. }) => text::shell_join(line),
                        Some(Action::Generic { title, .. }) => text::escape(title),
                        _ => text::escape(u.attributes.get("command").map_or(u.subject.id.as_str(), String::as_str)),
                    },
                })
                .collect()
        },
    }
}

fn approval_audit(r: &Request) -> Vec<Detail> {
    let facts = &r.facts;
    let req = &facts.requester;
    let reqs = &r.requirements;
    let mut a = vec![
        Detail::new("Request", r.id.to_string()),
        Detail::new("Subject", text::escape(&format!("{}/{}/{}", r.subject.backend, r.subject.kind, r.subject.id))),
    ];
    if let Some(s) = &facts.source {
        a.push(Detail::new("Source", text::escape(&s.to_string())));
    }
    let mut requester = text::escape(&req.id);
    if let Some(name) = &req.display_name {
        let _ = write!(requester, " ({})", text::escape(name));
    }
    a.push(Detail::new("Requester", requester));
    if !req.identity.is_empty() {
        a.push(Detail::new("Identity", text::escape(&req.identity)));
    }
    if let Some(actor) = &req.actor {
        a.push(Detail::new("Actor", text::escape(actor.as_str())));
    }
    if !req.groups.is_empty() {
        let groups: Vec<String> = req.groups.iter().map(|g| text::escape(g)).collect();
        a.push(Detail::new("Source groups", groups.join(", ")));
    }
    if let Some(i) = &facts.initiator {
        let mut s = text::escape(&i.identity);
        if let Some(actor) = &i.actor {
            let _ = write!(s, " ({})", text::escape(actor.as_str()));
        }
        a.push(Detail::new("Initiator", s));
    }
    a.push(Detail::new("Policy", text::escape(reqs.policy.as_str())));
    let mut rules = format!(
        "{} for {} · {} approval{} at {}",
        reqs.grant.as_str(),
        duration_words(reqs.ttl),
        reqs.quorum,
        if reqs.quorum == 1 { "" } else { "s" },
        reqs.min_assurance
    );
    if !reqs.exclude.is_empty() {
        let names: Vec<&str> = reqs
            .exclude
            .iter()
            .map(|e| match e {
                Exclusion::Requester => "requester",
                Exclusion::Owners => "owners",
                Exclusion::Initiator => "initiator",
            })
            .collect();
        let _ = write!(rules, " · excluding {}", names.join(", "));
    }
    a.push(Detail::new("Rules", rules));
    for (k, v) in &reqs.scope {
        a.push(Detail::new("Matched", format!("{} `{}`", text::escape(k), text::escape(v))));
    }
    for (k, v) in &facts.attributes {
        a.push(Detail::new(format!("Attribute {}", text::escape(k)), text::escape(v)));
    }
    if let Some(t) = facts.requested_ttl {
        a.push(Detail::new("Asked for", duration_words(t)));
    }
    if let Some(b) = &facts.binding {
        a.push(Detail::new("Bound to", text::escape(b)));
    }
    a.push(Detail::new("Requested at", r.created_at.to_string()));
    a
}

fn question_status(q: &Question) -> Status {
    let by = |by: &crate::id::ActorId, via: &crate::id::ChannelName| {
        format!("by {} via {}", text::escape(by.as_str()), text::escape(via.as_str()))
    };
    let (label, detail, time, tone) = match &q.outcome {
        None => ("Waiting for an answer", None, Some(When { label: "Answer by", at: q.pending_until }), Tone::Asking),
        Some(QuestionOutcome::Accepted { by: who, via, at, confidential, .. }) => {
            let mut d = by(who, via);
            if *confidential {
                d.push_str(" (confidential)");
            }
            ("Answered", Some(d), Some(When { label: "Answered at", at: *at }), Tone::Done)
        }
        Some(QuestionOutcome::Declined { by: who, via, at, .. }) => {
            ("Declined", Some(by(who, via)), Some(When { label: "Declined at", at: *at }), Tone::Bad)
        }
        Some(QuestionOutcome::Expired { .. }) => {
            ("No answer", Some("Nobody answered in time".to_owned()), None, Tone::Muted)
        }
        Some(QuestionOutcome::Withdrawn { .. }) => {
            ("Withdrawn", Some("The asker gave up".to_owned()), None, Tone::Muted)
        }
    };
    Status {
        state: q.state(),
        label: label.to_owned(),
        detail,
        time,
        needs: Some(format!("1 answer at {}", q.required_assurance())),
        tone,
        decisions: Vec::new(),
        uses: Vec::new(),
    }
}

/// One line per form field: its label and what it accepts.
fn form_summary(q: &Question) -> Vec<Detail> {
    let Ok(form) = q.form() else { return Vec::new() };
    let labels =
        |opts: &[crate::form::Choice]| opts.iter().map(|o| text::escape(o.label())).collect::<Vec<_>>().join(", ");
    form.fields
        .iter()
        .map(|f| {
            let what = match &f.kind {
                FieldKind::Boolean { .. } => "yes or no".to_owned(),
                FieldKind::Choice { options, .. } => format!("one of: {}", labels(options)),
                FieldKind::Choices { options, .. } => format!("any of: {}", labels(options)),
                FieldKind::Number { integer: true, .. } => "a whole number".to_owned(),
                FieldKind::Number { .. } => "a number".to_owned(),
                FieldKind::Text { format: Some(TextFormat::Email), .. } => "an email address".to_owned(),
                FieldKind::Text { format: Some(f), .. } => format!("text ({})", f.as_str()),
                FieldKind::Text { .. } => "text".to_owned(),
            };
            let optional = if f.required { "" } else { " (optional)" };
            Detail::new(text::escape(f.label()), format!("{what}{optional}"))
        })
        .collect()
}

/// A duration in words: `45 seconds`, `1 minute`, `1 hour 30 minutes`.
pub fn duration_words(d: Duration) -> String {
    let secs = d.as_secs();
    let unit = |n: u64, one: &str| if n == 1 { format!("1 {one}") } else { format!("{n} {one}s") };
    if secs < 60 {
        return unit(secs, "second");
    }
    let (days, hours, mins) = (secs / 86_400, secs / 3600 % 24, secs / 60 % 60);
    let parts: Vec<String> = [(days, "day"), (hours, "hour"), (mins, "minute")]
        .into_iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, u)| unit(n, u))
        .collect();
    parts.join(" ")
}

/// `delta` from now in words: `in 4 min`, `3 h ago`.
pub fn relative(at: Timestamp, now: Timestamp) -> String {
    let secs = at.as_second() - now.as_second();
    let n = secs.unsigned_abs();
    let amount = if n < 60 {
        format!("{n} s")
    } else if n < 3600 {
        format!("{} min", n / 60)
    } else if n < 86_400 {
        format!("{} h", n / 3600)
    } else {
        format!("{} d", n / 86_400)
    };
    if secs >= 0 { format!("in {amount}") } else { format!("{amount} ago") }
}

#[cfg(test)]
mod tests;
