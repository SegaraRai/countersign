//! Web UI and JSON API for persons.
//!
//! - Sessions live in an encrypted, HTTP-only cookie. Every request re-checks
//!   that the sign-in identity still belongs to the person, that the person
//!   is active (not suspended) and holds a role, so a suspension or a config
//!   change ends their access at once.
//! - Every state-changing request needs the per-session CSRF token.
//! - A decision counts as `fresh-auth` only while the identity provider's
//!   `auth_time` is within `server.fresh_auth_window`. When a policy needs
//!   more than the session offers, the user is sent through a fresh login
//!   (`prompt=login`) and back.
//! - Members see what they could decide or answer, what they took part in,
//!   and what they or their workloads asked for; auditors and admins see
//!   everything. Confidential question content is shown only to that
//!   question's responders, and only while it is kept.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use askama::Template;
use axum::extract::{FromRef, Path, Query, Request as HttpRequest, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use axum_extra::extract::PrivateCookieJar;
use axum_extra::extract::cookie::{Cookie, Key, SameSite};
use countersign_core::form::{Field, FieldKind, TextFormat};
use countersign_core::present::{self, Audience, Presentation, Shown, Tone, When};
use countersign_core::question::REMOVED;
use countersign_core::text::escape;
use countersign_core::{
    ActionIntent, ActorId, ActorKind, AnswerError, AnswerIntent, Assurance, Authenticator, IdpSnapshot, Purpose,
    Question, QuestionOutcome, Request, RequestFilter, RequestId, RequestState, Response as Reply, Role, Roster,
    Standing, TransitionError, Verdict,
};
use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tracing::{info, warn};

use crate::engine::{Engine, EngineError, Rules};
use crate::link::LinkCodes;

const SESSION_COOKIE: &str = "cs_session";
const LOGIN_COOKIE: &str = "cs_login";
const LOGIN_TTL: Duration = Duration::from_secs(10 * 60);
const CSRF_HEADER: &str = "x-csrf-token";
const RECENT: usize = 25;

/// Settings for the web layer, derived from `[server]`.
#[derive(Debug, Clone)]
pub struct WebSettings {
    pub secure_cookies: bool,
    pub session_ttl: Duration,
    pub fresh_auth_window: Duration,
}

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<Engine>,
    pub auth: Option<Arc<dyn Authenticator>>,
    pub links: Arc<LinkCodes>,
    pub key: Key,
    pub settings: Arc<WebSettings>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState").field("settings", &self.settings).finish_non_exhaustive()
    }
}

impl FromRef<AppState> for Key {
    fn from_ref(s: &AppState) -> Self {
        s.key.clone()
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/requests/{id}", get(show))
        .route("/requests/{id}/decision", post(decide_form))
        .route("/requests/{id}/revoke", post(revoke_form))
        .route("/requests/{id}/answer", post(answer_form))
        .route("/admin", get(admin_page))
        .route("/admin/action", post(admin_action))
        .route("/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/logout", post(logout))
        .route("/link", get(link_page).post(link_issue))
        .route("/api/me", get(api_me))
        .route("/api/requests", get(api_list))
        .route("/api/requests/{id}", get(api_get))
        .route("/api/requests/{id}/decision", post(api_decide))
        .route("/api/questions", get(api_questions))
        .route("/api/questions/{id}", get(api_question))
        .route("/api/questions/{id}/answer", post(api_answer))
        .route("/healthz", get(|| async { "ok" }))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

async fn security_headers(req: HttpRequest, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

// ------------------------------------------------------------------ sessions

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionData {
    person: String,
    identity: String,
    auth_time: Option<i64>,
    issued: i64,
    csrf: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginData {
    state: String,
    next: String,
    issued: i64,
}

/// A signed-in, active person holding at least one role, with the rules and
/// standing their access was checked against.
#[derive(Debug, Clone)]
struct Session {
    person: ActorId,
    name: String,
    roles: BTreeSet<Role>,
    data: SessionData,
    rules: Arc<Rules>,
    standing: Arc<Standing>,
}

impl Session {
    fn assurance(&self, now: Timestamp, window: Duration) -> Assurance {
        match self.fresh_until(window) {
            Some(until) if now <= until => Assurance::FreshAuth,
            _ => Assurance::Web,
        }
    }

    fn fresh_until(&self, window: Duration) -> Option<Timestamp> {
        let t = Timestamp::from_second(self.data.auth_time?).ok()?;
        t.checked_add(SignedDuration::try_from(window).ok()?).ok()
    }

    fn roster(&self, now: Timestamp) -> Roster<'_> {
        self.rules.roster(&self.standing, now)
    }

    fn has(&self, role: Role) -> bool {
        self.roles.contains(&role)
    }

    /// Auditors and admins see everything.
    fn oversees(&self) -> bool {
        self.has(Role::Auditor) || self.has(Role::Admin)
    }

    fn view(&self) -> UserView {
        UserView { name: self.name.clone(), csrf: self.data.csrf.clone(), admin: self.oversees() }
    }
}

fn random_token() -> String {
    format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple())
}

fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn cookie(name: &'static str, value: String, secure: bool) -> Cookie<'static> {
    Cookie::build((name, value)).http_only(true).secure(secure).same_site(SameSite::Lax).path("/").build()
}

fn removal(name: &'static str) -> Cookie<'static> {
    Cookie::build((name, "")).path("/").build()
}

async fn current_session(state: &AppState, jar: &PrivateCookieJar, now: Timestamp) -> Option<Session> {
    let data: SessionData = serde_json::from_str(jar.get(SESSION_COOKIE)?.value()).ok()?;
    let ttl = i64::try_from(state.settings.session_ttl.as_secs()).unwrap_or(i64::MAX);
    if now.as_second() >= data.issued.saturating_add(ttl) {
        return None;
    }
    let (rules, standing) = match state.engine.standing().await {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "loading standing failed");
            return None;
        }
    };
    let person = ActorId::new(data.person.clone());
    let roster = rules.roster(&standing, now);
    // The sign-in identity must still belong to this person.
    let actor = rules.directory.by_identity(&data.identity, Purpose::SignIn).filter(|a| a.id == person)?;
    roster.active_person(&person)?;
    let held = roster.roles(&person);
    if held.is_empty() {
        return None;
    }
    let name = actor.display_name.clone().unwrap_or_else(|| person.to_string());
    Some(Session { person, name, roles: held, data, standing: Arc::new(standing), rules })
}

/// Only same-site absolute paths are accepted as post-login destinations.
fn safe_next(next: Option<&str>) -> String {
    match next {
        Some(n) if n.starts_with('/') && !n.starts_with("//") && !n.starts_with("/\\") && !n.contains(['\r', '\n']) => {
            n.to_owned()
        }
        _ => "/".to_owned(),
    }
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn login_url(next: &str, fresh: bool) -> String {
    format!("/login?next={}{}", percent_encode(next), if fresh { "&fresh=1" } else { "" })
}

// ------------------------------------------------------------------ visibility

/// Whether `s` relates to an actor: is it, or owns it.
fn relates_to(roster: &Roster<'_>, s: &Session, actor: Option<&ActorId>) -> bool {
    actor.is_some_and(|a| a == &s.person || roster.owners(a).contains(&s.person))
}

fn sees_approval(roster: &Roster<'_>, s: &Session, r: &Request) -> bool {
    s.oversees()
        || roster.could_be_selected(&r.requirements.approvers, &s.person)
        || r.decisions.iter().any(|d| d.approver == s.person)
        || r.facts.initiator.as_ref().and_then(|i| i.actor.as_ref()) == Some(&s.person)
        || relates_to(roster, s, r.facts.requester.actor.as_ref())
}

/// A responder of the question: selected now, or the one who answered.
fn responds_to(roster: &Roster<'_>, s: &Session, q: &Question) -> bool {
    roster.selected(&q.requirements.responders, &s.person) || answered_by(q) == Some(&s.person)
}

fn answered_by(q: &Question) -> Option<&ActorId> {
    match &q.outcome {
        Some(QuestionOutcome::Accepted { by, .. } | QuestionOutcome::Declined { by, .. }) => Some(by),
        _ => None,
    }
}

fn sees_question(roster: &Roster<'_>, s: &Session, q: &Question) -> bool {
    s.oversees()
        || roster.could_be_selected(&q.requirements.responders, &s.person)
        || answered_by(q) == Some(&s.person)
        || relates_to(roster, s, q.asker.actor.as_ref())
}

/// What of a question's content `s` may see now: (question text, answer).
fn question_access(roster: &Roster<'_>, s: &Session, q: &Question, assurance: Assurance) -> (bool, bool) {
    let responder = responds_to(roster, s, q);
    let text = !q.confidentiality.question || (responder && assurance >= q.required_assurance());
    let answer = !q.answer_confidential() || (responder && text);
    (text, answer)
}

/// A copy with what `s` may not see taken out.
fn redacted(q: &Question, (text, answer): (bool, bool)) -> Question {
    let mut q = q.clone();
    if !text && !q.content_removed {
        REMOVED.clone_into(&mut q.message);
        q.schema = serde_json::json!({ "type": "object", "properties": {} });
        q.context.clear();
    }
    if !answer && let Some(QuestionOutcome::Accepted { content, .. }) = &mut q.outcome {
        *content = None;
    }
    q
}

// ------------------------------------------------------------------ views

#[derive(Debug, Clone)]
struct UserView {
    name: String,
    csrf: String,
    admin: bool,
}

/// One line of the request lists.
#[derive(Debug)]
struct Row {
    kind: &'static str,
    id: String,
    headline: String,
    /// The first line of the command, session or question.
    summary: Option<String>,
    label: String,
    tone: &'static str,
    /// The time that matters (open items) or when it last changed.
    when: String,
    created_at: Timestamp,
    updated_at: Timestamp,
    open: bool,
}

#[derive(Debug)]
struct TimeView {
    label: &'static str,
    at: String,
    relative: String,
}

fn time_view(w: Option<When>, now: Timestamp) -> Option<TimeView> {
    w.map(|w| TimeView { label: w.label, at: fmt_time(w.at), relative: present::relative(w.at, now) })
}

/// The action, flattened for the template.
#[derive(Debug, Default)]
struct ItemAction {
    command: Option<String>,
    title: Option<String>,
    lines: Vec<countersign_core::Detail>,
}

fn action_view(shown: Option<&Shown>) -> ItemAction {
    match shown {
        Some(Shown::Command { line }) => ItemAction { command: Some(line.clone()), ..ItemAction::default() },
        Some(Shown::Lines { title, lines }) => {
            ItemAction { title: Some(title.clone()), lines: lines.clone(), ..ItemAction::default() }
        }
        Some(Shown::Question { .. }) | None => ItemAction::default(),
    }
}

#[derive(Debug)]
struct DecisionView {
    who: String,
    verdict: &'static str,
    assurance: String,
    via: String,
    at: String,
    comment: Option<String>,
}

#[derive(Debug)]
struct UseView {
    at: String,
    what: String,
}

fn tone_name(t: Tone) -> &'static str {
    match t {
        Tone::Waiting => "waiting",
        Tone::Asking => "asking",
        Tone::Good => "good",
        Tone::Done => "done",
        Tone::Bad => "bad",
        Tone::Muted => "muted",
    }
}

fn fmt_time(t: Timestamp) -> String {
    t.strftime("%Y-%m-%d %H:%M:%S UTC").to_string()
}

fn row(kind: &'static str, id: RequestId, p: &Presentation, open: bool, times: (Timestamp, Timestamp)) -> Row {
    let now = Timestamp::now();
    let when = match (open, time_view(p.status.time, now)) {
        (true, Some(t)) => format!("{} {}", t.label, t.relative),
        _ => present::relative(times.1, now),
    };
    Row {
        kind,
        id: id.to_string(),
        headline: p.headline.clone(),
        summary: p.action.as_ref().map(Shown::summary).filter(|s| !s.is_empty()),
        label: p.status.label.clone(),
        tone: tone_name(p.status.tone),
        when,
        created_at: times.0,
        updated_at: times.1,
        open,
    }
}

fn approval_row(r: &Request) -> Row {
    // A sensitive request's command stays on its own page.
    let mut p = Presentation::approval(r, Audience::Full);
    if r.sensitive {
        p.action = None;
    }
    row("approval", r.id, &p, !r.state.is_terminal(), (r.created_at, r.updated_at))
}

fn question_row(q: &Question) -> Row {
    let p = Presentation::question(q, Audience::Chat);
    row("question", q.id, &p, q.is_pending(), (q.created_at, q.updated_at))
}

#[derive(Debug)]
struct OptionView {
    value: String,
    label: String,
    selected: bool,
}

/// One form field, flattened for the template.
#[derive(Debug)]
struct FieldView {
    /// The input name: `f.<property>`.
    input: String,
    label: String,
    description: Option<String>,
    required: bool,
    /// `text`, `number`, `boolean`, `choice` or `choices`.
    kind: &'static str,
    input_type: &'static str,
    step: &'static str,
    min: String,
    max: String,
    value: String,
    hint: Option<&'static str>,
    options: Vec<OptionView>,
}

fn field_view(f: &Field) -> FieldView {
    let mut v = FieldView {
        input: format!("f.{}", f.name),
        label: escape(f.label()),
        description: f.description.as_deref().map(escape),
        required: f.required,
        kind: "text",
        input_type: "text",
        step: "any",
        min: String::new(),
        max: String::new(),
        value: String::new(),
        hint: None,
        options: Vec::new(),
    };
    let opts = |options: &[countersign_core::form::Choice], selected: &dyn Fn(&str) -> bool| {
        options
            .iter()
            .map(|o| OptionView { value: o.value.clone(), label: escape(o.label()), selected: selected(&o.value) })
            .collect()
    };
    match &f.kind {
        FieldKind::Text { format, default, .. } => {
            (v.input_type, v.hint) = match format {
                Some(TextFormat::Email) => ("email", None),
                Some(TextFormat::Uri) => ("url", None),
                Some(TextFormat::Date) => ("date", None),
                Some(TextFormat::DateTime) => ("text", Some("RFC 3339, e.g. 2026-01-02T03:04:05Z")),
                None => ("text", None),
            };
            v.value = default.clone().unwrap_or_default();
        }
        FieldKind::Number { integer, minimum, maximum, default } => {
            v.kind = "number";
            v.step = if *integer { "1" } else { "any" };
            v.min = minimum.map(|m| m.to_string()).unwrap_or_default();
            v.max = maximum.map(|m| m.to_string()).unwrap_or_default();
            v.value = default.map(|d| d.to_string()).unwrap_or_default();
        }
        FieldKind::Boolean { default } => {
            v.kind = "boolean";
            v.value = default.map(|d| d.to_string()).unwrap_or_default();
        }
        FieldKind::Choice { options, default } => {
            v.kind = "choice";
            v.options = opts(options, &|o| default.as_deref() == Some(o));
        }
        FieldKind::Choices { options, default, .. } => {
            v.kind = "choices";
            v.options = opts(options, &|o| default.iter().any(|d| d == o));
        }
    }
    v
}

/// An answer value as shown: choice labels, yes/no, numbers, text.
fn show_value(field: Option<&Field>, v: &Value) -> String {
    let label = |s: &str| -> String {
        let options = match field.map(|f| &f.kind) {
            Some(FieldKind::Choice { options, .. } | FieldKind::Choices { options, .. }) => options.as_slice(),
            _ => &[],
        };
        escape(options.iter().find(|o| o.value == s).map_or(s, countersign_core::form::Choice::label))
    };
    match v {
        Value::String(s) => label(s),
        Value::Bool(b) => if *b { "yes" } else { "no" }.to_owned(),
        Value::Array(a) => {
            a.iter().map(|x| x.as_str().map_or_else(|| x.to_string(), label)).collect::<Vec<_>>().join(", ")
        }
        other => escape(&other.to_string()),
    }
}

#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)] // flags the template branches on
struct QuestionView {
    id: String,
    asker: String,
    asker_actor: Option<String>,
    policy: String,
    message: Option<String>,
    context: Vec<(String, String)>,
    confidential_question: bool,
    answer_may_be: bool,
    removed: bool,
    created: String,
    pending_until: Option<String>,
    responders: String,
    min_assurance: String,
    /// The outcome line, e.g. "answered by bob (web, fresh-auth) at ...".
    outcome: Option<String>,
    answer_confidential: bool,
    answer: Vec<(String, String)>,
    answer_hidden: bool,
    note: Option<String>,
    fields: Vec<FieldView>,
}

fn question_view(q: &Question, (text, answer): (bool, bool)) -> QuestionView {
    let form = q.form().ok();
    let mut v = QuestionView {
        id: q.id.to_string(),
        asker: q.asker.client.to_string(),
        asker_actor: q.asker.actor.as_ref().map(ToString::to_string),
        policy: q.requirements.policy.to_string(),
        message: (text && !q.content_removed).then(|| q.message.clone()),
        context: if text { q.context.iter().map(|(k, v)| (escape(k), escape(v))).collect() } else { Vec::new() },
        confidential_question: q.confidentiality.question,
        answer_may_be: q.confidentiality.answer_may_be,
        removed: q.content_removed,
        created: fmt_time(q.created_at),
        pending_until: q.is_pending().then(|| fmt_time(q.pending_until)),
        responders: q.requirements.responders.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "),
        min_assurance: q.required_assurance().to_string(),
        outcome: None,
        answer_confidential: q.answer_confidential(),
        answer: Vec::new(),
        answer_hidden: false,
        note: None,
        fields: if text && q.is_pending() {
            form.as_ref().map(|f| f.fields.iter().map(field_view).collect()).unwrap_or_default()
        } else {
            Vec::new()
        },
    };
    match &q.outcome {
        None => {}
        Some(QuestionOutcome::Accepted { by, at, assurance, via, content, fields, .. }) => {
            v.outcome = Some(format!("Answered by {by} via {via} ({assurance}) at {}", fmt_time(*at)));
            match content {
                Some(c) if answer => {
                    v.answer = c
                        .iter()
                        .map(|(k, val)| {
                            let field = form.as_ref().and_then(|f| f.field(k));
                            (escape(field.map_or(k.as_str(), Field::label)), show_value(field, val))
                        })
                        .collect();
                }
                Some(_) => v.answer_hidden = true,
                None => v.answer = fields.iter().map(|f| (escape(f), REMOVED.to_owned())).collect(),
            }
        }
        Some(QuestionOutcome::Declined { by, at, assurance, via, note }) => {
            v.outcome = Some(format!("Declined by {by} via {via} ({assurance}) at {}", fmt_time(*at)));
            v.note = note.as_deref().map(escape);
        }
        Some(QuestionOutcome::Expired { at }) => v.outcome = Some(format!("No answer: expired at {}", fmt_time(*at))),
        Some(QuestionOutcome::Withdrawn { at }) => {
            v.outcome = Some(format!("Withdrawn by the asker at {}", fmt_time(*at)));
        }
    }
    v
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexPage {
    user: Option<UserView>,
    open: Vec<Row>,
    recent: Vec<Row>,
}

#[derive(Template)]
#[template(path = "request.html")]
#[allow(clippy::struct_excessive_bools)]
struct RequestPage {
    user: Option<UserView>,
    id: String,
    p: Presentation,
    tone: &'static str,
    when: Option<TimeView>,
    action: ItemAction,
    decisions: Vec<DecisionView>,
    uses: Vec<UseView>,
    sensitive: bool,
    csrf: String,
    error: Option<String>,
    can_decide: bool,
    can_revoke: bool,
    approve_needs_reauth: bool,
    fresh_until: Option<String>,
    cannot_decide: Option<String>,
}

#[derive(Template)]
#[template(path = "question.html")]
#[allow(clippy::struct_excessive_bools)]
struct QuestionPage {
    user: Option<UserView>,
    q: QuestionView,
    headline: String,
    label: String,
    tone: &'static str,
    detail: Option<String>,
    when: Option<TimeView>,
    grant: String,
    csrf: String,
    error: Option<String>,
    can_answer: bool,
    needs_reauth: bool,
    read_needs_reauth: bool,
    cannot_answer: Option<String>,
}

#[derive(Template)]
#[template(path = "link.html")]
struct LinkPage {
    user: Option<UserView>,
    csrf: String,
    code: Option<String>,
    expires: Option<String>,
}

#[derive(Template)]
#[template(path = "message.html")]
struct MessagePage {
    user: Option<UserView>,
    heading: String,
    body: String,
    detail: Option<String>,
}

#[derive(Debug)]
struct ActorView {
    id: String,
    kind: &'static str,
    name: String,
    status: String,
    suspended: bool,
    groups: String,
    roles: String,
    owners: String,
}

#[derive(Debug)]
struct LinkView {
    channel: String,
    external_id: String,
    person: String,
    linked: String,
}

#[derive(Debug)]
struct ActionView {
    at: String,
    by: String,
    action: String,
    target: String,
    detail: Option<String>,
}

#[derive(Template)]
#[template(path = "admin.html")]
struct AdminPage {
    user: Option<UserView>,
    csrf: String,
    admin: bool,
    error: Option<String>,
    actors: Vec<ActorView>,
    links: Vec<LinkView>,
    actions: Vec<ActionView>,
}

fn render(t: &impl Template) -> Response {
    match t.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            warn!(error = %e, "template rendering failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

fn message(status: StatusCode, user: Option<UserView>, heading: &str, body: &str, detail: Option<String>) -> Response {
    let page = MessagePage { user, heading: heading.into(), body: body.into(), detail };
    (status, render(&page)).into_response()
}

fn not_found(s: &Session) -> Response {
    message(StatusCode::NOT_FOUND, Some(s.view()), "Not found", "No such request.", None)
}

fn signed_out() -> Response {
    message(StatusCode::UNAUTHORIZED, None, "Signed out", "Your session has ended. Sign in and try again.", None)
}

fn bad_form(s: &Session) -> Response {
    message(
        StatusCode::FORBIDDEN,
        Some(s.view()),
        "Forbidden",
        "The form was not valid. Reload the page and try again.",
        None,
    )
}

fn human_error(e: &EngineError) -> (StatusCode, String) {
    let status = match e {
        EngineError::UnknownRequest(_) | EngineError::UnknownQuestion(_) => StatusCode::NOT_FOUND,
        EngineError::Forbidden(_)
        | EngineError::Refused(_)
        | EngineError::Transition(
            TransitionError::NotEligible | TransitionError::Inactive | TransitionError::Excluded(_),
        )
        | EngineError::Answer(AnswerError::NotEligible | AnswerError::Inactive | AnswerError::SelfAnswer) => {
            StatusCode::FORBIDDEN
        }
        EngineError::Invalid(_) | EngineError::Answer(AnswerError::Invalid(_) | AnswerError::MustStayConfidential) => {
            StatusCode::BAD_REQUEST
        }
        EngineError::Transition(_) | EngineError::Answer(_) | EngineError::Busy => StatusCode::CONFLICT,
        EngineError::Backend(_) => StatusCode::BAD_GATEWAY,
        EngineError::Store(_) | EngineError::UnknownBackend(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, e.to_string())
}

/// Either kind, as stored.
enum Item {
    Approval(Box<Request>),
    Question(Box<Question>),
}

async fn load(state: &AppState, id: RequestId) -> Result<Option<Item>, EngineError> {
    let store = state.engine.store();
    if let Some(r) = store.get_request(id).await? {
        return Ok(Some(Item::Approval(Box::new(r))));
    }
    Ok(store.get_question(id).await?.map(|q| Item::Question(Box::new(q))))
}

// ------------------------------------------------------------------ pages

async fn index(State(state): State<AppState>, jar: PrivateCookieJar) -> Response {
    let now = Timestamp::now();
    let Some(session) = current_session(&state, &jar, now).await else {
        return Redirect::to(&login_url("/", false)).into_response();
    };
    let store = state.engine.store();
    let filter = RequestFilter { open_only: false, limit: Some(500) };
    let (approvals, questions) = match (store.list_requests(&filter).await, store.list_questions(&filter).await) {
        (Ok(a), Ok(q)) => (a, q),
        (Err(e), _) | (_, Err(e)) => {
            warn!(error = %e, "listing requests failed");
            return message(
                StatusCode::INTERNAL_SERVER_ERROR,
                Some(session.view()),
                "Error",
                "Could not load requests.",
                None,
            );
        }
    };
    let roster = session.roster(now);
    let mut rows: Vec<Row> = approvals
        .iter()
        .filter(|r| sees_approval(&roster, &session, r))
        .map(approval_row)
        .chain(questions.iter().filter(|q| sees_question(&roster, &session, q)).map(question_row))
        .collect();
    rows.sort_by_key(|a| std::cmp::Reverse(a.created_at));
    let (open, mut recent): (Vec<Row>, Vec<Row>) = rows.into_iter().partition(|r| r.open);
    recent.sort_by_key(|a| std::cmp::Reverse(a.updated_at));
    recent.truncate(RECENT);
    render(&IndexPage { user: Some(session.view()), open, recent })
}

async fn item_page(
    state: &AppState,
    session: &Session,
    id: RequestId,
    error: Option<String>,
    status: StatusCode,
) -> Response {
    match load(state, id).await {
        Ok(Some(Item::Approval(r))) => approval_page(state, session, &r, error, status),
        Ok(Some(Item::Question(q))) => question_page(state, session, &q, error, status),
        Ok(None) => not_found(session),
        Err(e) => {
            warn!(error = %e, "loading request failed");
            message(
                StatusCode::INTERNAL_SERVER_ERROR,
                Some(session.view()),
                "Error",
                "Could not load the request.",
                None,
            )
        }
    }
}

fn approval_page(
    state: &AppState,
    session: &Session,
    r: &Request,
    error: Option<String>,
    status: StatusCode,
) -> Response {
    let now = Timestamp::now();
    let roster = session.roster(now);
    if !sees_approval(&roster, session, r) {
        return not_found(session);
    }
    let assurance = session.assurance(now, state.settings.fresh_auth_window);
    let member = session.has(Role::Member);
    let check = if member {
        r.check_decision(&roster, &session.person, Verdict::Deny, Assurance::FreshAuth, now)
    } else {
        Err(TransitionError::NotEligible)
    };
    let can_decide = check.is_ok();
    let cannot_decide = match check {
        Err(TransitionError::InvalidState { .. }) | Ok(()) => None,
        Err(_) if !member => Some("You can see this request but not decide it.".to_owned()),
        Err(e) => Some(format!("You cannot decide this request: {e}.")),
    };
    let may_revoke = session.has(Role::Admin) || (member && r.eligible(&roster, &session.person).is_ok());
    let p = Presentation::approval(r, Audience::Full);
    let page = RequestPage {
        user: Some(session.view()),
        csrf: session.data.csrf.clone(),
        error,
        can_decide,
        can_revoke: may_revoke && matches!(r.state, RequestState::Active { .. }),
        approve_needs_reauth: assurance < r.requirements.min_assurance,
        fresh_until: (assurance == Assurance::FreshAuth)
            .then(|| session.fresh_until(state.settings.fresh_auth_window).map(fmt_time))
            .flatten(),
        cannot_decide,
        id: r.id.to_string(),
        tone: tone_name(p.status.tone),
        when: time_view(p.status.time, now),
        action: action_view(p.action.as_ref()),
        decisions: p
            .status
            .decisions
            .iter()
            .map(|d| DecisionView {
                who: d.who.clone(),
                verdict: d.verdict(),
                assurance: d.assurance.clone(),
                via: d.via.clone(),
                at: fmt_time(d.at),
                comment: d.comment.clone(),
            })
            .collect(),
        uses: p.status.uses.iter().map(|u| UseView { at: fmt_time(u.at), what: u.what.clone() }).collect(),
        sensitive: r.sensitive,
        p,
    };
    (status, render(&page)).into_response()
}

fn question_page(
    state: &AppState,
    session: &Session,
    q: &Question,
    error: Option<String>,
    status: StatusCode,
) -> Response {
    let now = Timestamp::now();
    let roster = session.roster(now);
    if !sees_question(&roster, session, q) {
        return not_found(session);
    }
    let assurance = session.assurance(now, state.settings.fresh_auth_window);
    let access = question_access(&roster, session, q, assurance);
    let member = session.has(Role::Member);
    let eligible = if member { q.eligible(&roster, &session.person) } else { Err(AnswerError::NotEligible) };
    let can_answer = q.is_pending() && now < q.pending_until && eligible.is_ok();
    let cannot_answer = match eligible {
        _ if !q.is_pending() => None,
        Ok(()) => None,
        Err(_) if !member => Some("You can see this question but not answer it.".to_owned()),
        Err(e) => Some(format!("You cannot answer this question: {e}.")),
    };
    // Only the headline and status are taken from it: the text and answer
    // follow the reader's access below.
    let p = Presentation::question(q, Audience::Chat);
    let page = QuestionPage {
        user: Some(session.view()),
        csrf: session.data.csrf.clone(),
        error,
        can_answer,
        needs_reauth: assurance < q.required_assurance(),
        read_needs_reauth: q.confidentiality.question && !access.0 && responds_to(&roster, session, q),
        cannot_answer,
        headline: p.headline.clone(),
        label: p.status.label.clone(),
        tone: tone_name(p.status.tone),
        detail: p.status.detail.clone(),
        when: time_view(p.status.time, now),
        grant: p.grant.clone(),
        q: question_view(q, access),
    };
    (status, render(&page)).into_response()
}

async fn show(State(state): State<AppState>, jar: PrivateCookieJar, Path(id): Path<String>) -> Response {
    let Some(session) = current_session(&state, &jar, Timestamp::now()).await else {
        return Redirect::to(&login_url(&format!("/requests/{}", percent_encode(&id)), false)).into_response();
    };
    let Ok(id) = id.parse::<RequestId>() else {
        return not_found(&session);
    };
    item_page(&state, &session, id, None, StatusCode::OK).await
}

#[derive(Debug, Deserialize)]
struct DecisionForm {
    verdict: String,
    #[serde(default)]
    comment: Option<String>,
    csrf: String,
}

fn parse_verdict(s: &str) -> Option<Verdict> {
    match s {
        "approve" => Some(Verdict::Approve),
        "deny" => Some(Verdict::Deny),
        _ => None,
    }
}

fn clean_comment(c: Option<String>) -> Option<String> {
    c.map(|c| c.trim().chars().take(500).collect::<String>()).filter(|c| !c.is_empty())
}

async fn decide_form(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Path(id): Path<String>,
    Form(form): Form<DecisionForm>,
) -> Response {
    let now = Timestamp::now();
    let Some(session) = current_session(&state, &jar, now).await else {
        return signed_out();
    };
    if !same(&form.csrf, &session.data.csrf) {
        return bad_form(&session);
    }
    let (Ok(id), Some(verdict)) = (id.parse::<RequestId>(), parse_verdict(&form.verdict)) else {
        return message(
            StatusCode::BAD_REQUEST,
            Some(session.view()),
            "Bad request",
            "Unknown request or action.",
            None,
        );
    };
    let intent = ActionIntent {
        request_id: id,
        verdict,
        approver: session.person.clone(),
        assurance: session.assurance(now, state.settings.fresh_auth_window),
        via: "web".into(),
        comment: clean_comment(form.comment),
    };
    match state.engine.decide(intent, now).await {
        Ok(_) => Redirect::to(&format!("/requests/{id}")).into_response(),
        Err(EngineError::Transition(TransitionError::InsufficientAssurance { .. })) => {
            Redirect::to(&login_url(&format!("/requests/{id}"), true)).into_response()
        }
        Err(e) => {
            let (status, msg) = human_error(&e);
            item_page(&state, &session, id, Some(msg), status).await
        }
    }
}

#[derive(Debug, Deserialize)]
struct CsrfForm {
    csrf: String,
}

async fn revoke_form(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Path(id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let now = Timestamp::now();
    let Some(session) = current_session(&state, &jar, now).await else {
        return signed_out();
    };
    if !same(&form.csrf, &session.data.csrf) {
        return bad_form(&session);
    }
    let Ok(id) = id.parse::<RequestId>() else {
        return not_found(&session);
    };
    match state.engine.revoke(id, &session.person, now).await {
        Ok(_) => Redirect::to(&format!("/requests/{id}")).into_response(),
        Err(e) => {
            let (status, msg) = human_error(&e);
            item_page(&state, &session, id, Some(msg), status).await
        }
    }
}

/// The submitted values of form field `name` (input `f.<name>`).
fn field_values<'a>(pairs: &'a [(String, String)], name: &'a str) -> impl Iterator<Item = &'a str> {
    pairs.iter().filter(move |(k, _)| k.strip_prefix("f.") == Some(name)).map(|(_, v)| v.as_str())
}

/// Turn the submitted form into answer content, following the schema.
fn form_content(q: &Question, pairs: &[(String, String)]) -> Result<Map<String, Value>, String> {
    let form = q.form().map_err(|e| e.to_string())?;
    let mut content = Map::new();
    for f in &form.fields {
        let first = field_values(pairs, &f.name).next().map(str::trim).filter(|v| !v.is_empty());
        let value = match &f.kind {
            FieldKind::Text { .. } | FieldKind::Choice { .. } => first.map(|v| Value::String(v.to_owned())),
            FieldKind::Boolean { .. } => match first {
                Some("true") => Some(Value::Bool(true)),
                Some("false") => Some(Value::Bool(false)),
                Some(_) => return Err(format!("{}: choose yes or no", f.label())),
                None => None,
            },
            FieldKind::Number { integer, .. } => match first {
                None => None,
                Some(v) if *integer => {
                    Some(Value::from(v.parse::<i64>().map_err(|_| format!("{} must be a whole number", f.label()))?))
                }
                Some(v) => {
                    let n = v.parse::<f64>().map_err(|_| format!("{} must be a number", f.label()))?;
                    Some(
                        serde_json::Number::from_f64(n)
                            .map(Value::Number)
                            .ok_or(format!("{} is not finite", f.label()))?,
                    )
                }
            },
            FieldKind::Choices { .. } => {
                let chosen: Vec<Value> = field_values(pairs, &f.name).map(|v| Value::String(v.to_owned())).collect();
                (!chosen.is_empty()).then_some(Value::Array(chosen))
            }
        };
        if let Some(v) = value {
            content.insert(f.name.clone(), v);
        }
    }
    Ok(content)
}

fn form_value<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

async fn answer_form(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Path(id): Path<String>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let now = Timestamp::now();
    let Some(session) = current_session(&state, &jar, now).await else {
        return signed_out();
    };
    if !form_value(&pairs, "csrf").is_some_and(|c| same(c, &session.data.csrf)) {
        return bad_form(&session);
    }
    let Ok(id) = id.parse::<RequestId>() else {
        return not_found(&session);
    };
    let q = match state.engine.store().get_question(id).await {
        Ok(Some(q)) => q,
        Ok(None) => return not_found(&session),
        Err(e) => {
            warn!(error = %e, "loading question failed");
            return message(
                StatusCode::INTERNAL_SERVER_ERROR,
                Some(session.view()),
                "Error",
                "Could not load the question.",
                None,
            );
        }
    };
    let response = match form_value(&pairs, "action") {
        Some("decline") => Reply::Decline { note: form_value(&pairs, "note").map(str::to_owned) },
        Some("answer") => match form_content(&q, &pairs) {
            Ok(content) => Reply::Accept {
                content,
                confidential: q.confidentiality.question || form_value(&pairs, "confidential").is_some(),
            },
            Err(msg) => return question_page(&state, &session, &q, Some(msg), StatusCode::BAD_REQUEST),
        },
        _ => return message(StatusCode::BAD_REQUEST, Some(session.view()), "Bad request", "Unknown action.", None),
    };
    let intent = AnswerIntent {
        question_id: id,
        responder: session.person.clone(),
        response,
        assurance: session.assurance(now, state.settings.fresh_auth_window),
        via: "web".into(),
    };
    match state.engine.answer(intent, now).await {
        Ok(_) => Redirect::to(&format!("/requests/{id}")).into_response(),
        Err(EngineError::Answer(AnswerError::InsufficientAssurance { .. })) => {
            Redirect::to(&login_url(&format!("/requests/{id}"), true)).into_response()
        }
        Err(e) => {
            let (status, msg) = human_error(&e);
            question_page(&state, &session, &q, Some(msg), status)
        }
    }
}

// ------------------------------------------------------------------ admin

async fn admin_view(state: &AppState, session: &Session, error: Option<String>, status: StatusCode) -> Response {
    let now = Timestamp::now();
    let roster = session.roster(now);
    let dir = &session.rules.directory;
    let actors = dir
        .actors()
        .map(|a| {
            let suspension = session.standing.suspended.get(&a.id);
            let status = match suspension {
                Some(s) => format!(
                    "suspended by {} at {}{}",
                    s.by,
                    fmt_time(s.since),
                    s.reason.as_deref().map(|r| format!(": {}", escape(r))).unwrap_or_default()
                ),
                None if roster.is_active(&a.id) => "active".to_owned(),
                None => "inactive (no active owner)".to_owned(),
            };
            ActorView {
                id: a.id.to_string(),
                kind: if a.is_person() { "person" } else { "workload" },
                name: escape(a.name()),
                status,
                suspended: suspension.is_some(),
                groups: roster.groups(&a.id).into_iter().collect::<Vec<_>>().join(", "),
                roles: roster.roles(&a.id).into_iter().map(Role::as_str).collect::<Vec<_>>().join(", "),
                owners: match &a.kind {
                    ActorKind::Workload { owners } => {
                        owners.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
                    }
                    ActorKind::Person => String::new(),
                },
            }
        })
        .collect();
    let store = state.engine.store();
    let links = store
        .list_account_links()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|l| LinkView {
            channel: l.channel.to_string(),
            external_id: escape(&l.external_id),
            person: l.person.to_string(),
            linked: fmt_time(l.linked_at),
        })
        .collect();
    let actions = store
        .admin_actions(50)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|a| ActionView {
            at: fmt_time(a.at),
            by: a.by.to_string(),
            action: a.action,
            target: escape(&a.target),
            detail: a.detail.as_deref().map(escape),
        })
        .collect();
    let page = AdminPage {
        user: Some(session.view()),
        csrf: session.data.csrf.clone(),
        admin: session.has(Role::Admin),
        error,
        actors,
        links,
        actions,
    };
    (status, render(&page)).into_response()
}

async fn admin_page(State(state): State<AppState>, jar: PrivateCookieJar) -> Response {
    let Some(session) = current_session(&state, &jar, Timestamp::now()).await else {
        return Redirect::to(&login_url("/admin", false)).into_response();
    };
    if !session.oversees() {
        return message(
            StatusCode::FORBIDDEN,
            Some(session.view()),
            "Forbidden",
            "This page is for auditors and admins.",
            None,
        );
    }
    admin_view(&state, &session, None, StatusCode::OK).await
}

#[derive(Debug, Deserialize)]
struct AdminForm {
    csrf: String,
    action: String,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    external_id: Option<String>,
}

async fn admin_action(State(state): State<AppState>, jar: PrivateCookieJar, Form(form): Form<AdminForm>) -> Response {
    let now = Timestamp::now();
    let Some(session) = current_session(&state, &jar, now).await else {
        return signed_out();
    };
    if !same(&form.csrf, &session.data.csrf) {
        return bad_form(&session);
    }
    if !session.has(Role::Admin) {
        return message(StatusCode::FORBIDDEN, Some(session.view()), "Forbidden", "Only admins can do this.", None);
    }
    let actor = form.actor.as_deref().map(ActorId::new);
    let engine = &state.engine;
    let result = match (form.action.as_str(), actor) {
        ("suspend", Some(a)) => engine.suspend(&a, &session.person, form.reason, now).await.map(drop),
        // Lifting a suspension widens access: like approving, it needs a
        // fresh sign-in.
        ("reinstate", Some(_)) if session.assurance(now, state.settings.fresh_auth_window) < Assurance::FreshAuth => {
            return Redirect::to(&login_url("/admin", true)).into_response();
        }
        ("reinstate", Some(a)) => engine.reinstate(&a, &session.person, now).await.map(drop),
        ("revoke-approved-by", Some(a)) => engine.revoke_approved_by(&a, &session.person, now).await.map(drop),
        ("unlink", _) => match (form.channel, form.external_id) {
            (Some(c), Some(x)) => engine.unlink(&c.as_str().into(), &x, &session.person, now).await.map(drop),
            _ => Err(EngineError::Invalid("channel and account are required".into())),
        },
        _ => Err(EngineError::Invalid("unknown action".into())),
    };
    match result {
        Ok(()) => Redirect::to("/admin").into_response(),
        Err(e) => {
            let (status, msg) = human_error(&e);
            // Reload: the session's standing predates the change.
            match current_session(&state, &jar, now).await {
                Some(s) => admin_view(&state, &s, Some(msg), status).await,
                None => signed_out(),
            }
        }
    }
}

// ------------------------------------------------------------------ chat account linking

async fn link_page(State(state): State<AppState>, jar: PrivateCookieJar) -> Response {
    let Some(session) = current_session(&state, &jar, Timestamp::now()).await else {
        return Redirect::to(&login_url("/link", false)).into_response();
    };
    render(&LinkPage { user: Some(session.view()), csrf: session.data.csrf.clone(), code: None, expires: None })
}

async fn link_issue(State(state): State<AppState>, jar: PrivateCookieJar, Form(form): Form<CsrfForm>) -> Response {
    let now = Timestamp::now();
    let Some(session) = current_session(&state, &jar, now).await else {
        return signed_out();
    };
    if !same(&form.csrf, &session.data.csrf) {
        return bad_form(&session);
    }
    let (code, expires) = state.links.issue(&session.person, now);
    info!(person = %session.person, "chat link code issued");
    render(&LinkPage {
        user: Some(session.view()),
        csrf: session.data.csrf.clone(),
        code: Some(code),
        expires: Some(fmt_time(expires)),
    })
}

// ------------------------------------------------------------------ login

#[derive(Debug, Deserialize)]
struct LoginQuery {
    next: Option<String>,
    fresh: Option<String>,
}

fn no_idp() -> Response {
    message(StatusCode::SERVICE_UNAVAILABLE, None, "Sign-in unavailable", "No identity provider is configured.", None)
}

async fn login(State(state): State<AppState>, jar: PrivateCookieJar, Query(q): Query<LoginQuery>) -> Response {
    let Some(auth) = &state.auth else {
        return no_idp();
    };
    let fresh = q.fresh.as_deref().is_some_and(|f| f == "1" || f == "true");
    match auth.begin(fresh).await {
        Ok(start) => {
            let data = LoginData {
                state: start.state,
                next: safe_next(q.next.as_deref()),
                issued: Timestamp::now().as_second(),
            };
            let Ok(value) = serde_json::to_string(&data) else {
                return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
            };
            let jar = jar.add(cookie(LOGIN_COOKIE, value, state.settings.secure_cookies));
            (jar, Redirect::to(&start.redirect_url)).into_response()
        }
        Err(e) => {
            warn!(error = %e, "starting login failed");
            message(
                StatusCode::BAD_GATEWAY,
                None,
                "Sign-in unavailable",
                "The identity provider could not be reached.",
                None,
            )
        }
    }
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

async fn callback(State(state): State<AppState>, jar: PrivateCookieJar, Query(q): Query<CallbackQuery>) -> Response {
    let Some(auth) = &state.auth else {
        return no_idp();
    };
    let now = Timestamp::now();
    let saved: Option<LoginData> = jar.get(LOGIN_COOKIE).and_then(|c| serde_json::from_str(c.value()).ok());
    let jar = jar.remove(removal(LOGIN_COOKIE));
    let max_age = i64::try_from(LOGIN_TTL.as_secs()).unwrap_or(600);
    let Some(saved) = saved.filter(|s| now.as_second() < s.issued.saturating_add(max_age)) else {
        return (jar, message(StatusCode::BAD_REQUEST, None, "Sign-in expired", "Start the sign-in again.", None))
            .into_response();
    };
    if let Some(err) = q.error {
        let page = message(
            StatusCode::UNAUTHORIZED,
            None,
            "Sign-in failed",
            "The identity provider refused the sign-in.",
            Some(err),
        );
        return (jar, page).into_response();
    }
    let (Some(code), Some(returned)) = (q.code, q.state) else {
        return (jar, message(StatusCode::BAD_REQUEST, None, "Sign-in failed", "The callback was incomplete.", None))
            .into_response();
    };
    let login = match auth.complete(&saved.state, &returned, &code).await {
        Ok(l) => l,
        Err(e) => {
            warn!(error = %e, "completing login failed");
            let page =
                message(StatusCode::UNAUTHORIZED, None, "Sign-in failed", "The sign-in could not be verified.", None);
            return (jar, page).into_response();
        }
    };
    let rules = state.engine.rules();
    let Some(person) = rules.directory.by_identity(&login.identity, Purpose::SignIn).map(|a| a.id.clone()) else {
        info!(identity = %login.identity, "sign-in by an identity that is not a person");
        let page = message(
            StatusCode::FORBIDDEN,
            None,
            "No access",
            "You signed in, but this identity is not a person in countersign's configuration. An administrator can add it:",
            Some(login.identity),
        );
        return (jar, page).into_response();
    };

    // Remember the groups the provider reported now (none if it sent no
    // groups claim), replacing the previous sign-in's.
    let (provider, groups) = login.groups.clone().unwrap_or_else(|| {
        let provider = login.identity.rsplit_once('#').map_or(login.identity.as_str(), |(p, _)| p).to_owned();
        (provider, BTreeSet::new())
    });
    let snapshot = IdpSnapshot { provider, groups, at: now };
    if let Err(e) = state.engine.store().save_idp_snapshot(&person, &snapshot).await {
        warn!(error = %e, "saving sign-in groups failed");
    }

    let data = SessionData {
        person: person.to_string(),
        identity: login.identity,
        auth_time: login.auth_time.map(Timestamp::as_second),
        issued: now.as_second(),
        csrf: random_token(),
    };
    let Ok(value) = serde_json::to_string(&data) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    };
    let jar = jar.add(cookie(SESSION_COOKIE, value, state.settings.secure_cookies));
    if current_session(&state, &jar, now).await.is_none() {
        info!(%person, "sign-in by a person who is suspended or holds no role");
        let page = message(
            StatusCode::FORBIDDEN,
            None,
            "No access",
            "You signed in, but you are suspended or hold no role in countersign.",
            None,
        );
        return (jar.remove(removal(SESSION_COOKIE)), page).into_response();
    }
    info!(%person, "signed in");
    (jar, Redirect::to(&safe_next(Some(&saved.next)))).into_response()
}

async fn logout(State(state): State<AppState>, jar: PrivateCookieJar, Form(form): Form<CsrfForm>) -> Response {
    match current_session(&state, &jar, Timestamp::now()).await {
        Some(s) if !same(&form.csrf, &s.data.csrf) => {
            message(StatusCode::FORBIDDEN, Some(s.view()), "Forbidden", "The form was not valid.", None)
        }
        _ => (jar.remove(removal(SESSION_COOKIE)), Redirect::to("/")).into_response(),
    }
}

// ------------------------------------------------------------------ JSON API

#[derive(Debug, Serialize)]
struct ApiError {
    error: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    login: Option<String>,
}

fn api_error(status: StatusCode, error: &'static str, message: impl Into<String>) -> Response {
    (status, Json(ApiError { error, message: message.into(), login: None })).into_response()
}

fn fresh_auth_required(id: RequestId, message: String) -> Response {
    let body =
        ApiError { error: "fresh_auth_required", message, login: Some(login_url(&format!("/requests/{id}"), true)) };
    (StatusCode::UNAUTHORIZED, Json(body)).into_response()
}

// Handlers return the error response as is; boxing it buys nothing here.
#[allow(clippy::result_large_err)]
async fn api_session(state: &AppState, jar: &PrivateCookieJar) -> Result<Session, Response> {
    current_session(state, jar, Timestamp::now())
        .await
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "unauthenticated", "sign in first"))
}

#[allow(clippy::result_large_err)]
fn api_csrf(headers: &HeaderMap, session: &Session) -> Result<(), Response> {
    let token = headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok()).unwrap_or_default();
    if same(token, &session.data.csrf) {
        Ok(())
    } else {
        Err(api_error(StatusCode::FORBIDDEN, "csrf", "missing or wrong x-csrf-token header"))
    }
}

#[derive(Debug, Serialize)]
struct Me {
    person: String,
    roles: Vec<&'static str>,
    csrf: String,
    assurance: Assurance,
    fresh_until: Option<Timestamp>,
}

async fn api_me(State(state): State<AppState>, jar: PrivateCookieJar) -> Response {
    match api_session(&state, &jar).await {
        Ok(s) => Json(Me {
            person: s.person.to_string(),
            roles: s.roles.iter().map(|r| r.as_str()).collect(),
            csrf: s.data.csrf.clone(),
            assurance: s.assurance(Timestamp::now(), state.settings.fresh_auth_window),
            fresh_until: s.fresh_until(state.settings.fresh_auth_window),
        })
        .into_response(),
        Err(r) => r,
    }
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[serde(default)]
    open: Option<String>,
    #[serde(default)]
    limit: Option<u32>,
}

impl ListQuery {
    fn filter(&self) -> RequestFilter {
        RequestFilter {
            open_only: self.open.as_deref().is_some_and(|v| v == "1" || v == "true"),
            limit: Some(self.limit.unwrap_or(100).min(500)),
        }
    }
}

async fn api_list(State(state): State<AppState>, jar: PrivateCookieJar, Query(q): Query<ListQuery>) -> Response {
    let s = match api_session(&state, &jar).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    match state.engine.store().list_requests(&q.filter()).await {
        Ok(list) => {
            let roster = s.roster(Timestamp::now());
            Json(list.into_iter().filter(|r| sees_approval(&roster, &s, r)).collect::<Vec<_>>()).into_response()
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store", e.to_string()),
    }
}

async fn api_get(State(state): State<AppState>, jar: PrivateCookieJar, Path(id): Path<String>) -> Response {
    let s = match api_session(&state, &jar).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let missing = || api_error(StatusCode::NOT_FOUND, "not_found", "no such request");
    let Ok(id) = id.parse::<RequestId>() else {
        return missing();
    };
    match state.engine.store().get_request(id).await {
        Ok(Some(r)) if sees_approval(&s.roster(Timestamp::now()), &s, &r) => Json(r).into_response(),
        Ok(_) => missing(),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store", e.to_string()),
    }
}

#[derive(Debug, Deserialize)]
struct ApiDecision {
    verdict: Verdict,
    #[serde(default)]
    comment: Option<String>,
}

async fn api_decide(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ApiDecision>,
) -> Response {
    let now = Timestamp::now();
    let session = match api_session(&state, &jar).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = api_csrf(&headers, &session) {
        return r;
    }
    let Ok(id) = id.parse::<RequestId>() else {
        return api_error(StatusCode::NOT_FOUND, "not_found", "no such request");
    };
    let intent = ActionIntent {
        request_id: id,
        verdict: body.verdict,
        approver: session.person.clone(),
        assurance: session.assurance(now, state.settings.fresh_auth_window),
        via: "web".into(),
        comment: clean_comment(body.comment),
    };
    match state.engine.decide(intent, now).await {
        Ok(r) => Json(r).into_response(),
        Err(EngineError::Transition(e @ TransitionError::InsufficientAssurance { .. })) => {
            fresh_auth_required(id, e.to_string())
        }
        Err(e) => {
            let (status, msg) = human_error(&e);
            api_error(status, "rejected", msg)
        }
    }
}

async fn api_questions(State(state): State<AppState>, jar: PrivateCookieJar, Query(q): Query<ListQuery>) -> Response {
    let s = match api_session(&state, &jar).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let now = Timestamp::now();
    let assurance = s.assurance(now, state.settings.fresh_auth_window);
    match state.engine.store().list_questions(&q.filter()).await {
        Ok(list) => {
            let roster = s.roster(now);
            let visible: Vec<Question> = list
                .iter()
                .filter(|q| sees_question(&roster, &s, q))
                .map(|q| redacted(q, question_access(&roster, &s, q, assurance)))
                .collect();
            Json(visible).into_response()
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store", e.to_string()),
    }
}

async fn api_question(State(state): State<AppState>, jar: PrivateCookieJar, Path(id): Path<String>) -> Response {
    let s = match api_session(&state, &jar).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let missing = || api_error(StatusCode::NOT_FOUND, "not_found", "no such question");
    let Ok(id) = id.parse::<RequestId>() else {
        return missing();
    };
    let now = Timestamp::now();
    let roster = s.roster(now);
    match state.engine.store().get_question(id).await {
        Ok(Some(q)) if sees_question(&roster, &s, &q) => {
            let access = question_access(&roster, &s, &q, s.assurance(now, state.settings.fresh_auth_window));
            Json(redacted(&q, access)).into_response()
        }
        Ok(_) => missing(),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store", e.to_string()),
    }
}

async fn api_answer(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(response): Json<Reply>,
) -> Response {
    let now = Timestamp::now();
    let session = match api_session(&state, &jar).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = api_csrf(&headers, &session) {
        return r;
    }
    let Ok(id) = id.parse::<RequestId>() else {
        return api_error(StatusCode::NOT_FOUND, "not_found", "no such question");
    };
    let intent = AnswerIntent {
        question_id: id,
        responder: session.person.clone(),
        response,
        assurance: session.assurance(now, state.settings.fresh_auth_window),
        via: "web".into(),
    };
    match state.engine.answer(intent, now).await {
        Ok(q) => {
            // The responder wrote the answer; they may see it back.
            Json(redacted(&q, (true, true))).into_response()
        }
        Err(EngineError::Answer(e @ AnswerError::InsufficientAssurance { .. })) => {
            fresh_auth_required(id, e.to_string())
        }
        Err(e) => {
            let (status, msg) = human_error(&e);
            api_error(status, "rejected", msg)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_must_be_a_local_path() {
        assert_eq!(safe_next(Some("/requests/1")), "/requests/1");
        for bad in ["//evil.example", "/\\evil.example", "https://evil.example", "evil", "/a\r\nSet-Cookie: x"] {
            assert_eq!(safe_next(Some(bad)), "/", "{bad:?}");
        }
        assert_eq!(safe_next(None), "/");
    }

    #[test]
    fn encodes_login_urls() {
        assert_eq!(login_url("/requests/a b?x=1&y", true), "/login?next=/requests/a%20b%3Fx%3D1%26y&fresh=1");
    }

    #[test]
    fn freshness_window() {
        let s = Session {
            person: "a".into(),
            name: "a".into(),
            roles: BTreeSet::from([Role::Member]),
            data: SessionData {
                person: "a".into(),
                identity: "i".into(),
                auth_time: Some(1000),
                issued: 1000,
                csrf: "c".into(),
            },
            rules: Arc::default(),
            standing: Arc::default(),
        };
        let w = Duration::from_secs(300);
        let at = |s| Timestamp::from_second(s).unwrap();
        assert_eq!(s.assurance(at(1300), w), Assurance::FreshAuth);
        assert_eq!(s.assurance(at(1301), w), Assurance::Web);
        let none = Session { data: SessionData { auth_time: None, ..s.data.clone() }, ..s };
        assert_eq!(none.assurance(at(1000), w), Assurance::Web);
    }

    fn question(schema: Value) -> Question {
        let policy: countersign_core::QuestionPolicy =
            toml::from_str("name = 'q'\nresponders = ['group:ops']\n").unwrap();
        Question::ask(
            countersign_core::Asker { client: "c".into(), actor: None },
            "m".into(),
            schema,
            std::collections::BTreeMap::new(),
            &policy,
            countersign_core::Confidentiality::default(),
            Timestamp::UNIX_EPOCH,
        )
        .0
    }

    #[test]
    fn form_fields_become_content() {
        let q = question(serde_json::json!({ "type": "object", "properties": {
            "branch": { "type": "string", "enum": ["main", "release"] },
            "count": { "type": "integer" },
            "ratio": { "type": "number" },
            "ok": { "type": "boolean" },
            "tags": { "type": "array", "items": { "type": "string", "enum": ["a", "b", "c"] } },
            "note": { "type": "string" }
        }}));
        let pairs: Vec<(String, String)> = [
            ("f.branch", "release"),
            ("f.count", "3"),
            ("f.ratio", "0.5"),
            ("f.ok", "false"),
            ("f.tags", "a"),
            ("f.tags", "c"),
            ("f.note", "  "),
            ("csrf", "x"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let c = form_content(&q, &pairs).unwrap();
        assert_eq!(
            Value::Object(c),
            serde_json::json!({ "branch": "release", "count": 3, "ratio": 0.5, "ok": false, "tags": ["a", "c"] })
        );
        let bad = vec![("f.count".to_owned(), "x".to_owned())];
        assert!(form_content(&q, &bad).unwrap_err().contains("whole number"));
    }

    #[test]
    fn redaction_hides_text_and_answer() {
        let mut q = question(serde_json::json!({ "type": "object", "properties": { "x": { "type": "string" } } }));
        q.context.insert("k".into(), "v".into());
        let r = redacted(&q, (false, false));
        assert_eq!(r.message, REMOVED);
        assert!(r.context.is_empty());
        assert_eq!(redacted(&q, (true, true)), q);
    }
}
