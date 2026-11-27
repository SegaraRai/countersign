//! The UI API: what the pages read and do, as JSON.
//!
//! It is served only in process, at [`UI_ORIGIN`](super::UI_ORIGIN), to the
//! pages' server code; no browser reaches it. Who is asking comes from the
//! [`Visit`] in the trusted context of the page request, never from what
//! JavaScript sends. Changes are accepted only for page requests that came
//! from the site itself, so a form on another site cannot make them.
//!
//! Errors are `{ "error": code, "message": text }`, plus `login` (where to
//! sign in again) for `fresh_auth_required`.

use std::collections::BTreeSet;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Form, Json, Router};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tracing::{info, warn};

use countersign_core::form::{Choice, Field, FieldKind, TextFormat};
use countersign_core::present::{Audience, Presentation, Shown, Tone, When};
use countersign_core::question::REMOVED;
use countersign_core::text::escape;
use countersign_core::{
    ActionIntent, ActorId, ActorKind, AnswerError, AnswerIntent, Assurance, Question, QuestionOutcome, Request,
    RequestFilter, RequestId, RequestState, Response as Reply, Role, TransitionError, Verdict,
};

use super::pages::Visit;
use super::session::{Session, check_session, login_url, question_access, responds_to, sees_approval, sees_question};
use super::{AppState, clean_comment, human_error};
use crate::engine::EngineError;

const RECENT: usize = 25;

/// The UI API. Every route expects the [`Visit`] of a page request in its
/// `fetchlet::Context`; without one it is as if nobody were signed in.
pub fn ui_router(state: AppState) -> Router {
    Router::new()
        .route("/me", get(me))
        .route("/requests", get(index))
        .route("/requests/{id}", get(item))
        .route("/requests/{id}/decision", post(decide))
        .route("/requests/{id}/revoke", post(revoke))
        .route("/requests/{id}/answer", post(answer))
        .route("/admin", get(admin))
        .route("/admin/action", post(admin_action))
        .route("/link", post(link))
        .route("/notice", get(notice))
        .with_state(state)
}

// ------------------------------------------------------------------ plumbing

#[derive(Debug, Serialize)]
struct UiError {
    error: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    login: Option<String>,
}

fn error(status: StatusCode, error: &'static str, message: impl Into<String>) -> Response {
    (status, Json(UiError { error, message: message.into(), login: None })).into_response()
}

fn fresh_auth_required(next: &str, message: String) -> Response {
    let body = UiError { error: "fresh_auth_required", message, login: Some(login_url(next, true)) };
    (StatusCode::UNAUTHORIZED, Json(body)).into_response()
}

fn rejected(e: &EngineError) -> Response {
    let (status, message) = human_error(e);
    error(status, "rejected", message)
}

fn not_found() -> Response {
    error(StatusCode::NOT_FOUND, "not_found", "No such request.")
}

fn ok() -> Response {
    Json(serde_json::json!({ "ok": true })).into_response()
}

type Ctx = Option<Extension<fetchlet::Context>>;

fn visit(ctx: &Ctx) -> Visit {
    ctx.as_ref().and_then(|Extension(c)| c.get::<Visit>()).cloned().unwrap_or_default()
}

// Handlers return the error response as is; boxing it buys nothing here.
#[allow(clippy::result_large_err)]
async fn signed_in(state: &AppState, ctx: &Ctx, now: Timestamp) -> Result<Session, Response> {
    match visit(ctx).session {
        Some(data) => check_session(state, data, now).await,
        None => None,
    }
    .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "unauthenticated", "Sign in first."))
}

/// The signed-in person, for a change: only from a page request that came
/// from the site itself.
#[allow(clippy::result_large_err)]
async fn acting(state: &AppState, ctx: &Ctx, now: Timestamp) -> Result<Session, Response> {
    if !visit(ctx).same_origin {
        return Err(error(StatusCode::FORBIDDEN, "cross_site", "The form did not come from this site."));
    }
    signed_in(state, ctx, now).await
}

fn parse_id(id: &str) -> Option<RequestId> {
    id.parse().ok()
}

// ------------------------------------------------------------------ me

#[derive(Debug, Serialize)]
struct Me {
    person: String,
    name: String,
    roles: Vec<&'static str>,
    member: bool,
    oversees: bool,
    admin: bool,
    /// For the sign-out form, which Rust handles.
    csrf: String,
    assurance: Assurance,
    fresh_until: Option<Timestamp>,
}

async fn me(State(state): State<AppState>, ctx: Ctx) -> Response {
    let now = Timestamp::now();
    match signed_in(&state, &ctx, now).await {
        Ok(s) => Json(Me {
            person: s.person.to_string(),
            name: s.name.clone(),
            roles: s.roles.iter().map(|r| r.as_str()).collect(),
            member: s.has(Role::Member),
            oversees: s.oversees(),
            admin: s.has(Role::Admin),
            csrf: s.data.csrf.clone(),
            assurance: s.assurance(now, state.settings.fresh_auth_window),
            fresh_until: s.fresh_until(state.settings.fresh_auth_window),
        })
        .into_response(),
        Err(r) => r,
    }
}

// ------------------------------------------------------------------ lists

/// One line of the request lists.
#[derive(Debug, Serialize)]
struct Row {
    kind: &'static str,
    id: String,
    headline: String,
    /// The first line of the command, session or question.
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,
    label: String,
    tone: Tone,
    /// The time that matters now, for items not yet finished.
    #[serde(skip_serializing_if = "Option::is_none")]
    time: Option<When>,
    created_at: Timestamp,
    updated_at: Timestamp,
    #[serde(skip)]
    stage: Stage,
}

/// Where a row goes on the index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Someone has to decide or answer.
    Waiting,
    /// Approved and not over yet.
    Active,
    Finished,
}

fn row(id: RequestId, p: &Presentation, stage: Stage, (created_at, updated_at): (Timestamp, Timestamp)) -> Row {
    Row {
        kind: p.kind,
        id: id.to_string(),
        headline: p.headline.clone(),
        summary: p.action.as_ref().map(Shown::summary).filter(|s| !s.is_empty()),
        label: p.status.label.clone(),
        tone: p.status.tone,
        time: if stage == Stage::Finished { None } else { p.status.time },
        created_at,
        updated_at,
        stage,
    }
}

fn approval_row(r: &Request) -> Row {
    // A sensitive request's command stays on its own page.
    let mut p = Presentation::approval(r, Audience::Full);
    if r.sensitive {
        p.action = None;
    }
    let stage = if r.state.is_pending() {
        Stage::Waiting
    } else if r.state.is_terminal() {
        Stage::Finished
    } else {
        Stage::Active
    };
    row(r.id, &p, stage, (r.created_at, r.updated_at))
}

fn question_row(q: &Question) -> Row {
    let p = Presentation::question(q, Audience::Chat);
    let stage = if q.is_pending() { Stage::Waiting } else { Stage::Finished };
    row(q.id, &p, stage, (q.created_at, q.updated_at))
}

#[derive(Debug, Serialize)]
struct Index {
    waiting: Vec<Row>,
    active: Vec<Row>,
    recent: Vec<Row>,
}

async fn index(State(state): State<AppState>, ctx: Ctx) -> Response {
    let now = Timestamp::now();
    let session = match signed_in(&state, &ctx, now).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let store = state.engine.store();
    let filter = RequestFilter { open_only: false, limit: Some(500) };
    let (approvals, questions) = match (store.list_requests(&filter).await, store.list_questions(&filter).await) {
        (Ok(a), Ok(q)) => (a, q),
        (Err(e), _) | (_, Err(e)) => {
            warn!(error = %e, "listing requests failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "store", "Could not load requests.");
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
    let mut index = Index { waiting: vec![], active: vec![], recent: vec![] };
    for r in rows {
        match r.stage {
            Stage::Waiting => index.waiting.push(r),
            Stage::Active => index.active.push(r),
            Stage::Finished => index.recent.push(r),
        }
    }
    index.recent.sort_by_key(|a| std::cmp::Reverse(a.updated_at));
    index.recent.truncate(RECENT);
    Json(index).into_response()
}

// ------------------------------------------------------------------ one item

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Item {
    Approval(Box<ApprovalPage>),
    Question(Box<QuestionPage>),
}

#[derive(Debug, Serialize)]
#[allow(clippy::struct_excessive_bools)] // flags the page branches on
struct ApprovalPage {
    id: String,
    p: Presentation,
    claims_note: &'static str,
    sensitive: bool,
    can_decide: bool,
    can_revoke: bool,
    /// Approving needs a fresh sign-in first.
    approve_needs_reauth: bool,
    /// Until when approving works without signing in again.
    fresh_until: Option<Timestamp>,
    cannot_decide: Option<String>,
}

#[derive(Debug, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct QuestionPage {
    id: String,
    headline: String,
    status: StatusView,
    grant: String,
    q: QuestionView,
    can_answer: bool,
    /// Answering needs a fresh sign-in first.
    needs_reauth: bool,
    /// Reading the confidential text needs a fresh sign-in first.
    read_needs_reauth: bool,
    cannot_answer: Option<String>,
}

#[derive(Debug, Serialize)]
struct StatusView {
    label: String,
    tone: Tone,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    time: Option<When>,
}

#[derive(Debug, Serialize)]
struct OptionView {
    value: String,
    label: String,
    selected: bool,
}

/// One form field, as the answer form lays it out.
#[derive(Debug, Serialize)]
struct FieldView {
    /// The input name: `f.<property>`.
    input: String,
    label: String,
    description: Option<String>,
    required: bool,
    /// `text`, `number`, `boolean`, `choice` or `choices`.
    kind: &'static str,
    /// For `text`: the `<input>` type.
    input_type: &'static str,
    step: &'static str,
    min: Option<f64>,
    max: Option<f64>,
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
        min: None,
        max: None,
        value: String::new(),
        hint: None,
        options: Vec::new(),
    };
    let opts = |options: &[Choice], selected: &dyn Fn(&str) -> bool| {
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
            v.min = *minimum;
            v.max = *maximum;
            v.value = default.map_or_else(String::new, |d| d.to_string());
        }
        FieldKind::Boolean { default } => {
            v.kind = "boolean";
            v.value = default.map_or_else(String::new, |d| d.to_string());
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
        escape(options.iter().find(|o| o.value == s).map_or(s, Choice::label))
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

/// How a question ended.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum OutcomeView {
    Answered { by: String, via: String, assurance: String, at: Timestamp },
    Declined { by: String, via: String, assurance: String, at: Timestamp },
    Expired { at: Timestamp },
    Withdrawn { at: Timestamp },
}

#[derive(Debug, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct QuestionView {
    asker: String,
    asker_actor: Option<String>,
    policy: String,
    /// The text, when the reader may see it and it is still kept.
    message: Option<String>,
    context: Vec<(String, String)>,
    confidential_question: bool,
    answer_may_be: bool,
    removed: bool,
    created_at: Timestamp,
    pending_until: Option<Timestamp>,
    responders: Vec<String>,
    min_assurance: String,
    outcome: Option<OutcomeView>,
    answer_confidential: bool,
    /// (label, value) of each answered field.
    answer: Vec<(String, String)>,
    /// The answer exists but is not for this reader.
    answer_hidden: bool,
    note: Option<String>,
    fields: Vec<FieldView>,
}

fn question_view(q: &Question, (text, answer): (bool, bool)) -> QuestionView {
    let form = q.form().ok();
    let mut v = QuestionView {
        asker: q.asker.client.to_string(),
        asker_actor: q.asker.actor.as_ref().map(ToString::to_string),
        policy: q.requirements.policy.to_string(),
        message: (text && !q.content_removed).then(|| q.message.clone()),
        context: if text { q.context.iter().map(|(k, v)| (escape(k), escape(v))).collect() } else { Vec::new() },
        confidential_question: q.confidentiality.question,
        answer_may_be: q.confidentiality.answer_may_be,
        removed: q.content_removed,
        created_at: q.created_at,
        pending_until: q.is_pending().then_some(q.pending_until),
        responders: q.requirements.responders.iter().map(ToString::to_string).collect(),
        min_assurance: q.required_assurance().to_string(),
        outcome: None,
        answer_confidential: q.answer_confidential(),
        answer: Vec::new(),
        answer_hidden: false,
        note: None,
        fields: if text && q.is_pending() {
            form.as_ref().map_or_else(Vec::new, |f| f.fields.iter().map(field_view).collect())
        } else {
            Vec::new()
        },
    };
    match &q.outcome {
        None => {}
        Some(QuestionOutcome::Accepted { by, at, assurance, via, content, fields, .. }) => {
            v.outcome = Some(OutcomeView::Answered {
                by: by.to_string(),
                via: via.to_string(),
                assurance: assurance.to_string(),
                at: *at,
            });
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
            v.outcome = Some(OutcomeView::Declined {
                by: by.to_string(),
                via: via.to_string(),
                assurance: assurance.to_string(),
                at: *at,
            });
            v.note = note.as_deref().map(escape);
        }
        Some(QuestionOutcome::Expired { at }) => v.outcome = Some(OutcomeView::Expired { at: *at }),
        Some(QuestionOutcome::Withdrawn { at }) => v.outcome = Some(OutcomeView::Withdrawn { at: *at }),
    }
    v
}

fn approval_page(state: &AppState, session: &Session, r: &Request, now: Timestamp) -> ApprovalPage {
    let roster = session.roster(now);
    let window = state.settings.fresh_auth_window;
    let assurance = session.assurance(now, window);
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
    ApprovalPage {
        id: r.id.to_string(),
        claims_note: p.claims_note(),
        sensitive: r.sensitive,
        can_decide,
        can_revoke: may_revoke && matches!(r.state, RequestState::Active { .. }),
        approve_needs_reauth: assurance < r.requirements.min_assurance,
        fresh_until: (assurance == Assurance::FreshAuth).then(|| session.fresh_until(window)).flatten(),
        cannot_decide,
        p,
    }
}

fn question_page(state: &AppState, session: &Session, q: &Question, now: Timestamp) -> QuestionPage {
    let roster = session.roster(now);
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
    QuestionPage {
        id: q.id.to_string(),
        headline: p.headline,
        status: StatusView { label: p.status.label, tone: p.status.tone, detail: p.status.detail, time: p.status.time },
        grant: p.grant,
        can_answer,
        needs_reauth: assurance < q.required_assurance(),
        read_needs_reauth: q.confidentiality.question && !access.0 && responds_to(&roster, session, q),
        cannot_answer,
        q: question_view(q, access),
    }
}

async fn item(State(state): State<AppState>, ctx: Ctx, Path(id): Path<String>) -> Response {
    let now = Timestamp::now();
    let session = match signed_in(&state, &ctx, now).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    let store = state.engine.store();
    let found = match store.get_request(id).await {
        Ok(Some(r)) => Ok(sees_approval(&session.roster(now), &session, &r)
            .then(|| Item::Approval(Box::new(approval_page(&state, &session, &r, now))))),
        Ok(None) => match store.get_question(id).await {
            Ok(Some(q)) => Ok(sees_question(&session.roster(now), &session, &q)
                .then(|| Item::Question(Box::new(question_page(&state, &session, &q, now))))),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        },
        Err(e) => Err(e),
    };
    match found {
        Ok(Some(item)) => Json(item).into_response(),
        Ok(None) => not_found(),
        Err(e) => {
            warn!(error = %e, "loading request failed");
            error(StatusCode::INTERNAL_SERVER_ERROR, "store", "Could not load the request.")
        }
    }
}

// ------------------------------------------------------------------ decisions and answers

#[derive(Debug, Deserialize)]
struct DecisionForm {
    verdict: String,
    #[serde(default)]
    comment: Option<String>,
}

async fn decide(
    State(state): State<AppState>,
    ctx: Ctx,
    Path(id): Path<String>,
    Form(form): Form<DecisionForm>,
) -> Response {
    let now = Timestamp::now();
    let session = match acting(&state, &ctx, now).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    let verdict = match form.verdict.as_str() {
        "approve" => Verdict::Approve,
        "deny" => Verdict::Deny,
        _ => return error(StatusCode::BAD_REQUEST, "invalid", "Unknown action."),
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
        Ok(_) => ok(),
        Err(EngineError::Transition(e @ TransitionError::InsufficientAssurance { .. })) => {
            fresh_auth_required(&format!("/requests/{id}"), e.to_string())
        }
        Err(e) => rejected(&e),
    }
}

async fn revoke(State(state): State<AppState>, ctx: Ctx, Path(id): Path<String>) -> Response {
    let now = Timestamp::now();
    let session = match acting(&state, &ctx, now).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    match state.engine.revoke(id, &session.person, now).await {
        Ok(_) => ok(),
        Err(e) => rejected(&e),
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

/// `action=answer` with the fields as `f.<name>` (and `confidential`), or
/// `action=decline` with an optional `note`.
async fn answer(
    State(state): State<AppState>,
    ctx: Ctx,
    Path(id): Path<String>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let now = Timestamp::now();
    let session = match acting(&state, &ctx, now).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    let q = match state.engine.store().get_question(id).await {
        Ok(Some(q)) => q,
        Ok(None) => return not_found(),
        Err(e) => {
            warn!(error = %e, "loading question failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "store", "Could not load the question.");
        }
    };
    let response = match form_value(&pairs, "action") {
        Some("decline") => Reply::Decline {
            note: form_value(&pairs, "note").map(str::trim).filter(|n| !n.is_empty()).map(str::to_owned),
        },
        Some("answer") => match form_content(&q, &pairs) {
            Ok(content) => Reply::Accept {
                content,
                confidential: q.confidentiality.question || form_value(&pairs, "confidential").is_some(),
            },
            Err(msg) => return error(StatusCode::BAD_REQUEST, "invalid", msg),
        },
        _ => return error(StatusCode::BAD_REQUEST, "invalid", "Unknown action."),
    };
    let intent = AnswerIntent {
        question_id: id,
        responder: session.person.clone(),
        response,
        assurance: session.assurance(now, state.settings.fresh_auth_window),
        via: "web".into(),
    };
    match state.engine.answer(intent, now).await {
        Ok(_) => ok(),
        Err(EngineError::Answer(e @ AnswerError::InsufficientAssurance { .. })) => {
            fresh_auth_required(&format!("/requests/{id}"), e.to_string())
        }
        Err(e) => rejected(&e),
    }
}

// ------------------------------------------------------------------ admin

#[derive(Debug, Serialize)]
struct SuspensionView {
    by: String,
    since: Timestamp,
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct ActorView {
    id: String,
    /// `person` or `workload`.
    kind: &'static str,
    name: String,
    /// Active: not suspended, and (a workload) with an active owner.
    active: bool,
    suspension: Option<SuspensionView>,
    groups: BTreeSet<String>,
    roles: Vec<&'static str>,
    owners: Vec<String>,
}

#[derive(Debug, Serialize)]
struct LinkView {
    channel: String,
    external_id: String,
    person: String,
    linked_at: Timestamp,
}

#[derive(Debug, Serialize)]
struct ActionView {
    at: Timestamp,
    by: String,
    action: String,
    target: String,
    detail: Option<String>,
}

#[derive(Debug, Serialize)]
struct AdminPage {
    /// The reader may act (admins); auditors only look.
    admin: bool,
    actors: Vec<ActorView>,
    links: Vec<LinkView>,
    actions: Vec<ActionView>,
}

async fn admin(State(state): State<AppState>, ctx: Ctx) -> Response {
    let now = Timestamp::now();
    let session = match signed_in(&state, &ctx, now).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if !session.oversees() {
        return error(StatusCode::FORBIDDEN, "forbidden", "This page is for auditors and admins.");
    }
    let roster = session.roster(now);
    let actors = session
        .rules
        .directory
        .actors()
        .map(|a| {
            let suspension = session.standing.suspended.get(&a.id);
            ActorView {
                id: a.id.to_string(),
                kind: if a.is_person() { "person" } else { "workload" },
                name: escape(a.name()),
                active: roster.is_active(&a.id),
                suspension: suspension.map(|s| SuspensionView {
                    by: s.by.to_string(),
                    since: s.since,
                    reason: s.reason.as_deref().map(escape),
                }),
                groups: roster.groups(&a.id),
                roles: roster.roles(&a.id).into_iter().map(Role::as_str).collect(),
                owners: match &a.kind {
                    ActorKind::Workload { owners } => owners.iter().map(ToString::to_string).collect(),
                    ActorKind::Person => Vec::new(),
                },
            }
        })
        .collect();
    let store = state.engine.store();
    let links = store
        .list_account_links()
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "listing account links failed");
            Vec::new()
        })
        .into_iter()
        .map(|l| LinkView {
            channel: l.channel.to_string(),
            external_id: escape(&l.external_id),
            person: l.person.to_string(),
            linked_at: l.linked_at,
        })
        .collect();
    let actions = store
        .admin_actions(50)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "listing admin actions failed");
            Vec::new()
        })
        .into_iter()
        .map(|a| ActionView {
            at: a.at,
            by: a.by.to_string(),
            action: a.action,
            target: escape(&a.target),
            detail: a.detail.as_deref().map(escape),
        })
        .collect();
    Json(AdminPage { admin: session.has(Role::Admin), actors, links, actions }).into_response()
}

#[derive(Debug, Deserialize)]
struct AdminForm {
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

async fn admin_action(State(state): State<AppState>, ctx: Ctx, Form(form): Form<AdminForm>) -> Response {
    let now = Timestamp::now();
    let session = match acting(&state, &ctx, now).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if !session.has(Role::Admin) {
        return error(StatusCode::FORBIDDEN, "forbidden", "Only admins can do this.");
    }
    let actor = form.actor.as_deref().map(ActorId::new);
    let engine = &state.engine;
    let result = match (form.action.as_str(), actor) {
        ("suspend", Some(a)) => engine.suspend(&a, &session.person, clean_comment(form.reason), now).await.map(drop),
        // Lifting a suspension widens access: like approving, it needs a
        // fresh sign-in.
        ("reinstate", Some(_)) if session.assurance(now, state.settings.fresh_auth_window) < Assurance::FreshAuth => {
            return fresh_auth_required("/admin", "Lifting a suspension needs a fresh sign-in.".into());
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
        Ok(()) => ok(),
        Err(e) => rejected(&e),
    }
}

// ------------------------------------------------------------------ chat account linking

#[derive(Debug, Serialize)]
struct LinkCode {
    code: String,
    expires: Timestamp,
}

async fn link(State(state): State<AppState>, ctx: Ctx) -> Response {
    let now = Timestamp::now();
    let session = match acting(&state, &ctx, now).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let (code, expires) = state.links.issue(&session.person, now);
    info!(person = %session.person, "chat link code issued");
    Json(LinkCode { code, expires }).into_response()
}

// ------------------------------------------------------------------ notices

/// The notice Rust asked the pages to show; nothing for a page request.
async fn notice(ctx: Ctx) -> Response {
    match visit(&ctx).notice {
        Some(n) => Json(n).into_response(),
        None => error(StatusCode::NOT_FOUND, "not_found", "Nothing to show."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            ("action", "answer"),
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
        let r = super::super::session::redacted(&q, (false, false));
        assert_eq!(r.message, REMOVED);
        assert!(r.context.is_empty());
        assert_eq!(super::super::session::redacted(&q, (true, true)), q);
    }
}
