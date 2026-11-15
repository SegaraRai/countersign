//! Web UI and JSON API for approvers.
//!
//! - Sessions live in an encrypted, HTTP-only cookie. Every request re-checks
//!   that the approver still exists and still owns the logged-in identity, so
//!   removing someone from the config (and reloading) ends their access.
//! - Every state-changing request needs the per-session CSRF token.
//! - A decision counts as `fresh-auth` only while the identity provider's
//!   `auth_time` is within `server.fresh_auth_window`. When a policy needs
//!   more than the session offers, approving sends the user through a fresh
//!   login (`prompt=login`) and back.

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
use countersign_core::{
    ActionIntent, Approver, Assurance, Authenticator, Request, RequestFilter, RequestId, RequestState, TransitionError,
    Verdict,
};
use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::engine::{Engine, EngineError};
use crate::link::LinkCodes;

const SESSION_COOKIE: &str = "cs_session";
const LOGIN_COOKIE: &str = "cs_login";
const LOGIN_TTL: Duration = Duration::from_secs(10 * 60);
const CSRF_HEADER: &str = "x-csrf-token";
const RECENT: u32 = 25;

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
        .route("/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/logout", post(logout))
        .route("/link", get(link_page).post(link_issue))
        .route("/api/me", get(api_me))
        .route("/api/requests", get(api_list))
        .route("/api/requests/{id}", get(api_get))
        .route("/api/requests/{id}/decision", post(api_decide))
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
    approver: String,
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

/// A logged-in approver.
#[derive(Debug, Clone)]
struct Session {
    approver: Approver,
    data: SessionData,
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

    fn view(&self) -> UserView {
        UserView {
            name: self.approver.display_name.clone().unwrap_or_else(|| self.approver.id.to_string()),
            csrf: self.data.csrf.clone(),
        }
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

fn current_session(state: &AppState, jar: &PrivateCookieJar, now: Timestamp) -> Option<Session> {
    let data: SessionData = serde_json::from_str(jar.get(SESSION_COOKIE)?.value()).ok()?;
    let ttl = i64::try_from(state.settings.session_ttl.as_secs()).unwrap_or(i64::MAX);
    if now.as_second() >= data.issued.saturating_add(ttl) {
        return None;
    }
    let approver = state.engine.rules().approvers.get(&data.approver.as_str().into())?.clone();
    approver.identities.contains(&data.identity).then_some(Session { approver, data })
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

// ------------------------------------------------------------------ views

#[derive(Debug, Clone)]
struct UserView {
    name: String,
    csrf: String,
}

#[derive(Debug)]
struct Row {
    id: String,
    requester: String,
    target: Option<String>,
    policy: String,
    state: &'static str,
    created: String,
    updated: String,
}

#[derive(Debug)]
struct DecisionView {
    approver: String,
    verdict: &'static str,
    assurance: String,
    via: String,
    at: String,
    comment: Option<String>,
}

#[derive(Debug)]
struct UseView {
    at: String,
    command: String,
    cwd: Option<String>,
}

#[derive(Debug)]
struct RequestView {
    id: String,
    state: &'static str,
    requester: String,
    display_name: Option<String>,
    groups: String,
    target: Option<String>,
    reason: Option<String>,
    subject: String,
    attributes: Vec<(String, String)>,
    policy: String,
    ttl: String,
    window: bool,
    quorum: u8,
    min_assurance: String,
    created: String,
    pending_until: Option<String>,
    active_until: Option<String>,
    failure: Option<String>,
    decisions: Vec<DecisionView>,
    uses: Vec<UseView>,
}

fn fmt_time(t: Timestamp) -> String {
    t.strftime("%Y-%m-%d %H:%M:%S UTC").to_string()
}

fn fmt_duration(d: Duration) -> String {
    let s = d.as_secs();
    match (s / 3600, (s % 3600) / 60, s % 60) {
        (0, 0, s) => format!("{s}s"),
        (0, m, 0) => format!("{m}m"),
        (h, 0, 0) => format!("{h}h"),
        (0, m, s) => format!("{m}m {s}s"),
        (h, m, _) => format!("{h}h {m}m"),
    }
}

fn row(r: &Request) -> Row {
    Row {
        id: r.id.to_string(),
        requester: r.facts.requester.id.clone(),
        target: r.facts.target.clone(),
        policy: r.requirements.policy.to_string(),
        state: r.state.name(),
        created: fmt_time(r.created_at),
        updated: fmt_time(r.updated_at),
    }
}

fn request_view(r: &Request) -> RequestView {
    let f = &r.facts;
    RequestView {
        id: r.id.to_string(),
        state: r.state.name(),
        requester: f.requester.id.clone(),
        display_name: f.requester.display_name.clone(),
        groups: f.requester.groups.iter().cloned().collect::<Vec<_>>().join(", "),
        target: f.target.clone(),
        reason: f.reason.clone(),
        subject: format!("{}/{}/{}", r.subject.backend, r.subject.kind, r.subject.id),
        attributes: f.attributes.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        policy: r.requirements.policy.to_string(),
        ttl: fmt_duration(r.requirements.ttl),
        window: r.requirements.grant == countersign_core::GrantMode::Window,
        quorum: r.requirements.quorum,
        min_assurance: r.requirements.min_assurance.to_string(),
        created: fmt_time(r.created_at),
        pending_until: r.state.is_pending().then(|| fmt_time(r.pending_until)),
        active_until: match r.state {
            RequestState::Active { until } => Some(fmt_time(until)),
            _ => None,
        },
        failure: match &r.state {
            RequestState::Failed { error } => Some(error.clone()),
            _ => None,
        },
        decisions: r
            .decisions
            .iter()
            .map(|d| DecisionView {
                approver: d.approver.to_string(),
                verdict: match d.verdict {
                    Verdict::Approve => "approve",
                    Verdict::Deny => "deny",
                },
                assurance: d.assurance.to_string(),
                via: d.via.to_string(),
                at: fmt_time(d.at),
                comment: d.comment.clone(),
            })
            .collect(),
        uses: r
            .uses
            .iter()
            .map(|u| UseView {
                at: fmt_time(u.at),
                command: u.attributes.get("command").cloned().unwrap_or_else(|| u.subject.id.clone()),
                cwd: u.attributes.get("cwd").cloned(),
            })
            .collect(),
    }
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
    r: RequestView,
    csrf: String,
    error: Option<String>,
    can_decide: bool,
    can_revoke: bool,
    approve_needs_reauth: bool,
    fresh_until: Option<String>,
    cannot_decide: Option<String>,
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

fn human_error(e: &EngineError) -> (StatusCode, String) {
    let status = match e {
        EngineError::UnknownRequest(_) => StatusCode::NOT_FOUND,
        EngineError::UnknownApprover(_)
        | EngineError::Transition(TransitionError::NotEligible | TransitionError::SelfApproval) => {
            StatusCode::FORBIDDEN
        }
        EngineError::Transition(_) | EngineError::Busy => StatusCode::CONFLICT,
        EngineError::Backend(_) => StatusCode::BAD_GATEWAY,
        EngineError::Store(_) | EngineError::UnknownBackend(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, e.to_string())
}

// ------------------------------------------------------------------ pages

async fn index(State(state): State<AppState>, jar: PrivateCookieJar) -> Response {
    let Some(session) = current_session(&state, &jar, Timestamp::now()) else {
        return Redirect::to(&login_url("/", false)).into_response();
    };
    let store = state.engine.store();
    let open = store.list_requests(&RequestFilter { open_only: true, limit: None }).await;
    let all = store.list_requests(&RequestFilter { open_only: false, limit: Some(RECENT * 4) }).await;
    match (open, all) {
        (Ok(open), Ok(all)) => render(&IndexPage {
            user: Some(session.view()),
            open: open.iter().map(row).collect(),
            recent: all.iter().filter(|r| r.state.is_terminal()).take(RECENT as usize).map(row).collect(),
        }),
        (Err(e), _) | (_, Err(e)) => {
            warn!(error = %e, "listing requests failed");
            message(StatusCode::INTERNAL_SERVER_ERROR, Some(session.view()), "Error", "Could not load requests.", None)
        }
    }
}

async fn request_page(
    state: &AppState,
    session: &Session,
    id: RequestId,
    error: Option<String>,
    status: StatusCode,
) -> Response {
    let now = Timestamp::now();
    let r = match state.engine.store().get_request(id).await {
        Ok(Some(r)) => r,
        Ok(None) => return message(StatusCode::NOT_FOUND, Some(session.view()), "Not found", "No such request.", None),
        Err(e) => {
            warn!(error = %e, "loading request failed");
            return message(
                StatusCode::INTERNAL_SERVER_ERROR,
                Some(session.view()),
                "Error",
                "Could not load the request.",
                None,
            );
        }
    };
    let assurance = session.assurance(now, state.settings.fresh_auth_window);
    let eligible = r.requirements.is_eligible(&session.approver);
    let check = r.check_decision(&session.approver, Verdict::Deny, Assurance::FreshAuth, now);
    let can_decide = check.is_ok();
    let cannot_decide = match check {
        Err(TransitionError::InvalidState { .. }) | Ok(()) => None,
        Err(e) => Some(format!("You cannot decide this request: {e}.")),
    };
    let page = RequestPage {
        user: Some(session.view()),
        csrf: session.data.csrf.clone(),
        error,
        can_decide,
        can_revoke: eligible && matches!(r.state, RequestState::Active { .. }),
        approve_needs_reauth: assurance < r.requirements.min_assurance,
        fresh_until: (assurance == Assurance::FreshAuth)
            .then(|| session.fresh_until(state.settings.fresh_auth_window).map(fmt_time))
            .flatten(),
        cannot_decide,
        r: request_view(&r),
    };
    (status, render(&page)).into_response()
}

async fn show(State(state): State<AppState>, jar: PrivateCookieJar, Path(id): Path<String>) -> Response {
    let Some(session) = current_session(&state, &jar, Timestamp::now()) else {
        return Redirect::to(&login_url(&format!("/requests/{}", percent_encode(&id)), false)).into_response();
    };
    let Ok(id) = id.parse::<RequestId>() else {
        return message(StatusCode::NOT_FOUND, Some(session.view()), "Not found", "No such request.", None);
    };
    request_page(&state, &session, id, None, StatusCode::OK).await
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
    let Some(session) = current_session(&state, &jar, now) else {
        return message(
            StatusCode::UNAUTHORIZED,
            None,
            "Signed out",
            "Your session has ended. Sign in and try again.",
            None,
        );
    };
    if !same(&form.csrf, &session.data.csrf) {
        return message(
            StatusCode::FORBIDDEN,
            Some(session.view()),
            "Forbidden",
            "The form was not valid. Reload the page and try again.",
            None,
        );
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
        approver: session.approver.id.clone(),
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
            request_page(&state, &session, id, Some(msg), status).await
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
    let Some(session) = current_session(&state, &jar, now) else {
        return message(
            StatusCode::UNAUTHORIZED,
            None,
            "Signed out",
            "Your session has ended. Sign in and try again.",
            None,
        );
    };
    if !same(&form.csrf, &session.data.csrf) {
        return message(
            StatusCode::FORBIDDEN,
            Some(session.view()),
            "Forbidden",
            "The form was not valid. Reload the page and try again.",
            None,
        );
    }
    let Ok(id) = id.parse::<RequestId>() else {
        return message(StatusCode::NOT_FOUND, Some(session.view()), "Not found", "No such request.", None);
    };
    match state.engine.revoke(id, &session.approver.id, now).await {
        Ok(_) => Redirect::to(&format!("/requests/{id}")).into_response(),
        Err(e) => {
            let (status, msg) = human_error(&e);
            request_page(&state, &session, id, Some(msg), status).await
        }
    }
}

// ------------------------------------------------------------------ chat account linking

async fn link_page(State(state): State<AppState>, jar: PrivateCookieJar) -> Response {
    let Some(session) = current_session(&state, &jar, Timestamp::now()) else {
        return Redirect::to(&login_url("/link", false)).into_response();
    };
    render(&LinkPage { user: Some(session.view()), csrf: session.data.csrf.clone(), code: None, expires: None })
}

async fn link_issue(State(state): State<AppState>, jar: PrivateCookieJar, Form(form): Form<CsrfForm>) -> Response {
    let now = Timestamp::now();
    let Some(session) = current_session(&state, &jar, now) else {
        return message(
            StatusCode::UNAUTHORIZED,
            None,
            "Signed out",
            "Your session has ended. Sign in and try again.",
            None,
        );
    };
    if !same(&form.csrf, &session.data.csrf) {
        return message(
            StatusCode::FORBIDDEN,
            Some(session.view()),
            "Forbidden",
            "The form was not valid. Reload the page and try again.",
            None,
        );
    }
    let (code, expires) = state.links.issue(&session.approver.id, now);
    info!(approver = %session.approver.id, "chat link code issued");
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

async fn login(State(state): State<AppState>, jar: PrivateCookieJar, Query(q): Query<LoginQuery>) -> Response {
    let Some(auth) = &state.auth else {
        return message(
            StatusCode::SERVICE_UNAVAILABLE,
            None,
            "Sign-in unavailable",
            "No identity provider is configured.",
            None,
        );
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
        return message(
            StatusCode::SERVICE_UNAVAILABLE,
            None,
            "Sign-in unavailable",
            "No identity provider is configured.",
            None,
        );
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
        return (
            jar,
            message(
                StatusCode::UNAUTHORIZED,
                None,
                "Sign-in failed",
                "The identity provider refused the sign-in.",
                Some(err),
            ),
        )
            .into_response();
    }
    let (Some(code), Some(returned)) = (q.code, q.state) else {
        return (jar, message(StatusCode::BAD_REQUEST, None, "Sign-in failed", "The callback was incomplete.", None))
            .into_response();
    };
    let login = match auth.complete(&saved.state, &returned, &code).await {
        Ok(l) => l,
        Err(e) => {
            warn!(error = %e, "completing login failed");
            return (
                jar,
                message(StatusCode::UNAUTHORIZED, None, "Sign-in failed", "The sign-in could not be verified.", None),
            )
                .into_response();
        }
    };
    let rules = state.engine.rules();
    let Some(approver) = rules.approvers.values().find(|a| a.identities.contains(&login.identity)) else {
        info!(identity = %login.identity, "sign-in by an identity that is not an approver");
        return (
            jar,
            message(
                StatusCode::FORBIDDEN,
                None,
                "Not an approver",
                "You signed in, but this identity is not listed as an approver. An administrator can add it:",
                Some(login.identity),
            ),
        )
            .into_response();
    };
    let data = SessionData {
        approver: approver.id.to_string(),
        identity: login.identity,
        auth_time: login.auth_time.map(Timestamp::as_second),
        issued: now.as_second(),
        csrf: random_token(),
    };
    let Ok(value) = serde_json::to_string(&data) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    };
    info!(approver = %approver.id, "signed in");
    let jar = jar.add(cookie(SESSION_COOKIE, value, state.settings.secure_cookies));
    (jar, Redirect::to(&safe_next(Some(&saved.next)))).into_response()
}

async fn logout(State(state): State<AppState>, jar: PrivateCookieJar, Form(form): Form<CsrfForm>) -> Response {
    match current_session(&state, &jar, Timestamp::now()) {
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

// Handlers return the error response as is; boxing it buys nothing here.
#[allow(clippy::result_large_err)]
fn api_session(state: &AppState, jar: &PrivateCookieJar) -> Result<Session, Response> {
    current_session(state, jar, Timestamp::now())
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "unauthenticated", "sign in first"))
}

#[derive(Debug, Serialize)]
struct Me {
    approver: String,
    csrf: String,
    assurance: Assurance,
    fresh_until: Option<Timestamp>,
}

async fn api_me(State(state): State<AppState>, jar: PrivateCookieJar) -> Response {
    match api_session(&state, &jar) {
        Ok(s) => Json(Me {
            approver: s.approver.id.to_string(),
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

async fn api_list(State(state): State<AppState>, jar: PrivateCookieJar, Query(q): Query<ListQuery>) -> Response {
    if let Err(r) = api_session(&state, &jar) {
        return r;
    }
    let filter = RequestFilter {
        open_only: q.open.as_deref().is_some_and(|v| v == "1" || v == "true"),
        limit: Some(q.limit.unwrap_or(100).min(500)),
    };
    match state.engine.store().list_requests(&filter).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store", e.to_string()),
    }
}

async fn api_get(State(state): State<AppState>, jar: PrivateCookieJar, Path(id): Path<String>) -> Response {
    if let Err(r) = api_session(&state, &jar) {
        return r;
    }
    let Ok(id) = id.parse::<RequestId>() else {
        return api_error(StatusCode::NOT_FOUND, "not_found", "no such request");
    };
    match state.engine.store().get_request(id).await {
        Ok(Some(r)) => Json(r).into_response(),
        Ok(None) => api_error(StatusCode::NOT_FOUND, "not_found", "no such request"),
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
    let session = match api_session(&state, &jar) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let token = headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok()).unwrap_or_default();
    if !same(token, &session.data.csrf) {
        return api_error(StatusCode::FORBIDDEN, "csrf", "missing or wrong x-csrf-token header");
    }
    let Ok(id) = id.parse::<RequestId>() else {
        return api_error(StatusCode::NOT_FOUND, "not_found", "no such request");
    };
    let intent = ActionIntent {
        request_id: id,
        verdict: body.verdict,
        approver: session.approver.id.clone(),
        assurance: session.assurance(now, state.settings.fresh_auth_window),
        via: "web".into(),
        comment: clean_comment(body.comment),
    };
    match state.engine.decide(intent, now).await {
        Ok(r) => Json(r).into_response(),
        Err(EngineError::Transition(e @ TransitionError::InsufficientAssurance { .. })) => (
            StatusCode::UNAUTHORIZED,
            Json(ApiError {
                error: "fresh_auth_required",
                message: e.to_string(),
                login: Some(login_url(&format!("/requests/{id}"), true)),
            }),
        )
            .into_response(),
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
    fn formats_durations() {
        assert_eq!(fmt_duration(Duration::from_secs(45)), "45s");
        assert_eq!(fmt_duration(Duration::from_secs(1800)), "30m");
        assert_eq!(fmt_duration(Duration::from_secs(7200)), "2h");
        assert_eq!(fmt_duration(Duration::from_secs(5400)), "1h 30m");
        assert_eq!(fmt_duration(Duration::from_secs(90)), "1m 30s");
    }

    #[test]
    fn freshness_window() {
        let s = Session {
            approver: Approver {
                id: "a".into(),
                display_name: None,
                groups: std::collections::BTreeSet::default(),
                identities: std::collections::BTreeSet::default(),
            },
            data: SessionData {
                approver: "a".into(),
                identity: "i".into(),
                auth_time: Some(1000),
                issued: 1000,
                csrf: "c".into(),
            },
        };
        let w = Duration::from_secs(300);
        let at = |s| Timestamp::from_second(s).unwrap();
        assert_eq!(s.assurance(at(1300), w), Assurance::FreshAuth);
        assert_eq!(s.assurance(at(1301), w), Assurance::Web);
        let none = Session { data: SessionData { auth_time: None, ..s.data.clone() }, ..s };
        assert_eq!(none.assurance(at(1000), w), Assurance::Web);
    }
}
