//! The JSON API for scripts and other front ends, on the session cookie and
//! the `x-csrf-token` header.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::PrivateCookieJar;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use countersign_core::{
    ActionIntent, AnswerError, AnswerIntent, Assurance, Question, RequestFilter, RequestId, Response as Reply,
    TransitionError, Verdict,
};

use super::session::{
    Session, current_session, login_url, question_access, redacted, same, sees_approval, sees_question,
};
use super::{AppState, clean_comment, human_error};
use crate::engine::EngineError;

const CSRF_HEADER: &str = "x-csrf-token";

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

pub(super) async fn me(State(state): State<AppState>, jar: PrivateCookieJar) -> Response {
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
pub(super) struct ListQuery {
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

pub(super) async fn list(State(state): State<AppState>, jar: PrivateCookieJar, Query(q): Query<ListQuery>) -> Response {
    let s = match api_session(&state, &jar).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    match state.engine.store().list_requests(&q.filter()).await {
        Ok(list) => {
            let roster = s.roster(Timestamp::now());
            Json(list.into_iter().filter(|r| sees_approval(&roster, &s, r)).collect::<Vec<_>>()).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "listing requests failed");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "store", "internal error")
        }
    }
}

pub(super) async fn get(State(state): State<AppState>, jar: PrivateCookieJar, Path(id): Path<String>) -> Response {
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
        Err(e) => {
            tracing::error!(error = %e, "listing requests failed");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "store", "internal error")
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct ApiDecision {
    verdict: Verdict,
    #[serde(default)]
    comment: Option<String>,
}

pub(super) async fn decide(
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

pub(super) async fn questions(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Query(q): Query<ListQuery>,
) -> Response {
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
        Err(e) => {
            tracing::error!(error = %e, "listing requests failed");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "store", "internal error")
        }
    }
}

pub(super) async fn question(State(state): State<AppState>, jar: PrivateCookieJar, Path(id): Path<String>) -> Response {
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
        Err(e) => {
            tracing::error!(error = %e, "listing requests failed");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "store", "internal error")
        }
    }
}

pub(super) async fn answer(
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
        // The responder wrote the answer; they may see it back.
        Ok(q) => Json(redacted(&q, (true, true))).into_response(),
        Err(EngineError::Answer(e @ AnswerError::InsufficientAssurance { .. })) => {
            fresh_auth_required(id, e.to_string())
        }
        Err(e) => {
            let (status, msg) = human_error(&e);
            api_error(status, "rejected", msg)
        }
    }
}

#[derive(Debug, Serialize)]
struct PushSubscriptionSummary {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    created_at: Timestamp,
}

#[derive(Debug, Serialize)]
struct PushConfigResponse {
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    vapid_public_key: Option<String>,
    subscriptions: Vec<PushSubscriptionSummary>,
}

pub(super) async fn push_config(State(state): State<AppState>, jar: PrivateCookieJar) -> Response {
    let session = match api_session(&state, &jar).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let Some(vapid_public_key) = state.vapid_public_key.clone() else {
        return Json(PushConfigResponse { enabled: false, vapid_public_key: None, subscriptions: Vec::new() })
            .into_response();
    };
    match state.engine.store().list_push_subscriptions(Some(&session.person)).await {
        Ok(list) => Json(PushConfigResponse {
            enabled: true,
            vapid_public_key: Some(vapid_public_key),
            subscriptions: list
                .into_iter()
                .map(|s| PushSubscriptionSummary { id: s.id, label: s.label, created_at: s.created_at })
                .collect(),
        })
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "listing push subscriptions failed");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "store", "internal error")
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct SubscribeBody {
    endpoint: String,
    keys: SubscribeKeys,
    #[serde(default)]
    label: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SubscribeKeys {
    p256dh: String,
    auth: String,
}

pub(super) async fn push_subscribe(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    headers: HeaderMap,
    Json(body): Json<SubscribeBody>,
) -> Response {
    let session = match api_session(&state, &jar).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = api_csrf(&headers, &session) {
        return r;
    }
    if state.vapid_public_key.is_none() {
        return api_error(StatusCode::NOT_FOUND, "disabled", "web push is not enabled");
    }
    let endpoint = body.endpoint.trim();
    if !endpoint.starts_with("https://") || endpoint.len() > 2048 || endpoint.contains('@') {
        return api_error(StatusCode::BAD_REQUEST, "invalid_endpoint", "push endpoint must be a valid https:// URL");
    }
    if body.keys.p256dh.len() > 256 || body.keys.auth.len() > 128 {
        return api_error(StatusCode::BAD_REQUEST, "invalid_keys", "push subscription keys are invalid");
    }
    let label =
        body.label.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(|s| s.chars().take(100).collect::<String>());
    let sub = countersign_core::PushSubscription {
        id: uuid::Uuid::new_v4().to_string(),
        person: session.person.clone(),
        endpoint: endpoint.to_owned(),
        p256dh: body.keys.p256dh.trim().to_owned(),
        auth: body.keys.auth.trim().to_owned(),
        label,
        created_at: Timestamp::now(),
    };
    match state.engine.store().save_push_subscription(&sub).await {
        Ok(()) => (
            StatusCode::CREATED,
            Json(PushSubscriptionSummary { id: sub.id, label: sub.label, created_at: sub.created_at }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "saving push subscription failed");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "store", "internal error")
        }
    }
}

pub(super) async fn push_unsubscribe(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let session = match api_session(&state, &jar).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = api_csrf(&headers, &session) {
        return r;
    }
    match state.engine.store().delete_push_subscription_for_person(&session.person, &id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => api_error(StatusCode::NOT_FOUND, "not_found", "no such subscription"),
        Err(e) => {
            tracing::error!(error = %e, "deleting push subscription failed");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "store", "internal error")
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct BreakGlassBody {
    reason: String,
}

pub(super) async fn break_glass(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<BreakGlassBody>,
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
    let assurance = session.assurance(now, state.settings.fresh_auth_window);
    match state.engine.break_glass(id, &session.person, assurance, "web".into(), &body.reason, now).await {
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
