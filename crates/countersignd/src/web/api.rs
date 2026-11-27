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
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store", e.to_string()),
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
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store", e.to_string()),
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
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store", e.to_string()),
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
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store", e.to_string()),
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
