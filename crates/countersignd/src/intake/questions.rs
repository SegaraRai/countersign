//! Structured question intake endpoints (`/intake/v1/questions`).

use std::collections::BTreeMap;
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use countersign_core::{AnswerError, Asker, Confidentiality, Question, QuestionOutcome};

use super::{ApiError, IntakeState, MAX_WAIT, Peer, RECHECK, WaitQuery, error, internal, peer_addr};
use crate::config::{ClientConfig, Scope};
use crate::engine::{Ask, EngineError};

/// Largest body accepted for a question.
pub(super) const MAX_QUESTION_BODY: usize = 64 * 1024;

/// A question as a client asks it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AskBody {
    pub message: String,
    /// The MCP elicitation `requestedSchema` subset.
    pub requested_schema: Value,
    /// Extra facts shown to responders.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub context: BTreeMap<String, String>,
    #[serde(default)]
    pub confidentiality: Confidentiality,
}

/// What the asking client sees.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct QuestionBody {
    pub id: String,
    pub url: String,
    /// `pending`, `answered`, `declined`, `expired` or `withdrawn`.
    pub state: String,
    /// The MCP view: `accept`, `decline` or `cancel`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answered_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answered_at: Option<Timestamp>,
    /// The responder marked the answer confidential: it is given out once
    /// and then removed.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub confidential: bool,
    /// The confidential answer was already read or has run out.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub content_removed: bool,
    /// A responder's note when declining.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

fn question_body(state: &IntakeState, q: &Question) -> QuestionBody {
    let mut b = QuestionBody {
        id: q.id.to_string(),
        url: state.url(q.id),
        state: q.state().to_owned(),
        action: q.mcp_action().map(str::to_owned),
        ..QuestionBody::default()
    };
    match &q.outcome {
        Some(QuestionOutcome::Accepted { by, at, content, confidential, .. }) => {
            b.answered_by = Some(by.to_string());
            b.answered_at = Some(*at);
            b.confidential = *confidential;
            b.content_removed = content.is_none();
            b.content.clone_from(content);
        }
        Some(QuestionOutcome::Declined { by, at, note, .. }) => {
            b.answered_by = Some(by.to_string());
            b.answered_at = Some(*at);
            b.note.clone_from(note);
        }
        _ => {}
    }
    b
}

fn question_error(e: EngineError) -> ApiError {
    match e {
        EngineError::Invalid(m) => error(StatusCode::BAD_REQUEST, "bad-request", m),
        EngineError::Refused(m) if m.starts_with("too many") => {
            error(StatusCode::TOO_MANY_REQUESTS, "too-many-pending", m)
        }
        EngineError::Refused(m) => error(StatusCode::FORBIDDEN, "no-policy", m),
        EngineError::Forbidden(m) => error(StatusCode::FORBIDDEN, "forbidden", m),
        EngineError::Answer(AnswerError::NotPending(s)) => {
            error(StatusCode::CONFLICT, "conflict", format!("the question is {s}"))
        }
        EngineError::UnknownQuestion(_) => error(StatusCode::NOT_FOUND, "not-found", "no such question"),
        e => internal(&e),
    }
}

pub(super) async fn ask(
    State(state): State<IntakeState>,
    peer: Peer,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let (client, _) = state.authenticate(&headers, peer_addr(peer), Scope::Question).await?;
    if body.len() > MAX_QUESTION_BODY {
        return Err(error(StatusCode::PAYLOAD_TOO_LARGE, "too-large", "the question is too large"));
    }
    let body: AskBody = serde_json::from_slice(&body)
        .map_err(|e| error(StatusCode::BAD_REQUEST, "bad-request", format!("invalid request body: {e}")))?;
    let q = ask_as(&state, &client, body).await?;
    Ok((StatusCode::CREATED, Json(question_body(&state, &q))).into_response())
}

/// Ask a question on behalf of an authenticated client.
pub(super) async fn ask_as(state: &IntakeState, client: &ClientConfig, body: AskBody) -> Result<Question, ApiError> {
    let ask = Ask {
        asker: Asker { client: client.id.clone(), actor: client.actor.clone() },
        message: body.message,
        schema: body.requested_schema,
        context: body.context,
        confidentiality: body.confidentiality,
    };
    state.engine.ask(ask, Timestamp::now()).await.map_err(question_error)
}

/// The client's question as it stands, waiting up to `wait` while it is
/// pending. Reading a decided question hands over (and for a confidential
/// answer, uses up) the answer.
pub(super) async fn wait_for_answer(
    state: &IntakeState,
    client: &ClientConfig,
    raw: &str,
    wait: Duration,
) -> Result<QuestionBody, ApiError> {
    let deadline = tokio::time::Instant::now() + wait.min(MAX_WAIT);
    let mut changes = state.engine.subscribe();
    loop {
        changes.borrow_and_update();
        let q = state.owned_question(client, raw).await?;
        if q.is_pending() {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Ok(question_body(state, &q));
            }
            let _ = tokio::time::timeout_at(deadline.min(now + RECHECK), changes.changed()).await;
            continue;
        }
        let q = state.engine.read_question(q.id, &client.id, Timestamp::now()).await.map_err(question_error)?;
        return Ok(question_body(state, &q));
    }
}

/// Withdraw the client's pending question.
pub(super) async fn withdraw_as(state: &IntakeState, client: &ClientConfig, raw: &str) -> Result<(), ApiError> {
    let q = state.owned_question(client, raw).await?;
    state.engine.withdraw_question(q.id, Some(&client.id), Timestamp::now()).await.map_err(question_error)?;
    Ok(())
}

pub(super) async fn question_status(
    State(state): State<IntakeState>,
    peer: Peer,
    headers: HeaderMap,
    Path(raw): Path<String>,
    Query(w): Query<WaitQuery>,
) -> Result<Json<QuestionBody>, ApiError> {
    let (client, _) = state.authenticate(&headers, peer_addr(peer), Scope::Question).await?;
    Ok(Json(wait_for_answer(&state, &client, &raw, Duration::from_secs(w.wait)).await?))
}

pub(super) async fn withdraw_question(
    State(state): State<IntakeState>,
    peer: Peer,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Result<StatusCode, ApiError> {
    let (client, _) = state.authenticate(&headers, peer_addr(peer), Scope::Question).await?;
    withdraw_as(&state, &client, &raw).await?;
    Ok(StatusCode::NO_CONTENT)
}
