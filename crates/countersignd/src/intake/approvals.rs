//! Approval intake endpoints (`/intake/v1/requests` and `/intake/v1/server-key`).

use std::collections::BTreeMap;
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use countersign_core::approval_signing::{self, Approval};
use countersign_core::{
    Action, BackendName, ClientId, GrantMode, PendingSubject, Purpose, Request, RequestFilter, RequestState, Requester,
    Source, SubjectFacts, SubjectRef, TransitionError, host_key, text,
};

use super::{ApiError, IntakeState, MAX_WAIT, Peer, RECHECK, WaitQuery, error, internal, peer_addr};
use crate::config::{ClientConfig, Scope};
use crate::engine::{EngineError, Submitted};

/// Subject kind for `sudo` invocations.
pub const KIND_SUDO: &str = "sudo";
/// The longest command (as shown) approvers are asked about. Chat
/// channels can show this much in full.
pub const MAX_COMMAND_CHARS: usize = 3000;

const MAX_ARGV_BYTES: usize = 8 * 1024;
const MAX_FIELD: usize = 1024;
const MAX_REASON: usize = 500;

/// What the submitting client sees.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusBody {
    pub id: String,
    /// `pending`, `approved`, `denied`, `expired`, `withdrawn`, `revoked` or `ended`.
    pub state: String,
    pub url: String,
    /// When the approval this answer relies on ends, if approved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<Timestamp>,
    /// With `approved`: countersign's signature over the request, the
    /// client, the submission's invocation digest and its nonce (see
    /// [`countersign_core::approval_signing`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// A submission as sent by the helper on the host.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubmitBody {
    /// The OS user running `sudo`.
    pub user: String,
    /// The whole `sudo` command line as `sudo` received it, starting with
    /// `sudo` or `sudoedit`. Shown to approvers as it is; countersign reads
    /// who it runs as and which command it is from it.
    pub sudo_argv: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tty: Option<String>,
    /// Free text from the requester. Displayed, never trusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Keep the details out of chat channels (the policy decides whether
    /// this is honoured). The record keeps everything.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sensitive: bool,
    /// Fresh random value (16–64 bytes, base64url) the approval signature
    /// is bound to.
    pub nonce: String,
}

/// The requester identity a client may name for an OS user.
pub fn unix_identity(client: &ClientId, user: &str) -> String {
    format!("unix:{client}#{user}")
}

/// OS user names: ASCII letters, digits, `-`, `_` and `.`.
fn is_name(s: &str) -> bool {
    countersign_core::actor::is_name(s)
}

/// The state as the client should act on it: only `approved` lets the
/// command run.
fn host_state(r: &Request) -> &'static str {
    match &r.state {
        RequestState::Pending | RequestState::Approved => "pending",
        RequestState::Active { .. } => "approved",
        // A collected single-use approval stays approved for its requester
        // (who may ask again if the first answer was lost). One that ran out
        // before it was collected was never used and must not be.
        RequestState::Ended if r.collected_at.is_some() => "approved",
        RequestState::Ended if r.requirements.grant == GrantMode::Once => "expired",
        RequestState::Ended => "ended",
        RequestState::Denied | RequestState::Failed { .. } => "denied",
        RequestState::Expired => "expired",
        RequestState::Withdrawn => "withdrawn",
        RequestState::Revoked => "revoked",
    }
}

/// Write out control and other hidden characters (see
/// [`countersign_core::text`]) so values cannot disturb terminals or logs or
/// look different from what they are, and cap the length.
fn clean(s: &str, max: usize) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if out.len() >= max {
            out.push('…');
            break;
        }
        if countersign_core::text::is_hidden(c) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

impl IntakeState {
    /// What the client sees, signed if it says `approved`. `binding` is the
    /// submission the answer is for (`<invocation digest>:<nonce>`); without
    /// one an approval is not signed and the client will not act on it.
    fn status_body(&self, r: &Request, client: &ClientConfig, binding: Option<&str>) -> StatusBody {
        let state = host_state(r);
        let signature = (state == "approved").then_some(binding).flatten().and_then(|b| b.split_once(':')).map(
            |(invocation, nonce)| {
                let id = r.id.to_string();
                let key = client
                    .auth
                    .host_key()
                    .and_then(|k| k.strip_prefix(host_key::REFERENCE_PREFIX))
                    .unwrap_or(client.id.as_str());
                self.signing.sign(&Approval { request: &id, client: key, invocation, nonce })
            },
        );
        StatusBody {
            id: r.id.to_string(),
            state: state.to_owned(),
            url: self.url(r.id),
            until: match r.state {
                RequestState::Active { until } => Some(until),
                _ => None,
            },
            signature,
        }
    }
}

fn pending_subject(client: &ClientConfig, backend: BackendName, body: SubmitBody) -> Result<PendingSubject, ApiError> {
    let bad = |m: &str| error(StatusCode::BAD_REQUEST, "bad-request", m);
    if !is_name(&body.user) {
        return Err(bad("invalid user"));
    }
    if !matches!(body.sudo_argv.first().map(String::as_str), Some("sudo" | "sudoedit")) || body.sudo_argv.len() < 2 {
        return Err(bad("sudo_argv must be a sudo command line"));
    }
    if body.sudo_argv.iter().map(String::len).sum::<usize>() > MAX_ARGV_BYTES {
        return Err(bad("sudo_argv is too long"));
    }
    if !approval_signing::is_nonce(&body.nonce) {
        return Err(bad("nonce must be 16 to 64 random bytes in base64url"));
    }
    // Of the raw values, before anything is cleaned for display.
    let binding = format!(
        "{}:{}",
        approval_signing::invocation_digest(&body.user, body.cwd.as_deref(), &body.sudo_argv),
        body.nonce
    );
    if text::shell_join(&body.sudo_argv).chars().count() > MAX_COMMAND_CHARS {
        return Err(bad("the command is too long to show to approvers"));
    }
    let parsed = countersign_core::sudo::parse(&body.sudo_argv);
    let runas = parsed.runas.unwrap_or_else(|| "root".to_owned());
    if !is_name(&runas) {
        return Err(bad("invalid user to run as"));
    }
    let command = text::shell_join(&parsed.command);
    let cwd = body.cwd.filter(|s| !s.is_empty()).map(|c| clean(&c, MAX_FIELD));

    let host = client.id.to_string();
    let mut attributes = BTreeMap::from([
        ("host".to_owned(), host.clone()),
        ("user".to_owned(), body.user.clone()),
        ("runas".to_owned(), runas.clone()),
        ("command".to_owned(), command),
    ]);
    if let Some(cwd) = &cwd {
        attributes.insert("cwd".to_owned(), cwd.clone());
    }
    if let Some(tty) = body.tty.filter(|s| !s.is_empty()) {
        attributes.insert("tty".to_owned(), clean(&tty, MAX_FIELD));
    }

    let mut facts = SubjectFacts::new(Requester {
        id: body.user.clone(),
        display_name: Some(format!("{}@{host}", body.user)),
        identity: unix_identity(&client.id, &body.user),
        ..Requester::default()
    });
    facts.source = Some(Source::Client(client.id.clone()));
    facts.target = Some(host);
    facts.reason = body.reason.map(|r| clean(r.trim(), MAX_REASON)).filter(|r| !r.is_empty());
    facts.attributes = attributes;
    facts.action =
        Some(Action::Command { line: body.sudo_argv, runas, cwd, notes: parsed.uninterpreted.into_iter().collect() });
    facts.sensitive = body.sensitive;
    facts.binding = Some(binding);
    Ok(PendingSubject {
        subject: SubjectRef { backend, kind: KIND_SUDO.to_owned(), id: uuid::Uuid::new_v4().to_string() },
        facts,
        observed_at: Timestamp::now(),
    })
}

fn unknown_user(client: &ClientConfig, user: &str) -> ApiError {
    tracing::warn!(client = %client.id, user = %clean(user, 64), "submission for a user that is not an active workload or person");
    error(StatusCode::FORBIDDEN, "unknown-user", "this user may not submit requests")
}

pub(super) async fn submit(
    State(state): State<IntakeState>,
    peer: Peer,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    // Authenticate before looking at the body.
    let (client, verified_oidc) = state.authenticate(&headers, peer_addr(peer), Scope::Approval).await?;
    let body: SubmitBody = serde_json::from_slice(&body)
        .map_err(|e| error(StatusCode::BAD_REQUEST, "bad-request", format!("invalid request body: {e}")))?;
    let Some(backend) = client.backend.clone() else {
        return Err(internal(&"approval client without a host backend"));
    };

    // Only OS users that are configured actors may ask.
    let rules = state.engine.rules();
    if rules.directory.by_identity(&unix_identity(&client.id, &body.user), Purpose::Recognition).is_none() {
        return Err(unknown_user(&client, &body.user));
    }
    let user = body.user.clone();
    let mut p = pending_subject(&client, backend, body)?;
    if let Some(initiator) = verified_oidc.and_then(|v| v.initiator) {
        p.facts.initiator = Some(countersign_core::Initiator { identity: initiator, actor: None, display_name: None });
    }
    let binding = p.facts.binding.clone();

    // Bound how many undecided requests one client can pile up.
    let open = state
        .engine
        .store()
        .list_requests(&RequestFilter { open_only: true, limit: None })
        .await
        .map_err(|e| internal(&e))?;
    let source = Some(Source::Client(client.id.clone()));
    let waiting = open.iter().filter(|r| r.state.is_pending() && r.facts.source == source).count();
    if waiting >= state.max_pending {
        return Err(error(
            StatusCode::TOO_MANY_REQUESTS,
            "too-many-pending",
            "too many requests are waiting for approval",
        ));
    }

    match state.engine.submit(p, Timestamp::now()).await.map_err(|e| internal(&e))? {
        Submitted::Opened(r) => {
            Ok((StatusCode::CREATED, Json(state.status_body(&r, &client, binding.as_deref()))).into_response())
        }
        // An open window covers this submission: the signature is for it,
        // not for the one that opened the window.
        Submitted::Covered(r) => Ok(Json(state.status_body(&r, &client, binding.as_deref())).into_response()),
        Submitted::Unmatched => Err(error(StatusCode::FORBIDDEN, "no-policy", "no policy allows this request")),
        Submitted::Inactive => Err(unknown_user(&client, &user)),
    }
}

/// countersign's approval signing public key, for `countersign-sudo enroll`.
/// Public and unauthenticated: a client must still confirm it out of band.
pub(super) async fn server_key(State(state): State<IntakeState>) -> Json<Value> {
    Json(serde_json::json!({ "server_key": state.signing.public() }))
}

pub(super) async fn status(
    State(state): State<IntakeState>,
    peer: Peer,
    headers: HeaderMap,
    Path(raw): Path<String>,
    Query(q): Query<WaitQuery>,
) -> Result<Json<StatusBody>, ApiError> {
    let (client, _) = state.authenticate(&headers, peer_addr(peer), Scope::Approval).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(q.wait).min(MAX_WAIT);
    let mut changes = state.engine.subscribe();
    loop {
        changes.borrow_and_update();
        let r = state.owned(&client, &raw).await?;
        if host_state(&r) == "pending" {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Ok(Json(state.status_body(&r, &client, r.facts.binding.as_deref())));
            }
            // Wake on changes made by this process, and re-read now and then
            // for changes made elsewhere (e.g. the CLI deciding).
            let _ = tokio::time::timeout_at(deadline.min(now + RECHECK), changes.changed()).await;
            continue;
        }
        if matches!(r.state, RequestState::Active { .. }) && r.requirements.grant == GrantMode::Once {
            // The client has the answer; a single-use approval ends here.
            let r = state.engine.collect(r.id, Timestamp::now()).await.map_err(|e| internal(&e))?;
            return Ok(Json(state.status_body(&r, &client, r.facts.binding.as_deref())));
        }
        return Ok(Json(state.status_body(&r, &client, r.facts.binding.as_deref())));
    }
}

pub(super) async fn withdraw(
    State(state): State<IntakeState>,
    peer: Peer,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Result<StatusCode, ApiError> {
    let (client, _) = state.authenticate(&headers, peer_addr(peer), Scope::Approval).await?;
    let r = state.owned(&client, &raw).await?;
    match state.engine.withdraw(r.id, Timestamp::now()).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(EngineError::Transition(TransitionError::InvalidState { state: s, .. })) => {
            Err(error(StatusCode::CONFLICT, "conflict", format!("the request is {s}")))
        }
        Err(e) => Err(internal(&e)),
    }
}
