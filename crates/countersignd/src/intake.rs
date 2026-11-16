//! Subjects pushed to countersign by target hosts, such as a `sudo`
//! invocation waiting for approval.
//!
//! Hosts authenticate with a per-host key (`Authorization: Bearer <key>`);
//! the configuration holds only its SHA-256. The host name, and so the
//! request's target, comes from the key, never from the request body.
//!
//! ```text
//! POST   /intake/v1/requests        submit; 201 pending, 200 approved by a window, 403 no policy
//! GET    /intake/v1/requests/{id}   state; ?wait=<secs> long-polls while pending
//! DELETE /intake/v1/requests/{id}   withdraw while pending
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use countersign_core::host_key;
use countersign_core::{
    AccessBackend, BackendCaps, BackendError, BackendName, GrantHandle, GrantMode, PendingSubject, Request,
    RequestFilter, RequestId, RequestState, Requester, Store, SubjectFacts, SubjectRef, TransitionError,
};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;

use crate::engine::{Engine, EngineError, Submitted};

/// Subject kind for `sudo` invocations.
pub const KIND_SUDO: &str = "sudo";

const MAX_WAIT: Duration = Duration::from_secs(60);
/// While long-polling, re-read the request at least this often.
const RECHECK: Duration = Duration::from_secs(2);
const MAX_ARGV_BYTES: usize = 8 * 1024;
const MAX_FIELD: usize = 1024;
const MAX_REASON: usize = 500;

/// `[intake]`: where hosts reach countersign.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntakeConfig {
    /// Listen address for hosts. Keep it private (a tailnet address); this
    /// listener speaks plain HTTP.
    pub listen: SocketAddr,
    /// Undecided requests a single host may have at once.
    #[serde(default = "default_max_pending")]
    pub max_pending_per_host: usize,
}

fn default_max_pending() -> usize {
    10
}

/// `[backend.<name>] type = "host"`: hosts that submit `sudo` invocations.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostBackendConfig {
    /// OS users whose submissions are accepted, with the requester groups
    /// they get for policy matching. Others are refused.
    pub users: BTreeMap<String, Vec<String>>,
    #[serde(default, rename = "host")]
    pub hosts: Vec<HostEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostEntry {
    pub name: String,
    /// Lowercase hex SHA-256 of the host's key (`countersign keygen --host`).
    pub key_sha256: String,
    /// If set, requests with this key must come from one of these addresses.
    #[serde(default)]
    pub allowed_ips: Vec<IpAddr>,
}

impl HostBackendConfig {
    /// Problems with this backend's settings, for the configuration check.
    pub fn problems(&self, backend: &BackendName) -> Vec<String> {
        let mut errors = Vec::new();
        if self.users.is_empty() {
            errors.push(format!("backend {backend}: users must list at least one OS user"));
        }
        for user in self.users.keys() {
            if !is_name(user) {
                errors.push(format!("backend {backend}: invalid user name {user:?}"));
            }
        }
        let mut names = BTreeSet::new();
        for h in &self.hosts {
            if !is_name(&h.name) {
                errors.push(format!("backend {backend}: invalid host name {:?}", h.name));
            }
            if !names.insert(&h.name) {
                errors.push(format!("backend {backend}: duplicate host {}", h.name));
            }
            if host_key::parse_digest_hex(&h.key_sha256).is_none() {
                errors.push(format!("backend {backend}: host {}: key_sha256 must be 64 hex digits", h.name));
            }
        }
        errors
    }
}

/// Host, user and group names: ASCII letters, digits, `-`, `_` and `.`.
fn is_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with(['-', '.'])
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// A backend for subjects that hosts submit. It holds no state of its own:
/// the stored request is the record, and hosts read the outcome through the
/// intake API.
pub struct HostBackend {
    name: BackendName,
    store: Arc<dyn Store>,
}

impl std::fmt::Debug for HostBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostBackend").field("name", &self.name).finish_non_exhaustive()
    }
}

impl HostBackend {
    pub fn new(name: BackendName, store: Arc<dyn Store>) -> Self {
        Self { name, store }
    }
}

#[async_trait]
impl AccessBackend for HostBackend {
    fn name(&self) -> &BackendName {
        &self.name
    }

    fn capabilities(&self) -> BackendCaps {
        BackendCaps { discover: false, revoke: true, native_expiry: true }
    }

    async fn discover_pending(&self) -> Result<Vec<PendingSubject>, BackendError> {
        Ok(Vec::new())
    }

    /// The facts recorded when the authenticated host submitted the subject.
    async fn verify(&self, subject: &SubjectRef) -> Result<SubjectFacts, BackendError> {
        if subject.backend != self.name {
            return Err(BackendError::NotFound);
        }
        match self.store.find_latest_by_subject(subject).await {
            Ok(Some(r)) => Ok(r.facts),
            Ok(None) => Err(BackendError::NotFound),
            Err(e) => Err(BackendError::Unavailable(e.to_string())),
        }
    }

    async fn grant(&self, subject: &SubjectRef, _: Duration) -> Result<GrantHandle, BackendError> {
        Ok(GrantHandle { subject: subject.clone(), backend_ref: None, expires_at: None })
    }

    async fn deny(&self, _: &SubjectRef) -> Result<(), BackendError> {
        Ok(())
    }

    async fn revoke(&self, _: &GrantHandle) -> Result<(), BackendError> {
        Ok(())
    }
}

#[derive(Debug)]
struct HostIdentity {
    backend: BackendName,
    host: String,
    allowed_ips: Vec<IpAddr>,
}

/// Everything the intake API needs.
#[derive(Clone)]
pub struct IntakeState {
    engine: Arc<Engine>,
    /// Key hash → host.
    hosts: Arc<Vec<([u8; 32], HostIdentity)>>,
    /// Backend → OS user → requester groups.
    users: Arc<BTreeMap<BackendName, BTreeMap<String, Vec<String>>>>,
    public_url: Arc<str>,
    max_pending: usize,
}

impl std::fmt::Debug for IntakeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntakeState").field("hosts", &self.hosts.len()).finish_non_exhaustive()
    }
}

impl IntakeState {
    /// `backends` are the `host` backends by name.
    pub fn new(
        engine: Arc<Engine>,
        backends: &BTreeMap<BackendName, HostBackendConfig>,
        intake: &IntakeConfig,
        public_url: &str,
    ) -> Self {
        let mut hosts = Vec::new();
        let mut users = BTreeMap::new();
        for (name, c) in backends {
            users.insert(name.clone(), c.users.clone());
            for h in &c.hosts {
                // Validated with the configuration.
                let Some(digest) = host_key::parse_digest_hex(&h.key_sha256) else { continue };
                hosts.push((
                    digest,
                    HostIdentity { backend: name.clone(), host: h.name.clone(), allowed_ips: h.allowed_ips.clone() },
                ));
            }
        }
        Self {
            engine,
            hosts: Arc::new(hosts),
            users: Arc::new(users),
            public_url: public_url.trim_end_matches('/').into(),
            max_pending: intake.max_pending_per_host,
        }
    }

    fn url(&self, id: RequestId) -> String {
        format!("{}/requests/{id}", self.public_url)
    }

    fn authenticate(&self, headers: &HeaderMap, peer: Option<SocketAddr>) -> Result<&HostIdentity, ApiError> {
        let key = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim)
            .filter(|k| !k.is_empty())
            .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "unauthorized", "missing host key"))?;
        // A malformed key gets the same answer as a wrong one, and is never
        // hashed. Every configured digest is compared in constant time.
        let found = host_key::is_well_formed(key).then(|| host_key::digest(key)).and_then(|digest| {
            self.hosts.iter().fold(None, |found, (d, id)| if bool::from(d.ct_eq(&digest)) { Some(id) } else { found })
        });
        let Some(id) = found else {
            tracing::warn!(peer = ?peer, "intake request with an unknown host key");
            return Err(error(StatusCode::UNAUTHORIZED, "unauthorized", "unknown host key"));
        };
        if !id.allowed_ips.is_empty() && !peer.is_some_and(|p| id.allowed_ips.contains(&p.ip())) {
            tracing::warn!(host = %id.host, peer = ?peer, "host key used from an address that is not allowed");
            return Err(error(StatusCode::UNAUTHORIZED, "unauthorized", "address not allowed for this host"));
        }
        Ok(id)
    }

    /// The request, if it exists and belongs to this host.
    async fn owned(&self, id: &HostIdentity, raw: &str) -> Result<Request, ApiError> {
        let not_found = || error(StatusCode::NOT_FOUND, "not-found", "no such request");
        let rid: RequestId = raw.parse().map_err(|_| not_found())?;
        let r = self.engine.store().get_request(rid).await.map_err(|e| internal(&e))?.ok_or_else(not_found)?;
        if r.subject.backend == id.backend && r.facts.target.as_deref() == Some(id.host.as_str()) {
            Ok(r)
        } else {
            Err(not_found())
        }
    }
}

pub fn router(state: IntakeState) -> Router {
    Router::new()
        .route("/intake/v1/requests", post(submit))
        .route("/intake/v1/requests/{id}", get(status).delete(withdraw))
        .with_state(state)
}

type Peer = Option<Extension<ConnectInfo<SocketAddr>>>;

fn peer_addr(p: Peer) -> Option<SocketAddr> {
    p.map(|Extension(ConnectInfo(a))| a)
}

/// An error answer: `{"error": <code>, "message": <text>}`.
#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

#[derive(Debug, Serialize)]
struct ErrorBody<'a> {
    error: &'static str,
    message: &'a str,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(ErrorBody { error: self.code, message: &self.message })).into_response()
    }
}

fn error(status: StatusCode, code: &'static str, message: impl Into<String>) -> ApiError {
    ApiError { status, code, message: message.into() }
}

fn internal(e: &dyn std::fmt::Display) -> ApiError {
    tracing::error!(error = %e, "intake request failed");
    error(StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal error")
}

/// What the submitting host sees.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusBody {
    pub id: String,
    /// `pending`, `approved`, `denied`, `expired`, `withdrawn`, `revoked` or `ended`.
    pub state: String,
    pub url: String,
    /// When the approval this answer relies on ends, if approved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<Timestamp>,
}

/// The state as the host should act on it: only `approved` lets the
/// command run.
fn host_state(r: &Request) -> &'static str {
    match &r.state {
        RequestState::Pending | RequestState::Approved => "pending",
        RequestState::Active { .. } => "approved",
        // A collected single-use approval stays approved for its requester.
        RequestState::Ended if r.requirements.grant == GrantMode::Once => "approved",
        RequestState::Ended => "ended",
        RequestState::Denied | RequestState::Failed { .. } => "denied",
        RequestState::Expired => "expired",
        RequestState::Withdrawn => "withdrawn",
        RequestState::Revoked => "revoked",
    }
}

fn status_body(state: &IntakeState, r: &Request) -> StatusBody {
    StatusBody {
        id: r.id.to_string(),
        state: host_state(r).to_owned(),
        url: state.url(r.id),
        until: match r.state {
            RequestState::Active { until } => Some(until),
            _ => None,
        },
    }
}

/// A submission as sent by the helper on the host.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubmitBody {
    /// The OS user running `sudo`.
    pub user: String,
    /// The user the command runs as. Defaults to `root`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runas: Option<String>,
    /// The command and its arguments.
    pub argv: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tty: Option<String>,
    /// Free text from the requester. Displayed, never trusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Replace control characters so values cannot disturb terminals or logs,
/// and cap the length.
fn clean(s: &str, max: usize) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if out.len() >= max {
            out.push('…');
            break;
        }
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// Join argv for display and policy matching, quoting like a POSIX shell
/// where needed.
pub fn shell_join(argv: &[String]) -> String {
    let safe = |a: &str| !a.is_empty() && a.bytes().all(|b| b.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&b));
    argv.iter()
        .map(|a| if safe(a) { a.clone() } else { format!("'{}'", a.replace('\'', r"'\''")) })
        .collect::<Vec<_>>()
        .join(" ")
}

fn pending_subject(id: &HostIdentity, groups: &[String], body: SubmitBody) -> Result<PendingSubject, ApiError> {
    let bad = |m: &str| error(StatusCode::BAD_REQUEST, "bad-request", m);
    if body.argv.is_empty() || body.argv[0].is_empty() {
        return Err(bad("argv must name a command"));
    }
    if body.argv.iter().map(String::len).sum::<usize>() > MAX_ARGV_BYTES {
        return Err(bad("argv is too long"));
    }
    let runas = body.runas.unwrap_or_else(|| "root".to_owned());
    if !is_name(&runas) {
        return Err(bad("invalid runas"));
    }
    let argv: Vec<String> = body.argv.iter().map(|a| clean(a, MAX_ARGV_BYTES)).collect();

    let mut attributes = BTreeMap::from([
        ("host".to_owned(), id.host.clone()),
        ("user".to_owned(), body.user.clone()),
        ("runas".to_owned(), runas),
        ("command".to_owned(), shell_join(&argv)),
    ]);
    if let Some(cwd) = body.cwd.filter(|s| !s.is_empty()) {
        attributes.insert("cwd".to_owned(), clean(&cwd, MAX_FIELD));
    }
    if let Some(tty) = body.tty.filter(|s| !s.is_empty()) {
        attributes.insert("tty".to_owned(), clean(&tty, MAX_FIELD));
    }

    Ok(PendingSubject {
        subject: SubjectRef {
            backend: id.backend.clone(),
            kind: KIND_SUDO.to_owned(),
            id: uuid::Uuid::new_v4().to_string(),
        },
        facts: SubjectFacts {
            requester: Requester {
                id: body.user.clone(),
                display_name: Some(format!("{}@{}", body.user, id.host)),
                groups: groups.iter().cloned().collect(),
                identities: BTreeSet::from([format!("host:{}:{}:user:{}", id.backend, id.host, body.user)]),
            },
            target: Some(id.host.clone()),
            requested_ttl: None,
            reason: body.reason.map(|r| clean(r.trim(), MAX_REASON)).filter(|r| !r.is_empty()),
            attributes,
        },
        observed_at: Timestamp::now(),
    })
}

async fn submit(
    State(state): State<IntakeState>,
    peer: Peer,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    // Authenticate before looking at the body.
    let id = state.authenticate(&headers, peer_addr(peer))?;
    let body: SubmitBody = serde_json::from_slice(&body)
        .map_err(|e| error(StatusCode::BAD_REQUEST, "bad-request", format!("invalid request body: {e}")))?;
    let Some(groups) = state.users.get(&id.backend).and_then(|u| u.get(&body.user)) else {
        tracing::warn!(host = %id.host, user = %clean(&body.user, 64), "submission for a user that is not configured");
        return Err(error(StatusCode::FORBIDDEN, "unknown-user", "this user may not submit requests"));
    };
    let p = pending_subject(id, groups, body)?;

    // Bound how many undecided requests one host can pile up.
    let open = state
        .engine
        .store()
        .list_requests(&RequestFilter { open_only: true, limit: None })
        .await
        .map_err(|e| internal(&e))?;
    let waiting = open
        .iter()
        .filter(|r| {
            r.state.is_pending() && r.subject.backend == id.backend && r.facts.target.as_ref() == Some(&id.host)
        })
        .count();
    if waiting >= state.max_pending {
        return Err(error(
            StatusCode::TOO_MANY_REQUESTS,
            "too-many-pending",
            "too many requests are waiting for approval",
        ));
    }

    match state.engine.submit(p, Timestamp::now()).await.map_err(|e| internal(&e))? {
        Submitted::Opened(r) => Ok((StatusCode::CREATED, Json(status_body(&state, &r))).into_response()),
        Submitted::Covered(r) => Ok(Json(status_body(&state, &r)).into_response()),
        Submitted::Unmatched => Err(error(StatusCode::FORBIDDEN, "no-policy", "no policy allows this request")),
    }
}

#[derive(Debug, Deserialize)]
struct WaitQuery {
    /// Seconds to wait while the request is pending (at most 60).
    #[serde(default)]
    wait: u64,
}

async fn status(
    State(state): State<IntakeState>,
    peer: Peer,
    headers: HeaderMap,
    Path(raw): Path<String>,
    Query(q): Query<WaitQuery>,
) -> Result<Json<StatusBody>, ApiError> {
    let id = state.authenticate(&headers, peer_addr(peer))?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(q.wait).min(MAX_WAIT);
    let mut changes = state.engine.subscribe();
    loop {
        changes.borrow_and_update();
        let r = state.owned(id, &raw).await?;
        if host_state(&r) == "pending" {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Ok(Json(status_body(&state, &r)));
            }
            // Wake on changes made by this process, and re-read now and then
            // for changes made elsewhere (e.g. the CLI deciding).
            let _ = tokio::time::timeout_at(deadline.min(now + RECHECK), changes.changed()).await;
            continue;
        }
        if matches!(r.state, RequestState::Active { .. }) && r.requirements.grant == GrantMode::Once {
            // The host has the answer; a single-use approval ends here.
            let r = state.engine.collect(r.id, Timestamp::now()).await.map_err(|e| internal(&e))?;
            return Ok(Json(status_body(&state, &r)));
        }
        return Ok(Json(status_body(&state, &r)));
    }
}

async fn withdraw(
    State(state): State<IntakeState>,
    peer: Peer,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Result<StatusCode, ApiError> {
    let id = state.authenticate(&headers, peer_addr(peer))?;
    let r = state.owned(id, &raw).await?;
    match state.engine.withdraw(r.id, Timestamp::now()).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(EngineError::Transition(TransitionError::InvalidState { state: s, .. })) => {
            Err(error(StatusCode::CONFLICT, "conflict", format!("the request is {s}")))
        }
        Err(e) => Err(internal(&e)),
    }
}
