//! The API for clients: `sudo` invocations waiting for approval, and
//! questions for people.
//!
//! Clients authenticate with their own key (`Authorization: Bearer cshk_…`);
//! the configuration holds only its SHA-256. Who the client is, and so the
//! namespace of the requesters it may name (`unix:<client>#<user>`) and the
//! target of its requests, comes from the key, never from the body. Each key
//! has scopes: `approval`, `question`, or both.
//!
//! ```text
//! POST   /intake/v1/requests         submit; 201 pending, 200 approved by a window, 403 no policy
//! GET    /intake/v1/requests/{id}    state; ?wait=<secs> long-polls while pending
//! DELETE /intake/v1/requests/{id}    withdraw while pending
//! POST   /intake/v1/questions        ask; 201 pending
//! GET    /intake/v1/questions/{id}   state and answer; ?wait=<secs> long-polls while pending
//! DELETE /intake/v1/questions/{id}   withdraw while pending
//! ```

use std::collections::BTreeMap;
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
    AccessBackend, AnswerError, Asker, BackendCaps, BackendError, BackendName, ClientId, Confidentiality, GrantHandle,
    GrantMode, PendingSubject, Purpose, Question, QuestionOutcome, Request, RequestFilter, RequestId, RequestState,
    Requester, Source, Store, SubjectFacts, SubjectRef, TransitionError,
};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use subtle::ConstantTimeEq as _;

use crate::config::{ClientConfig, Scope};
use crate::engine::{Ask, Engine, EngineError, Submitted};
use crate::tls::TlsConfig;

/// Subject kind for `sudo` invocations.
pub const KIND_SUDO: &str = "sudo";

const MAX_WAIT: Duration = Duration::from_secs(60);
/// While long-polling, re-read at least this often.
const RECHECK: Duration = Duration::from_secs(2);
const MAX_ARGV_BYTES: usize = 8 * 1024;
const MAX_FIELD: usize = 1024;
const MAX_REASON: usize = 500;
/// Largest body accepted for a question.
const MAX_QUESTION_BODY: usize = 64 * 1024;
/// The longest command (as shown) approvers are asked about. Chat
/// channels can show this much in full.
pub const MAX_COMMAND_CHARS: usize = 3000;

/// `[intake]`: where clients reach countersign.
///
/// Clients authenticate with their key alone; the network is not trusted.
/// The listener therefore always serves HTTPS: either it terminates TLS
/// itself (`tls`), or a reverse proxy or tunnel in front of it does
/// (`behind_proxy`, on a loopback or private address).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntakeConfig {
    pub listen: SocketAddr,
    /// Terminate TLS here.
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// A reverse proxy or tunnel terminates TLS and forwards plain HTTP to
    /// `listen`.
    #[serde(default)]
    pub behind_proxy: bool,
    /// Behind a proxy: the header in which it passes the client's address
    /// (e.g. `x-forwarded-for`; the last entry counts). Only needed for
    /// clients with `allowed_ips`.
    #[serde(default)]
    pub client_ip_header: Option<String>,
    /// Undecided approval requests a single client may have at once.
    /// Questions have their own limit per question policy.
    #[serde(default = "default_max_pending")]
    pub max_pending_per_client: usize,
}

impl IntakeConfig {
    /// Problems with how the listener is exposed.
    pub fn problems(&self) -> Vec<String> {
        let mut errors = Vec::new();
        match (&self.tls, self.behind_proxy) {
            (None, false) => errors.push(
                "intake: set tls = { cert_file, key_file } to serve HTTPS, or behind_proxy = true when a reverse \
                 proxy or tunnel terminates TLS"
                    .into(),
            ),
            (Some(_), true) => errors.push("intake: tls and behind_proxy exclude each other".into()),
            (None, true) if !crate::config::is_private(self.listen.ip()) => errors.push(format!(
                "intake: behind_proxy serves plain HTTP; listen on a loopback or private address, not {}",
                self.listen
            )),
            _ => {}
        }
        if let Some(h) = &self.client_ip_header {
            if !self.behind_proxy {
                errors.push("intake: client_ip_header is only used with behind_proxy".into());
            }
            if axum::http::HeaderName::try_from(h.as_str()).is_err() {
                errors.push(format!("intake: client_ip_header {h:?} is not a header name"));
            }
        }
        errors
    }

    /// Whether the client's address can be known (for `allowed_ips`).
    pub fn knows_client_address(&self) -> bool {
        !self.behind_proxy || self.client_ip_header.is_some()
    }
}

fn default_max_pending() -> usize {
    10
}

/// `[backend.<name>] type = "host"`: `sudo` invocations from clients. Which
/// OS users may ask is decided by workload identities (`unix:<client>#<user>`)
/// and policies.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostBackendConfig {}

/// OS user names: ASCII letters, digits, `-`, `_` and `.`.
fn is_name(s: &str) -> bool {
    countersign_core::actor::is_name(s)
}

/// A backend for subjects that clients submit. It holds no state of its
/// own: the stored request is the record, and clients read the outcome
/// through the intake API.
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

    /// Unused: intake names requesters `unix:<client>#<user>` itself.
    fn identity_scheme(&self) -> &'static str {
        "unix"
    }

    fn capabilities(&self) -> BackendCaps {
        BackendCaps { discover: false, revoke: true, native_expiry: true }
    }

    async fn discover_pending(&self) -> Result<Vec<PendingSubject>, BackendError> {
        Ok(Vec::new())
    }

    /// The facts recorded when the authenticated client submitted the subject.
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

/// Everything the intake API needs. Clients are read from the engine's
/// rules, so a configuration reload adds and removes them.
#[derive(Clone)]
pub struct IntakeState {
    engine: Arc<Engine>,
    public_url: Arc<str>,
    max_pending: usize,
    /// Behind a proxy: where it puts the client's address.
    client_ip_header: Option<axum::http::HeaderName>,
}

impl std::fmt::Debug for IntakeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntakeState").field("public_url", &self.public_url).finish_non_exhaustive()
    }
}

impl IntakeState {
    pub fn new(engine: Arc<Engine>, intake: &IntakeConfig, public_url: &str) -> Self {
        let client_ip_header = intake
            .client_ip_header
            .as_deref()
            .filter(|_| intake.behind_proxy)
            .and_then(|h| axum::http::HeaderName::try_from(h).ok());
        Self {
            engine,
            public_url: public_url.trim_end_matches('/').into(),
            max_pending: intake.max_pending_per_client,
            client_ip_header,
        }
    }

    /// The client's address: the peer's, or behind a proxy the last entry of
    /// the header it sets (earlier entries come from the client and are not
    /// trusted).
    fn client_ip(&self, headers: &HeaderMap, peer: Option<SocketAddr>) -> Option<IpAddr> {
        match &self.client_ip_header {
            None => peer.map(|p| p.ip()),
            Some(name) => {
                let last = headers.get_all(name).iter().next_back()?.to_str().ok()?.rsplit(',').next()?.trim();
                last.parse::<IpAddr>().ok().or_else(|| last.parse::<SocketAddr>().ok().map(|a| a.ip()))
            }
        }
    }

    fn url(&self, id: RequestId) -> String {
        format!("{}/requests/{id}", self.public_url)
    }

    fn authenticate(
        &self,
        headers: &HeaderMap,
        peer: Option<SocketAddr>,
        scope: Scope,
    ) -> Result<ClientConfig, ApiError> {
        let key = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim)
            .filter(|k| !k.is_empty())
            .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "unauthorized", "missing client key"))?;
        let rules = self.engine.rules();
        // A malformed key gets the same answer as a wrong one, and is never
        // hashed. Every configured digest is compared in constant time.
        let found = host_key::is_well_formed(key).then(|| host_key::digest(key)).and_then(|digest| {
            rules.clients.values().fold(None, |found, c| {
                let matches =
                    host_key::parse_digest_hex(&c.auth.host_key_sha256).is_some_and(|d| bool::from(d.ct_eq(&digest)));
                if matches { Some(c) } else { found }
            })
        });
        let ip = self.client_ip(headers, peer);
        let Some(client) = found else {
            tracing::warn!(address = ?ip, "intake request with an unknown client key");
            return Err(error(StatusCode::UNAUTHORIZED, "unauthorized", "unknown client key"));
        };
        if !client.allowed_ips.is_empty() && !ip.is_some_and(|a| client.allowed_ips.contains(&a)) {
            tracing::warn!(client = %client.id, address = ?ip, "client key used from an address that is not allowed");
            return Err(error(StatusCode::UNAUTHORIZED, "unauthorized", "address not allowed for this client"));
        }
        if !client.has_scope(scope) {
            tracing::warn!(client = %client.id, ?scope, "client key used outside its scopes");
            return Err(error(StatusCode::FORBIDDEN, "scope", "this key may not be used for this"));
        }
        Ok(client.clone())
    }

    /// The request, if it exists and this client submitted it.
    async fn owned(&self, client: &ClientConfig, raw: &str) -> Result<Request, ApiError> {
        let not_found = || error(StatusCode::NOT_FOUND, "not-found", "no such request");
        let rid: RequestId = raw.parse().map_err(|_| not_found())?;
        let r = self.engine.store().get_request(rid).await.map_err(|e| internal(&e))?.ok_or_else(not_found)?;
        if r.facts.source == Some(Source::Client(client.id.clone())) { Ok(r) } else { Err(not_found()) }
    }

    /// The question, if it exists and this client asked it.
    async fn owned_question(&self, client: &ClientConfig, raw: &str) -> Result<Question, ApiError> {
        let not_found = || error(StatusCode::NOT_FOUND, "not-found", "no such question");
        let id: RequestId = raw.parse().map_err(|_| not_found())?;
        let q = self.engine.store().get_question(id).await.map_err(|e| internal(&e))?.ok_or_else(not_found)?;
        if q.asker.client == client.id { Ok(q) } else { Err(not_found()) }
    }
}

pub fn router(state: IntakeState) -> Router {
    Router::new()
        .route("/intake/v1/requests", post(submit))
        .route("/intake/v1/requests/{id}", get(status).delete(withdraw))
        .route("/intake/v1/questions", post(ask))
        .route("/intake/v1/questions/{id}", get(question_status).delete(withdraw_question))
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
    /// Keep the details out of chat channels (the policy decides whether
    /// this is honoured). The record keeps everything.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sensitive: bool,
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

/// Join argv for display and policy matching, quoting like a POSIX shell
/// where needed.
pub fn shell_join(argv: &[String]) -> String {
    let safe = |a: &str| !a.is_empty() && a.bytes().all(|b| b.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&b));
    argv.iter()
        .map(|a| if safe(a) { a.clone() } else { format!("'{}'", a.replace('\'', r"'\''")) })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The requester identity a client may name for an OS user.
pub fn unix_identity(client: &ClientId, user: &str) -> String {
    format!("unix:{client}#{user}")
}

fn pending_subject(client: &ClientConfig, backend: BackendName, body: SubmitBody) -> Result<PendingSubject, ApiError> {
    let bad = |m: &str| error(StatusCode::BAD_REQUEST, "bad-request", m);
    if !is_name(&body.user) {
        return Err(bad("invalid user"));
    }
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
    let command = shell_join(&argv);
    if command.chars().count() > MAX_COMMAND_CHARS {
        return Err(bad("the command is too long to show to approvers"));
    }

    let host = client.id.to_string();
    let mut attributes = BTreeMap::from([
        ("host".to_owned(), host.clone()),
        ("user".to_owned(), body.user.clone()),
        ("runas".to_owned(), runas),
        ("command".to_owned(), command),
    ]);
    if let Some(cwd) = body.cwd.filter(|s| !s.is_empty()) {
        attributes.insert("cwd".to_owned(), clean(&cwd, MAX_FIELD));
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
    facts.sensitive = body.sensitive;
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

async fn submit(
    State(state): State<IntakeState>,
    peer: Peer,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    // Authenticate before looking at the body.
    let client = state.authenticate(&headers, peer_addr(peer), Scope::Approval)?;
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
    let p = pending_subject(&client, backend, body)?;

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
        Submitted::Opened(r) => Ok((StatusCode::CREATED, Json(status_body(&state, &r))).into_response()),
        Submitted::Covered(r) => Ok(Json(status_body(&state, &r)).into_response()),
        Submitted::Unmatched => Err(error(StatusCode::FORBIDDEN, "no-policy", "no policy allows this request")),
        Submitted::Inactive => Err(unknown_user(&client, &user)),
    }
}

#[derive(Debug, Deserialize)]
struct WaitQuery {
    /// Seconds to wait while pending (at most 60).
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
    let client = state.authenticate(&headers, peer_addr(peer), Scope::Approval)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(q.wait).min(MAX_WAIT);
    let mut changes = state.engine.subscribe();
    loop {
        changes.borrow_and_update();
        let r = state.owned(&client, &raw).await?;
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
            // The client has the answer; a single-use approval ends here.
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
    let client = state.authenticate(&headers, peer_addr(peer), Scope::Approval)?;
    let r = state.owned(&client, &raw).await?;
    match state.engine.withdraw(r.id, Timestamp::now()).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(EngineError::Transition(TransitionError::InvalidState { state: s, .. })) => {
            Err(error(StatusCode::CONFLICT, "conflict", format!("the request is {s}")))
        }
        Err(e) => Err(internal(&e)),
    }
}

// ---- Questions ------------------------------------------------------------

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

async fn ask(
    State(state): State<IntakeState>,
    peer: Peer,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let client = state.authenticate(&headers, peer_addr(peer), Scope::Question)?;
    if body.len() > MAX_QUESTION_BODY {
        return Err(error(StatusCode::PAYLOAD_TOO_LARGE, "too-large", "the question is too large"));
    }
    let body: AskBody = serde_json::from_slice(&body)
        .map_err(|e| error(StatusCode::BAD_REQUEST, "bad-request", format!("invalid request body: {e}")))?;
    let ask = Ask {
        asker: Asker { client: client.id.clone(), actor: client.actor.clone() },
        message: body.message,
        schema: body.requested_schema,
        context: body.context,
        confidentiality: body.confidentiality,
    };
    let q = state.engine.ask(ask, Timestamp::now()).await.map_err(question_error)?;
    Ok((StatusCode::CREATED, Json(question_body(&state, &q))).into_response())
}

async fn question_status(
    State(state): State<IntakeState>,
    peer: Peer,
    headers: HeaderMap,
    Path(raw): Path<String>,
    Query(w): Query<WaitQuery>,
) -> Result<Json<QuestionBody>, ApiError> {
    let client = state.authenticate(&headers, peer_addr(peer), Scope::Question)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(w.wait).min(MAX_WAIT);
    let mut changes = state.engine.subscribe();
    loop {
        changes.borrow_and_update();
        let q = state.owned_question(&client, &raw).await?;
        if q.is_pending() {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Ok(Json(question_body(&state, &q)));
            }
            let _ = tokio::time::timeout_at(deadline.min(now + RECHECK), changes.changed()).await;
            continue;
        }
        let q = state.engine.read_question(q.id, &client.id, Timestamp::now()).await.map_err(question_error)?;
        return Ok(Json(question_body(&state, &q)));
    }
}

async fn withdraw_question(
    State(state): State<IntakeState>,
    peer: Peer,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Result<StatusCode, ApiError> {
    let client = state.authenticate(&headers, peer_addr(peer), Scope::Question)?;
    let q = state.owned_question(&client, &raw).await?;
    state.engine.withdraw_question(q.id, Some(&client.id), Timestamp::now()).await.map_err(question_error)?;
    Ok(StatusCode::NO_CONTENT)
}
