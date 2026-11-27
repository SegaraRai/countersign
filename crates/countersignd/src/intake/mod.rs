//! The API for clients: `sudo` invocations waiting for approval, and
//! questions for people.
//!
//! Clients authenticate with their own key (`Authorization: Bearer cshk_…`) or
//! a CI OIDC JWT; the configuration holds only the SHA-256 of static keys. Who
//! the client is — and so the namespace of the requesters it may name
//! (`unix:<client>#<user>`) and the target of its requests — comes from the
//! credential, never from the body. Each client has scopes: `approval`,
//! `question`, or both.
//!
//! ```text
//! POST   /intake/v1/requests         submit; 201 pending, 200 approved by a window, 403 no policy
//! GET    /intake/v1/requests/{id}    state; ?wait=<secs> long-polls while pending
//! DELETE /intake/v1/requests/{id}    withdraw while pending
//! GET    /intake/v1/server-key       public approval signing key (ed25519:…)
//! POST   /intake/v1/questions        ask; 201 pending
//! GET    /intake/v1/questions/{id}   state and answer; ?wait=<secs> long-polls while pending
//! DELETE /intake/v1/questions/{id}   withdraw while pending
//! POST   /mcp                        the question calls as MCP tools (Streamable HTTP; see [`mcp`])
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ConnectInfo;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};

use countersign_core::approval_signing::ServerKey;
use countersign_core::{Question, Request, RequestId, Source};

use crate::config::{ClientConfig, Scope};
use crate::engine::Engine;
use crate::tls::TlsConfig;

mod approvals;
mod auth;
mod host_backend;
mod mcp;
mod oidc;
mod questions;

pub use approvals::{KIND_SUDO, MAX_COMMAND_CHARS, StatusBody, SubmitBody, unix_identity};
pub use host_backend::{HostBackend, HostBackendConfig};
pub use questions::{AskBody, QuestionBody};

use questions::{MAX_QUESTION_BODY, ask_as, wait_for_answer, withdraw_as};

const MAX_WAIT: Duration = Duration::from_secs(60);
/// While long-polling, re-read at least this often.
const RECHECK: Duration = Duration::from_secs(2);

/// `[intake]`: where clients reach countersign.
///
/// Clients authenticate with their key or OIDC JWT; the network is not trusted.
/// The listener therefore always serves HTTPS: either it terminates TLS itself
/// (`tls`), or a reverse proxy or tunnel in front of it does (`behind_proxy`,
/// on a loopback or private address).
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
    /// countersign's approval signing key (`cssk_…`, from `countersign
    /// signing-key`). Clients pin its public key and accept an approval only
    /// with a valid signature, so TLS is not the only thing between a forged
    /// answer and root.
    pub signing_key_file: std::path::PathBuf,
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
        if self.max_pending_per_client == 0 {
            errors.push("intake: max_pending_per_client must be at least 1".into());
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

/// Everything the intake API needs. Clients are read from the engine's
/// rules, so a configuration reload adds and removes them.
#[derive(Clone)]
pub struct IntakeState {
    pub(super) engine: Arc<Engine>,
    pub(super) public_url: Arc<str>,
    pub(super) max_pending: usize,
    /// Behind a proxy: where it puts the client's address.
    pub(super) client_ip_header: Option<axum::http::HeaderName>,
    pub(super) signing: Arc<ServerKey>,
    pub(super) oidc: Arc<oidc::OidcVerifier>,
}

impl std::fmt::Debug for IntakeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntakeState").field("public_url", &self.public_url).finish_non_exhaustive()
    }
}

impl IntakeState {
    pub fn new(engine: Arc<Engine>, intake: &IntakeConfig, public_url: &str, signing: Arc<ServerKey>) -> Self {
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
            signing,
            oidc: Arc::new(oidc::OidcVerifier::new()),
        }
    }

    pub(super) fn url(&self, id: RequestId) -> String {
        format!("{}/requests/{id}", self.public_url)
    }

    /// The request, if it exists and this client submitted it.
    pub(super) async fn owned(&self, client: &ClientConfig, raw: &str) -> Result<Request, ApiError> {
        let not_found = || error(StatusCode::NOT_FOUND, "not-found", "no such request");
        let rid: RequestId = raw.parse().map_err(|_| not_found())?;
        let r = self.engine.store().get_request(rid).await.map_err(|e| internal(&e))?.ok_or_else(not_found)?;
        if r.facts.source == Some(Source::Client(client.id.clone())) { Ok(r) } else { Err(not_found()) }
    }

    /// The question, if it exists and this client asked it.
    pub(super) async fn owned_question(&self, client: &ClientConfig, raw: &str) -> Result<Question, ApiError> {
        let not_found = || error(StatusCode::NOT_FOUND, "not-found", "no such question");
        let id: RequestId = raw.parse().map_err(|_| not_found())?;
        let q = self.engine.store().get_question(id).await.map_err(|e| internal(&e))?.ok_or_else(not_found)?;
        if q.asker.client == client.id { Ok(q) } else { Err(not_found()) }
    }
}

pub fn router(state: IntakeState) -> Router {
    Router::new()
        .route("/intake/v1/requests", post(approvals::submit))
        .route("/intake/v1/requests/{id}", get(approvals::status).delete(approvals::withdraw))
        .route("/intake/v1/server-key", get(approvals::server_key))
        .route("/intake/v1/questions", post(questions::ask))
        .route("/intake/v1/questions/{id}", get(questions::question_status).delete(questions::withdraw_question))
        .route("/mcp", post(mcp::post).get(mcp::no_stream).delete(mcp::no_stream))
        .with_state(state)
}

pub(super) type Peer = Option<Extension<ConnectInfo<SocketAddr>>>;

pub(super) fn peer_addr(p: Peer) -> Option<SocketAddr> {
    p.map(|Extension(ConnectInfo(a))| a)
}

#[derive(Debug, Deserialize)]
pub(super) struct WaitQuery {
    /// Seconds to wait while pending (at most 60).
    #[serde(default)]
    pub wait: u64,
}

/// An error answer: `{"error": <code>, "message": <text>}`.
#[derive(Debug)]
pub(super) struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
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

pub(super) fn error(status: StatusCode, code: &'static str, message: impl Into<String>) -> ApiError {
    ApiError { status, code, message: message.into() }
}

pub(super) fn internal(e: &dyn std::fmt::Display) -> ApiError {
    tracing::error!(error = %e, "intake request failed");
    error(StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal error")
}
