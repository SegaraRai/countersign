//! Exec backend for countersign.
//!
//! Delegates to any program (a "helper") that speaks a small JSON protocol,
//! so new access systems can be added without writing Rust: sudo rules,
//! cloud IAM bindings, database roles, door locks...
//!
//! # Protocol (version 1)
//!
//! For each operation countersign runs `command... <op>` directly (no shell),
//! with a cleared environment plus `env` from the configuration, writes one
//! JSON object to stdin, and reads one JSON object from stdout. Every request
//! carries `"version": 1` and `"op"`.
//!
//! | op | request (besides version/op) | response on success |
//! |---|---|---|
//! | `discover` | — | `{"pending": [{"kind", "id", "facts", "observed_at"?}]}` |
//! | `verify` | `{"subject": {"kind", "id"}}` | `{"facts": {...}}` |
//! | `grant` | `{"subject", "ttl_seconds"}` | `{"backend_ref"?, "expires_at"?}` |
//! | `deny` | `{"subject"}` | `{}` |
//! | `revoke` | `{"subject", "backend_ref"?}` | `{}` |
//!
//! `facts` is `{"requester": {"id", "display_name"?, "groups"?},
//! "initiator"?: {"identity", "display_name"?}, "target"?, "requested_ttl"?
//! (e.g. "30m"), "reason"?, "attributes"?, "sensitive"?}`. Unknown keys are
//! refused. Only report facts the helper can vouch for; `reason` is shown,
//! never trusted. countersign names the requester `exec:<backend>#<id>`; the
//! initiator is a recognition identity such as `github:<user id>`, the person
//! who caused the request. Times are RFC 3339.
//!
//! On failure, exit non-zero and optionally print
//! `{"error": {"kind": "not-found" | "conflict" | "unavailable" | "unsupported" | "other", "message": "..."}}`.
//! `unavailable` is retried; a crash or timeout counts as `unavailable` too.
//!
//! ```toml
//! [backend.sudo]
//! type = "exec"
//! command = ["/usr/local/lib/countersign/sudo-helper", "--rules", "/etc/sudoers.d"]
//! env = { HELPER_MODE = "prod" }  # PATH defaults to a standard system PATH
//! timeout = "30s"
//! revoke = true                   # the helper implements `revoke`
//! native_expiry = false           # countersign calls `revoke` when the TTL ends
//! ```

pub mod runner;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use countersign_core::{
    AccessBackend, BackendCaps, BackendError, BackendName, GrantHandle, PendingSubject, SubjectFacts, SubjectRef,
};
use jiff::Timestamp;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub use crate::runner::{CmdOutput, ProcessRunner, RunError, Runner};

pub const PROTOCOL_VERSION: u32 = 1;
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const MAX_OUTPUT: usize = 4 * 1024 * 1024;
const MAX_MESSAGE: usize = 500;
const MAX_ID: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecConfig {
    /// Program and leading arguments. The operation name is appended.
    pub command: Vec<String>,
    /// The helper's whole environment. `PATH` gets a standard default.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default = "default_timeout", with = "humantime_serde")]
    pub timeout: Duration,
    /// The helper can end grants early (`revoke`).
    #[serde(default = "yes")]
    pub revoke: bool,
    /// The access system ends grants by itself at the expiry passed to
    /// `grant`. Otherwise countersign calls `revoke` when the TTL elapses.
    #[serde(default)]
    pub native_expiry: bool,
}

fn default_timeout() -> Duration {
    Duration::from_secs(30)
}

fn yes() -> bool {
    true
}

impl ExecConfig {
    fn runner(&self) -> Result<ProcessRunner, BackendError> {
        let (program, args) = self.command.split_first().ok_or_else(|| other("exec: command is empty"))?;
        if program.is_empty() {
            return Err(other("exec: command is empty"));
        }
        if !self.revoke && !self.native_expiry {
            return Err(other(
                "exec: with native_expiry = false the helper must support revoke, or grants would never end",
            ));
        }
        let mut env = self.env.clone();
        env.entry("PATH".to_owned()).or_insert_with(|| DEFAULT_PATH.to_owned());
        // Windows processes cannot start without these.
        #[cfg(windows)]
        for key in ["SystemRoot", "SYSTEMROOT", "WINDIR"] {
            if let Ok(v) = std::env::var(key) {
                env.entry(key.to_owned()).or_insert(v);
            }
        }
        Ok(ProcessRunner { program: PathBuf::from(program), args: args.to_vec(), env, timeout: self.timeout })
    }
}

/// An [`AccessBackend`] backed by a helper program.
#[derive(Debug)]
pub struct ExecBackend<R = ProcessRunner> {
    name: BackendName,
    caps: BackendCaps,
    runner: R,
}

impl ExecBackend<ProcessRunner> {
    pub fn new(name: BackendName, config: &ExecConfig) -> Result<Self, BackendError> {
        let runner = config.runner()?;
        Ok(Self::with_runner(name, config, runner))
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct WireSubject {
    kind: String,
    id: String,
}

/// `facts` as the helper may write them.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireFacts {
    requester: WireRequester,
    #[serde(default)]
    initiator: Option<WireInitiator>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default, with = "humantime_serde")]
    requested_ttl: Option<Duration>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    attributes: BTreeMap<String, String>,
    #[serde(default)]
    sensitive: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRequester {
    id: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    groups: std::collections::BTreeSet<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireInitiator {
    identity: String,
    #[serde(default)]
    display_name: Option<String>,
}

impl From<WireFacts> for SubjectFacts {
    fn from(w: WireFacts) -> Self {
        Self {
            initiator: w.initiator.map(|i| countersign_core::Initiator {
                identity: i.identity,
                display_name: i.display_name,
                actor: None,
            }),
            target: w.target,
            requested_ttl: w.requested_ttl,
            reason: w.reason,
            attributes: w.attributes,
            sensitive: w.sensitive,
            ..SubjectFacts::new(countersign_core::Requester {
                id: w.requester.id,
                display_name: w.requester.display_name,
                groups: w.requester.groups,
                ..countersign_core::Requester::default()
            })
        }
    }
}

#[derive(Debug, Deserialize)]
struct WirePending {
    kind: String,
    id: String,
    facts: WireFacts,
    #[serde(default)]
    observed_at: Option<Timestamp>,
}

#[derive(Debug, Deserialize)]
struct DiscoverResponse {
    pending: Vec<WirePending>,
}

#[derive(Debug, Deserialize)]
struct VerifyResponse {
    facts: WireFacts,
}

#[derive(Debug, Default, Deserialize)]
struct GrantResponse {
    #[serde(default)]
    backend_ref: Option<String>,
    #[serde(default)]
    expires_at: Option<Timestamp>,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: WireError,
}

#[derive(Debug, Deserialize)]
struct WireError {
    kind: String,
    #[serde(default)]
    message: String,
}

impl<R: Runner> ExecBackend<R> {
    pub fn with_runner(name: BackendName, config: &ExecConfig, runner: R) -> Self {
        let caps = BackendCaps { discover: true, revoke: config.revoke, native_expiry: config.native_expiry };
        Self { name, caps, runner }
    }

    async fn call<T: DeserializeOwned>(&self, op: &str, mut request: Value) -> Result<T, BackendError> {
        request["version"] = json!(PROTOCOL_VERSION);
        request["op"] = json!(op);
        let input = serde_json::to_vec(&request).map_err(|e| BackendError::Other(Box::new(e)))?;
        let out = self.runner.run(op, &input).await.map_err(|e| BackendError::Unavailable(e.to_string()))?;
        if out.stdout.len() > MAX_OUTPUT {
            return Err(other(format!("exec {op}: output exceeds {MAX_OUTPUT} bytes")));
        }
        if !out.success {
            return Err(failure(op, &out));
        }
        let stdout = if out.stdout.iter().all(u8::is_ascii_whitespace) { b"{}".as_slice() } else { &out.stdout };
        serde_json::from_slice(stdout).map_err(|e| other(format!("exec {op}: invalid response: {e}")))
    }

    fn wire(&self, subject: &SubjectRef) -> Result<Value, BackendError> {
        if subject.backend != self.name {
            return Err(other(format!("subject belongs to backend {}, not {}", subject.backend, self.name)));
        }
        Ok(json!(WireSubject { kind: subject.kind.clone(), id: subject.id.clone() }))
    }

    fn subject(&self, kind: String, id: String) -> Result<SubjectRef, BackendError> {
        for (what, v) in [("kind", &kind), ("id", &id)] {
            if v.is_empty() || v.len() > MAX_ID || v.chars().any(char::is_control) {
                return Err(other(format!("exec: invalid subject {what} {v:?}")));
            }
        }
        Ok(SubjectRef { backend: self.name.clone(), kind, id })
    }
}

#[async_trait]
impl<R: Runner> AccessBackend for ExecBackend<R> {
    fn name(&self) -> &BackendName {
        &self.name
    }

    fn identity_scheme(&self) -> &'static str {
        "exec"
    }

    fn capabilities(&self) -> BackendCaps {
        self.caps
    }

    async fn discover_pending(&self) -> Result<Vec<PendingSubject>, BackendError> {
        let res: DiscoverResponse = self.call("discover", json!({})).await?;
        let now = Timestamp::now();
        res.pending
            .into_iter()
            .map(|p| {
                Ok(PendingSubject {
                    subject: self.subject(p.kind, p.id)?,
                    facts: p.facts.into(),
                    observed_at: p.observed_at.unwrap_or(now),
                })
            })
            .collect()
    }

    async fn verify(&self, subject: &SubjectRef) -> Result<SubjectFacts, BackendError> {
        let res: VerifyResponse = self.call("verify", json!({ "subject": self.wire(subject)? })).await?;
        Ok(res.facts.into())
    }

    async fn grant(&self, subject: &SubjectRef, ttl: Duration) -> Result<GrantHandle, BackendError> {
        let req = json!({ "subject": self.wire(subject)?, "ttl_seconds": ttl.as_secs().max(1) });
        let res: GrantResponse = self.call("grant", req).await?;
        Ok(GrantHandle { subject: subject.clone(), backend_ref: res.backend_ref, expires_at: res.expires_at })
    }

    async fn deny(&self, subject: &SubjectRef) -> Result<(), BackendError> {
        let _: Value = self.call("deny", json!({ "subject": self.wire(subject)? })).await?;
        Ok(())
    }

    async fn revoke(&self, grant: &GrantHandle) -> Result<(), BackendError> {
        if !self.caps.revoke {
            return Err(BackendError::Unsupported);
        }
        let req = json!({ "subject": self.wire(&grant.subject)?, "backend_ref": grant.backend_ref });
        match self.call::<Value>("revoke", req).await {
            Ok(_) | Err(BackendError::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

fn other(msg: impl Into<String>) -> BackendError {
    BackendError::Other(msg.into().into())
}

fn truncate(s: &str) -> String {
    let s = s.trim();
    match s.char_indices().nth(MAX_MESSAGE) {
        Some((i, _)) => format!("{}…", &s[..i]),
        None => s.to_owned(),
    }
}

/// Classify a failed run from its structured error, or its stderr.
fn failure(op: &str, out: &CmdOutput) -> BackendError {
    if let Ok(ErrorResponse { error }) = serde_json::from_slice::<ErrorResponse>(&out.stdout) {
        let msg = truncate(&error.message);
        return match error.kind.as_str() {
            "not-found" => BackendError::NotFound,
            "conflict" => BackendError::Conflict(msg),
            "unavailable" => BackendError::Unavailable(msg),
            "unsupported" => BackendError::Unsupported,
            _ => other(format!("exec {op}: {msg}")),
        };
    }
    let stderr = truncate(&out.stderr);
    // An unstructured failure is most likely a crash or a transient problem.
    BackendError::Unavailable(if stderr.is_empty() {
        format!("exec {op} failed without an error message")
    } else {
        format!("exec {op}: {stderr}")
    })
}

#[cfg(test)]
mod tests;
