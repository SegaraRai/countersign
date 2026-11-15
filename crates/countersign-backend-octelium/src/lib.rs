//! [Octelium] backend for countersign.
//!
//! Users whose `spec.session.defaultState` is `PENDING` get sessions that
//! cannot be used until approved. This backend lists those sessions, and
//! approves (with an expiry), rejects, or deletes them through `octeliumctl`.
//!
//! The `octeliumctl` login used here needs permission to get/list sessions
//! and users and to update/delete sessions — nothing else.
//!
//! An Octelium session ends for good after the user's `clientDuration`. With
//! `auth_token_file` set, the backend logs in again with that token when
//! `octeliumctl` reports `Unauthenticated`, and retries the command once.
//!
//! [Octelium]: https://octelium.com

mod model;
pub mod runner;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use countersign_core::{
    AccessBackend, BackendCaps, BackendError, BackendName, GrantHandle, PendingSubject, Requester, SubjectFacts,
    SubjectRef,
};
use jiff::Timestamp;
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::model::{List, Session, User};
pub use crate::runner::{CmdOutput, ProcessRunner, RunError, Runner};

/// Subject kind used for Octelium sessions.
pub const KIND_SESSION: &str = "session";

const PAGE_SIZE: u32 = 200;
const MAX_STDERR: usize = 500;

/// Configuration of one Octelium backend instance.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcteliumConfig {
    /// Cluster domain, e.g. `"octelium.example.com"`.
    pub domain: String,
    /// Path to `octeliumctl`. Defaults to looking it up in `PATH`.
    #[serde(default = "default_program")]
    pub octeliumctl: PathBuf,
    /// Octelium home directory holding the login used by countersign.
    #[serde(default)]
    pub homedir: Option<PathBuf>,
    #[serde(default = "default_timeout", with = "humantime_serde")]
    pub command_timeout: Duration,
    /// Maps Octelium identity-provider names to the identity namespace used by
    /// approvers, so self-approval can be detected across systems. For
    /// example `{ pocket = "oidc:https://id.example.com" }` turns identity
    /// `<sub>` from identity provider `pocket` into `oidc:https://id.example.com#<sub>`.
    #[serde(default)]
    pub identity_providers: BTreeMap<String, String>,
    /// Authentication token used to log in again when the current Octelium
    /// session has ended. Without it, an expired login needs a manual
    /// `octeliumctl login`.
    #[serde(default)]
    pub auth_token_file: Option<PathBuf>,
}

/// Minimum time between failed login attempts.
const RELOGIN_BACKOFF: Duration = Duration::from_secs(60);

/// Serializes logins so concurrent failures trigger one login.
#[derive(Debug, Default)]
struct Relogin {
    /// Incremented after each successful login.
    generation: u64,
    last_failure: Option<std::time::Instant>,
}

fn default_program() -> PathBuf {
    PathBuf::from("octeliumctl")
}

fn default_timeout() -> Duration {
    Duration::from_secs(30)
}

/// An [`AccessBackend`] for pending Octelium sessions.
#[derive(Debug)]
pub struct OcteliumBackend<R = ProcessRunner> {
    name: BackendName,
    config: OcteliumConfig,
    runner: R,
    relogin: tokio::sync::Mutex<Relogin>,
}

impl OcteliumBackend<ProcessRunner> {
    pub fn new(name: BackendName, config: OcteliumConfig) -> Result<Self, BackendError> {
        let runner = ProcessRunner { program: config.octeliumctl.clone(), timeout: config.command_timeout };
        Self::with_runner(name, config, runner)
    }
}

impl<R: Runner> OcteliumBackend<R> {
    pub fn with_runner(name: BackendName, config: OcteliumConfig, runner: R) -> Result<Self, BackendError> {
        if !is_valid_domain(&config.domain) {
            return Err(other(format!("invalid Octelium domain {:?}", config.domain)));
        }
        Ok(Self { name, config, runner, relogin: tokio::sync::Mutex::default() })
    }

    /// Run a command, logging in again and retrying once if the Octelium
    /// session has ended.
    async fn ctl(&self, cmd: &[&str], positional: Option<&str>) -> Result<Vec<u8>, BackendError> {
        if self.config.auth_token_file.is_none() {
            return self.ctl_once(cmd, positional).await.map_err(|(e, _)| e);
        }
        let generation = self.relogin.lock().await.generation;
        match self.ctl_once(cmd, positional).await {
            Ok(out) => Ok(out),
            Err((_, true)) if self.login(generation).await? => self.ctl_once(cmd, positional).await.map_err(|(e, _)| e),
            Err((e, _)) => Err(e),
        }
    }

    /// Log in with the configured token unless another call already did so
    /// since `seen`. Returns whether a retry is worthwhile.
    async fn login(&self, seen: u64) -> Result<bool, BackendError> {
        let Some(token_file) = &self.config.auth_token_file else { return Ok(false) };
        let mut state = self.relogin.lock().await;
        if state.generation != seen {
            return Ok(true);
        }
        if state.last_failure.is_some_and(|t| t.elapsed() < RELOGIN_BACKOFF) {
            return Err(other("Octelium login expired and the last login attempt failed".to_owned()));
        }
        tracing::info!(backend = %self.name, "Octelium session ended; logging in again");
        // `login` silently does nothing while the dead session is still
        // stored, so clear it first. Failure here is not fatal.
        if let Err((e, _)) = self.ctl_once(&["logout"], None).await {
            tracing::warn!(backend = %self.name, error = %e, "octeliumctl logout failed");
        }
        let token_file = token_file.display().to_string();
        match self.ctl_once(&["login", "--auth-token-file", &token_file], None).await {
            Ok(_) => {
                state.generation += 1;
                state.last_failure = None;
                tracing::info!(backend = %self.name, "logged in to Octelium");
                Ok(true)
            }
            Err((e, _)) => {
                state.last_failure = Some(std::time::Instant::now());
                tracing::error!(backend = %self.name, error = %e, "Octelium login failed");
                Err(e)
            }
        }
    }

    /// Run `octeliumctl <args…> --domain <d> [--homedir <h>] [-- <positional>]`.
    /// On failure, also reports whether the login was rejected.
    async fn ctl_once(&self, cmd: &[&str], positional: Option<&str>) -> Result<Vec<u8>, (BackendError, bool)> {
        let mut argv: Vec<String> = cmd.iter().map(|s| (*s).to_owned()).collect();
        argv.extend(["--domain".to_owned(), self.config.domain.clone()]);
        if let Some(h) = &self.config.homedir {
            argv.extend(["--homedir".to_owned(), h.display().to_string()]);
        }
        if let Some(p) = positional {
            argv.extend(["--".to_owned(), p.to_owned()]);
        }
        let out = self.runner.run(&argv).await.map_err(|e| match e {
            RunError::Timeout(_) => (BackendError::Unavailable(e.to_string()), false),
            RunError::Spawn(_) => (other(e.to_string()), false),
        })?;
        if out.success {
            Ok(out.stdout)
        } else {
            let text = failure_text(&out);
            let unauthenticated = text.to_ascii_lowercase().contains("unauthenticated");
            Err((classify(&text), unauthenticated))
        }
    }

    async fn get_json<T: DeserializeOwned>(&self, args: &[&str], name: Option<&str>) -> Result<T, BackendError> {
        let stdout = self.ctl(args, name).await?;
        serde_json::from_slice(&stdout).map_err(|e| other(format!("unexpected octeliumctl output: {e}")))
    }

    async fn get_session(&self, name: &str) -> Result<Session, BackendError> {
        self.get_json(&["get", "session", "-o", "json"], Some(name)).await
    }

    async fn get_user(&self, name: &str) -> Result<User, BackendError> {
        check_name(name)?;
        self.get_json(&["get", "user", "-o", "json"], Some(name)).await
    }

    async fn list_sessions(&self) -> Result<Vec<Session>, BackendError> {
        let mut all = Vec::new();
        for page in 1u32.. {
            let page_s = page.to_string();
            let size_s = PAGE_SIZE.to_string();
            let list: List<Session> = self
                .get_json(&["get", "session", "-o", "json", "--page", &page_s, "--items-per-page", &size_s], None)
                .await?;
            let n = list.items.len();
            all.extend(list.items);
            let total = list.list_response_meta.map_or(0, |m| m.total_count);
            if n < PAGE_SIZE as usize || all.len() as u64 >= total {
                break;
            }
        }
        Ok(all)
    }

    fn facts(&self, session: &Session, user: &User) -> SubjectFacts {
        let spec = &user.spec;
        let user_name = &session.status.user_ref.name;
        let domain = &self.config.domain;

        let mut identities = BTreeSet::from([format!("octelium:{domain}:user:{user_name}")]);
        for id in spec.authentication.iter().flat_map(|a| &a.identities) {
            identities.insert(match self.config.identity_providers.get(&id.identity_provider) {
                Some(prefix) => format!("{prefix}#{}", id.identifier),
                None => format!("octelium:{domain}:idp:{}#{}", id.identity_provider, id.identifier),
            });
        }

        let mut attributes = BTreeMap::new();
        let mut put = |k: &str, v: Option<&String>| {
            if let Some(v) = v.filter(|v| !v.is_empty()) {
                attributes.insert(k.to_owned(), v.clone());
            }
        };
        let st = &session.status;
        let info = st.authentication.as_ref().and_then(|a| a.info.as_ref());
        put("user_type", spec.kind.as_ref());
        put("session_type", st.kind.as_ref());
        put("auth_type", info.and_then(|i| i.kind.as_ref()));
        put("credential", info.and_then(|i| i.credential.as_ref()?.credential_ref.as_ref()).map(|r| &r.name));
        put("user_agent", info.and_then(|i| i.downstream.as_ref()?.user_agent.as_ref()));
        put("device", st.device_ref.as_ref().map(|r| &r.name));
        if st.is_browser {
            attributes.insert("browser".to_owned(), "true".to_owned());
        }

        SubjectFacts {
            requester: Requester {
                id: user_name.clone(),
                display_name: spec.email.clone(),
                groups: spec.groups.iter().cloned().collect(),
                identities,
            },
            target: None,
            requested_ttl: None,
            reason: None,
            attributes,
        }
    }

    fn subject(&self, session_name: &str) -> SubjectRef {
        SubjectRef { backend: self.name.clone(), kind: KIND_SESSION.to_owned(), id: session_name.to_owned() }
    }

    /// The session name for a subject of this backend, validated for use as
    /// a command-line argument.
    fn session_name<'a>(&self, subject: &'a SubjectRef) -> Result<&'a str, BackendError> {
        if subject.backend != self.name || subject.kind != KIND_SESSION {
            return Err(other(format!(
                "subject {}/{} does not belong to backend {}",
                subject.backend, subject.kind, self.name
            )));
        }
        check_name(&subject.id)?;
        Ok(&subject.id)
    }

    async fn require_pending(&self, name: &str) -> Result<Session, BackendError> {
        let s = self.get_session(name).await?;
        if s.spec.is_pending() {
            Ok(s)
        } else {
            Err(BackendError::Conflict(format!(
                "session is {}, not PENDING",
                s.spec.state.as_deref().unwrap_or("in an unknown state")
            )))
        }
    }
}

#[async_trait]
impl<R: Runner> AccessBackend for OcteliumBackend<R> {
    fn name(&self) -> &BackendName {
        &self.name
    }

    fn capabilities(&self) -> BackendCaps {
        BackendCaps { discover: true, revoke: true, native_expiry: true }
    }

    async fn discover_pending(&self) -> Result<Vec<PendingSubject>, BackendError> {
        let pending: Vec<Session> = self.list_sessions().await?.into_iter().filter(|s| s.spec.is_pending()).collect();
        let mut users: HashMap<String, User> = HashMap::new();
        let mut out = Vec::with_capacity(pending.len());
        for s in pending {
            let user_name = &s.status.user_ref.name;
            if !users.contains_key(user_name) {
                users.insert(user_name.clone(), self.get_user(user_name).await?);
            }
            let facts = self.facts(&s, &users[user_name]);
            out.push(PendingSubject {
                subject: self.subject(&s.metadata.name),
                facts,
                observed_at: s.metadata.created_at.unwrap_or_else(Timestamp::now),
            });
        }
        Ok(out)
    }

    async fn verify(&self, subject: &SubjectRef) -> Result<SubjectFacts, BackendError> {
        let name = self.session_name(subject)?;
        let s = self.get_session(name).await?;
        let user = self.get_user(&s.status.user_ref.name).await?;
        Ok(self.facts(&s, &user))
    }

    async fn grant(&self, subject: &SubjectRef, ttl: Duration) -> Result<GrantHandle, BackendError> {
        let name = self.session_name(subject)?;
        self.require_pending(name).await?;
        let expire_in = format!("{}s", ttl.as_secs().max(1));
        self.ctl(&["update", "session", "--approve", "--expire-in", &expire_in], Some(name)).await?;
        // Read back the expiry Octelium actually recorded.
        let s = self.get_session(name).await?;
        Ok(GrantHandle { subject: subject.clone(), backend_ref: None, expires_at: s.spec.expires_at })
    }

    async fn deny(&self, subject: &SubjectRef) -> Result<(), BackendError> {
        let name = self.session_name(subject)?;
        self.require_pending(name).await?;
        self.ctl(&["update", "session", "--reject"], Some(name)).await?;
        Ok(())
    }

    async fn revoke(&self, grant: &GrantHandle) -> Result<(), BackendError> {
        let name = self.session_name(&grant.subject)?;
        match self.ctl(&["delete", "session"], Some(name)).await {
            Ok(_) | Err(BackendError::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

fn other(msg: String) -> BackendError {
    BackendError::Other(msg.into())
}

/// Octelium resource names: lowercase alphanumerics, `-` and `.`, starting
/// with an alphanumeric. Rejecting anything else also rules out option
/// injection into the command line.
fn check_name(name: &str) -> Result<(), BackendError> {
    let ok = !name.is_empty()
        && name.len() <= 253
        && name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.');
    if ok { Ok(()) } else { Err(other(format!("invalid Octelium resource name {name:?}"))) }
}

fn is_valid_domain(d: &str) -> bool {
    !d.is_empty() && !d.starts_with(['-', '.']) && d.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
}

/// The useful part of a failed run. `octeliumctl` prints errors such as
/// `gRPC error NotFound: ...` on stdout and its usage text on stderr.
fn failure_text(out: &CmdOutput) -> String {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let errors: Vec<&str> = stdout
        .lines()
        .chain(out.stderr.lines())
        .map(str::trim)
        .filter(|l| l.to_ascii_lowercase().contains("error"))
        .collect();
    if !errors.is_empty() {
        errors.join(
            "
",
        )
    } else if !stdout.trim().is_empty() {
        stdout.trim().to_owned()
    } else {
        out.stderr.trim().to_owned()
    }
}

fn classify(text: &str) -> BackendError {
    let lower = text.to_ascii_lowercase();
    let mut msg = text.to_owned();
    if msg.len() > MAX_STDERR {
        let mut cut = MAX_STDERR;
        while !msg.is_char_boundary(cut) {
            cut -= 1;
        }
        msg.truncate(cut);
        msg.push('…');
    }
    if lower.contains("notfound") || lower.contains("not found") {
        BackendError::NotFound
    } else if ["unavailable", "deadline exceeded", "connection refused", "no such host", "i/o timeout"]
        .iter()
        .any(|p| lower.contains(p))
    {
        BackendError::Unavailable(msg)
    } else {
        other(format!("octeliumctl failed: {msg}"))
    }
}

#[cfg(test)]
mod tests;
