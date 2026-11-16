//! PAM helper for target hosts: asks countersign to approve a `sudo`
//! invocation and waits for the answer.
//!
//! Run by `pam_exec` in the `auth` stack of `/etc/pam.d/sudo` for the users
//! whose `sudo` needs approval. It reads what `sudo` was asked to do from the
//! waiting `sudo` process (`/proc/$PPID`), submits it to countersign's intake
//! API with this host's key, and long-polls until the request is decided.
//!
//! It exits 0 only when the invocation is approved. Every other outcome —
//! denial, timeout, Ctrl-C, an unreachable server, a configuration problem —
//! exits non-zero, so `sudo` fails closed. On timeout or a signal it
//! withdraws the request.
//!
//! See `contrib/` for the PAM, sudoers and configuration files.

pub mod invocation;

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

pub use crate::invocation::{Host, Invocation, System};

/// Default configuration file.
pub const CONFIG_PATH: &str = "/etc/countersign/sudo.toml";

/// Longest single long-poll; the server caps it at 60 s.
const POLL: Duration = Duration::from_secs(50);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Pause after a failed poll before trying again.
const RETRY: Duration = Duration::from_secs(2);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration: {0}")]
    Config(String),
    #[error("{0}")]
    Context(String),
    #[error("countersign: {0}")]
    Server(String),
}

/// `/etc/countersign/sudo.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Base URL of countersign's intake API, e.g. `https://countersign.example.com:8443`.
    /// Must be HTTPS (plain HTTP only to this machine).
    pub server: String,
    /// Extra PEM certificates to trust for `server`, e.g. a private CA or a
    /// self-signed certificate. The system's usual roots stay trusted.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// File holding this host's key. Must not be readable by group or others.
    #[serde(default = "default_key_file")]
    pub key_file: PathBuf,
    /// How long to wait for a decision before giving up.
    #[serde(default = "default_timeout", with = "humantime_serde")]
    pub timeout: Duration,
    /// Binaries accepted as the calling `sudo`.
    #[serde(default = "default_sudo_binaries")]
    pub sudo_binaries: Vec<PathBuf>,
}

fn default_key_file() -> PathBuf {
    PathBuf::from("/etc/countersign/host.key")
}

fn default_timeout() -> Duration {
    Duration::from_secs(5 * 60)
}

fn default_sudo_binaries() -> Vec<PathBuf> {
    invocation::DEFAULT_SUDO_BINARIES.iter().map(PathBuf::from).collect()
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, Error> {
        let c: Self = toml::from_str(text).map_err(|e| Error::Config(e.to_string()))?;
        if !countersign_core::url::is_secure(&c.server) {
            return Err(Error::Config(format!(
                "server must be an https:// URL (http:// only to this machine), got {:?}",
                c.server
            )));
        }
        if c.timeout.is_zero() {
            return Err(Error::Config("timeout must be greater than zero".into()));
        }
        Ok(c)
    }

    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
        Self::parse(&text)
    }
}

/// Read the host key, refusing a file others could read.
pub fn read_key(path: &Path) -> Result<String, Error> {
    let err = |e: std::io::Error| Error::Config(format!("{}: {e}", path.display()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(path).map_err(err)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(Error::Config(format!("{} must not be accessible by group or others", path.display())));
        }
    }
    let key = std::fs::read_to_string(path).map_err(err)?.trim().to_owned();
    if !countersign_core::host_key::is_well_formed(&key) {
        return Err(Error::Config(format!(
            "{} does not hold a countersign host key (create one with `countersign host-key`)",
            path.display()
        )));
    }
    Ok(key)
}

/// How the wait ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The command may run. `window` is set when an approval window
    /// (rather than a decision on this invocation) allowed it.
    Approved { window: bool },
    /// Anything else, with a message for the user.
    Refused(String),
}

#[derive(Debug, Deserialize)]
struct StatusBody {
    id: String,
    state: String,
    #[serde(default)]
    url: String,
}

#[derive(Debug, Deserialize)]
struct ErrorBody {
    #[serde(default)]
    error: String,
    #[serde(default)]
    message: String,
}

/// Talks to countersign's intake API.
#[derive(Debug, Clone)]
pub struct Client {
    http: reqwest::Client,
    base: String,
    key: String,
}

impl Client {
    /// `ca_file`: extra PEM certificates to trust (see [`Config::ca_file`]).
    pub fn new(server: &str, key: String, ca_file: Option<&Path>) -> Result<Self, Error> {
        let mut http = reqwest::Client::builder();
        if let Some(path) = ca_file {
            let err = |e: &dyn std::fmt::Display| Error::Config(format!("{}: {e}", path.display()));
            let pem = std::fs::read(path).map_err(|e| err(&e))?;
            let certs = reqwest::Certificate::from_pem_bundle(&pem).map_err(|e| err(&e))?;
            if certs.is_empty() {
                return Err(Error::Config(format!("{}: no certificate found", path.display())));
            }
            for c in certs {
                http = http.add_root_certificate(c);
            }
        }
        let http = http
            .https_only(!countersign_core::url::is_local_http(server))
            // The bearer key goes to `server` and nowhere else.
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(POLL + Duration::from_secs(15))
            .user_agent(concat!("countersign-sudo/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| Error::Config(e.to_string()))?;
        Ok(Self { http, base: format!("{}/intake/v1/requests", server.trim_end_matches('/')), key })
    }

    async fn submit(&self, inv: &Invocation) -> Result<(reqwest::StatusCode, StatusBody), Error> {
        let resp = self.http.post(&self.base).bearer_auth(&self.key).json(inv).send().await.map_err(net)?;
        let status = resp.status();
        if status.is_success() {
            Ok((status, resp.json().await.map_err(net)?))
        } else {
            Err(refusal(status, resp).await)
        }
    }

    async fn poll(&self, id: &str, wait: Duration) -> Result<StatusBody, Error> {
        let url = format!("{}/{id}?wait={}", self.base, wait.as_secs());
        let resp = self.http.get(url).bearer_auth(&self.key).send().await.map_err(net)?;
        let status = resp.status();
        if status.is_success() { resp.json().await.map_err(net) } else { Err(refusal(status, resp).await) }
    }

    async fn withdraw(&self, id: &str) {
        let _ = self
            .http
            .delete(format!("{}/{id}", self.base))
            .bearer_auth(&self.key)
            .timeout(CONNECT_TIMEOUT)
            .send()
            .await;
    }

    /// Submit `inv` and wait until it is decided, `timeout` passes, or
    /// `cancel` completes (e.g. on a signal). `say` receives progress
    /// messages for the user.
    pub async fn ask(
        &self,
        inv: &Invocation,
        timeout: Duration,
        cancel: impl Future<Output = ()>,
        say: &mut dyn FnMut(&str),
    ) -> Outcome {
        let deadline = tokio::time::Instant::now() + timeout;
        let (status, body) = match self.submit(inv).await {
            Ok(r) => r,
            Err(e) => return Outcome::Refused(e.to_string()),
        };
        if body.state == "approved" {
            return Outcome::Approved { window: status == reqwest::StatusCode::OK };
        }
        if body.state != "pending" {
            return Outcome::Refused(format!("request {}", body.state));
        }
        say(&format!("countersign: waiting for approval: {}", body.url));

        let id = body.id;
        let wait = async {
            loop {
                let left = deadline.saturating_duration_since(tokio::time::Instant::now());
                if left.is_zero() {
                    return None;
                }
                match self.poll(&id, left.min(POLL)).await {
                    Ok(b) if b.state == "pending" => {}
                    Ok(b) => return Some(b.state),
                    Err(Error::Server(m)) if m.starts_with("network:") => {
                        // Transient: keep trying until the deadline.
                        tokio::time::sleep(RETRY.min(left)).await;
                    }
                    Err(e) => return Some(e.to_string()),
                }
            }
        };
        tokio::select! {
            state = wait => match state.as_deref() {
                Some("approved") => Outcome::Approved { window: false },
                Some(other) => Outcome::Refused(format!("request {other}")),
                None => {
                    self.withdraw(&id).await;
                    Outcome::Refused("no decision in time; request withdrawn".into())
                }
            },
            () = cancel => {
                self.withdraw(&id).await;
                Outcome::Refused("interrupted; request withdrawn".into())
            }
        }
    }
}

#[allow(clippy::needless_pass_by_value)] // used as `map_err(net)`
fn net(e: reqwest::Error) -> Error {
    Error::Server(format!("network: {e}"))
}

async fn refusal(status: reqwest::StatusCode, resp: reqwest::Response) -> Error {
    let body: Option<ErrorBody> = resp.json().await.ok();
    match body {
        Some(b) if !b.message.is_empty() => Error::Server(format!("{} ({})", b.message, b.error)),
        _ => Error::Server(format!("HTTP {status}")),
    }
}
