//! PAM helper for target hosts: asks countersign to approve a `sudo`
//! invocation and waits for the answer.
//!
//! Run by `pam_exec` in the `auth` stack of `/etc/pam.d/sudo` for the users
//! whose `sudo` needs approval. It reads what `sudo` was asked to do from the
//! waiting `sudo` process (`/proc/$PPID`), submits it to countersign's intake
//! API with this host's key, and long-polls until the request is decided.
//!
//! An approval counts only with countersign's signature over this host's
//! key, this exact invocation and a fresh nonce, checked against the public
//! keys pinned in the configuration (`server_keys`). TLS protects the key
//! and the details on the way; the signature is what makes an approval
//! trustworthy even where TLS is terminated by something in between.
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
    /// Base URL of countersign's intake API, e.g. `https://countersign.example.com:2743`.
    /// Must be HTTPS (plain HTTP only to this machine).
    pub server: String,
    /// Extra PEM certificates to trust for `server`, e.g. a private CA or a
    /// self-signed certificate. The system's usual roots stay trusted.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// countersign's approval signing public keys (`ed25519:…`). An approval
    /// counts only if one of them signed it. More than one while rotating.
    pub server_keys: Vec<String>,
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
    Duration::from_mins(5)
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
        if c.server_keys.is_empty() {
            return Err(Error::Config("server_keys must list countersign's public key".into()));
        }
        for k in &c.server_keys {
            countersign_core::approval_signing::check_public_key(k)
                .map_err(|why| Error::Config(format!("server_keys: {why}")))?;
        }
        Ok(c)
    }

    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
        Self::parse(&text)
    }
}

/// What `countersign-sudo enroll` was told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enroll {
    pub server: String,
    pub ca_file: Option<PathBuf>,
    /// The public key as obtained out of band; compared with what the
    /// server reports. Without it the person enrolling confirms the key.
    pub server_key: Option<String>,
    pub config: PathBuf,
    pub key_file: PathBuf,
}

/// Set up this host: fetch and pin countersign's public key, create the host
/// key if there is none, and write the configuration. `confirm` is asked to
/// accept a key that was not given in advance. Returns the `[[client]]`
/// lines for countersign's configuration.
pub async fn enroll(e: &Enroll, confirm: &mut dyn FnMut(&str) -> bool) -> Result<String, Error> {
    if e.config.exists() {
        return Err(Error::Config(format!("{} exists; remove it to enroll again", e.config.display())));
    }
    if !countersign_core::url::is_secure(&e.server) {
        return Err(Error::Config(format!("server must be an https:// URL, got {:?}", e.server)));
    }
    if let Some(k) = &e.server_key {
        countersign_core::approval_signing::check_public_key(k)
            .map_err(|why| Error::Config(format!("--server-key: {why}")))?;
    }

    // Any client key will do to build the HTTP client; the key is not sent.
    let probe = Client::new(&e.server, String::new(), e.ca_file.as_deref(), Vec::new())?;
    let url = format!("{}/intake/v1/server-key", e.server.trim_end_matches('/'));
    let resp = probe.http.get(url).send().await.map_err(net)?;
    if !resp.status().is_success() {
        return Err(Error::Server(format!("HTTP {} fetching the server key", resp.status())));
    }
    let reported = resp.json::<KeyBody>().await.map_err(net)?.server_key;
    if !countersign_core::approval_signing::is_public_key(&reported) {
        return Err(Error::Server("the server reported something that is not a public key".into()));
    }
    if let Some(k) = &e.server_key {
        if *k != reported {
            return Err(Error::Server(format!(
                "the server reports {reported}, not the expected {k}; something is in between, or the key changed"
            )));
        }
    } else if !confirm(&reported) {
        return Err(Error::Context("not trusted; nothing written".into()));
    }

    let key = if e.key_file.exists() {
        read_key(&e.key_file)?
    } else {
        let mut random = [0u8; 32];
        getrandom::getrandom(&mut random)
            .map_err(|err| Error::Context(format!("no random numbers from the OS: {err}")))?;
        let key = countersign_core::host_key::from_random(&random);
        write_new(&e.key_file, &format!("{key}\n"), 0o600)?;
        key
    };

    let quote = |s: &str| toml::Value::String(s.to_owned()).to_string();
    let mut lines = vec![format!("server = {}", quote(&e.server))];
    if let Some(ca) = &e.ca_file {
        lines.push(format!("ca_file = {}", quote(&ca.display().to_string())));
    }
    lines.push(format!("server_keys = [{}]", quote(&reported)));
    lines.push(format!("key_file = {}", quote(&e.key_file.display().to_string())));
    let text = lines.join("\n") + "\n";
    Config::parse(&text)?;
    write_new(&e.config, &text, 0o644)?;

    Ok(format!(
        "[[client]]\nid = \"<this host's name>\"\nauth = {{ host_key = \"{}\" }}",
        countersign_core::host_key::reference(&key)
    ))
}

#[derive(Debug, Deserialize)]
struct KeyBody {
    server_key: String,
}

/// Create a file that must not exist yet.
fn write_new(path: &Path, text: &str, mode: u32) -> Result<(), Error> {
    use std::io::Write as _;
    let err = |e: std::io::Error| Error::Config(format!("{}: {e}", path.display()));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    opts.open(path).and_then(|mut f| f.write_all(text.as_bytes())).map_err(err)
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
    #[serde(default)]
    signature: Option<String>,
}

/// What is sent: the invocation and the nonce the approval is bound to.
#[derive(Debug, serde::Serialize)]
struct Submission<'a> {
    #[serde(flatten)]
    invocation: &'a Invocation,
    nonce: &'a str,
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
    /// What countersign signs as this client: the hash of its key.
    key_digest: String,
    server_keys: Vec<String>,
}

impl Client {
    /// `ca_file`: extra PEM certificates to trust (see [`Config::ca_file`]);
    /// `server_keys`: the pinned public keys (see [`Config::server_keys`]).
    pub fn new(server: &str, key: String, ca_file: Option<&Path>, server_keys: Vec<String>) -> Result<Self, Error> {
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
        let key_digest = countersign_core::host_key::digest_hex(&key);
        Ok(Self {
            http,
            base: format!("{}/intake/v1/requests", server.trim_end_matches('/')),
            key,
            key_digest,
            server_keys,
        })
    }

    /// Whether `body` is an approval countersign signed for this client,
    /// this invocation and this nonce.
    fn genuine(&self, body: &StatusBody, invocation: &str, nonce: &str) -> bool {
        let approval = countersign_core::approval_signing::Approval {
            request: &body.id,
            client: &self.key_digest,
            invocation,
            nonce,
        };
        body.signature
            .as_deref()
            .is_some_and(|s| countersign_core::approval_signing::verify(&self.server_keys, &approval, s))
    }

    async fn submit(&self, inv: &Invocation, nonce: &str) -> Result<(reqwest::StatusCode, StatusBody), Error> {
        let body = Submission { invocation: inv, nonce };
        let resp = self.http.post(&self.base).bearer_auth(&self.key).json(&body).send().await.map_err(net)?;
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
        let mut random = [0u8; 32];
        if let Err(e) = getrandom::getrandom(&mut random) {
            return Outcome::Refused(format!("no random numbers from the OS: {e}"));
        }
        let nonce = countersign_core::approval_signing::nonce(&random);
        let digest =
            countersign_core::approval_signing::invocation_digest(&inv.user, inv.cwd.as_deref(), &inv.sudo_argv);
        let forged = || Outcome::Refused("the approval is not signed by countersign; refusing".into());
        let (status, body) = match self.submit(inv, &nonce).await {
            Ok(r) => r,
            Err(e) => return Outcome::Refused(e.to_string()),
        };
        if body.state == "approved" {
            if !self.genuine(&body, &digest, &nonce) {
                return forged();
            }
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
                    Ok(b) if b.state == "approved" && b.id != id => return Some("answered for another request".into()),
                    Ok(b) if b.state == "approved" && !self.genuine(&b, &digest, &nonce) => {
                        return Some("forged".into());
                    }
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
                Some("forged") => forged(),
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
