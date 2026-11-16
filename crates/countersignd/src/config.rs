//! Configuration file loading and validation.
//!
//! The main file holds everything; `include` entries may add more
//! `[[policy]]` and `[[approver]]` tables (e.g. `policies.d/*.toml`). Secrets
//! never live here: components read them from `*_file` paths or environment
//! variables.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use countersign_core::{Approver, ApproverId, ApproverSelector, BackendName, ChannelName, Policy, PolicySet};
use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{path}: {source}")]
    Read { path: PathBuf, source: std::io::Error },
    #[error("{path}: {source}")]
    Parse { path: PathBuf, source: Box<toml::de::Error> },
    #[error("invalid configuration:\n  - {}", .0.join("\n  - "))]
    Invalid(Vec<String>),
}

/// The whole configuration after includes are merged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    pub store: StoreConfig,
    pub engine: EngineConfig,
    pub backends: BTreeMap<BackendName, BackendConfig>,
    pub channels: BTreeMap<ChannelName, ChannelConfig>,
    pub approvers: Vec<Approver>,
    pub policies: PolicySet,
    /// Where hosts submit subjects (needed by `host` backends).
    pub intake: Option<crate::intake::IntakeConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Base URL of the web UI, used in links sent to channels and as the
    /// base of the login callback URL.
    pub public_url: String,
    /// Address the web UI listens on. Keep it private (loopback, tailnet).
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// File with at least 32 bytes of secret key material for session
    /// cookies. Without it a random key is used and sessions end on restart.
    #[serde(default)]
    pub session_key_file: Option<PathBuf>,
    /// How long a web login lasts.
    #[serde(default = "default_session_ttl", with = "humantime_serde")]
    pub session_ttl: Duration,
    /// How recent the identity-provider authentication must be for a
    /// decision to count as `fresh-auth`.
    #[serde(default = "default_fresh_window", with = "humantime_serde")]
    pub fresh_auth_window: Duration,
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8080))
}

fn default_session_ttl() -> Duration {
    Duration::from_secs(12 * 3600)
}

fn default_fresh_window() -> Duration {
    Duration::from_secs(5 * 60)
}

/// How approvers log in to the web UI.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    #[cfg(feature = "auth-oidc")]
    #[serde(default)]
    pub oidc: Option<countersign_auth_oidc::OidcConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreConfig {
    #[serde(default = "default_store_path")]
    pub path: PathBuf,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self { path: default_store_path() }
    }
}

fn default_store_path() -> PathBuf {
    PathBuf::from("/var/lib/countersign/countersign.db")
}

/// What to do with a pending subject that matches no policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Unmatched {
    /// Leave it alone (another tool may handle it). Logged once per subject.
    #[default]
    Ignore,
    /// Reject it at the backend.
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineConfig {
    /// How often to poll backends and sweep timeouts.
    #[serde(default = "default_poll", with = "humantime_serde")]
    pub poll_interval: Duration,
    #[serde(default)]
    pub unmatched: Unmatched,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self { poll_interval: default_poll(), unmatched: Unmatched::Ignore }
    }
}

fn default_poll() -> Duration {
    Duration::from_secs(15)
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum BackendConfig {
    /// Hosts that submit `sudo` invocations through the intake API.
    Host(crate::intake::HostBackendConfig),
    #[cfg(feature = "backend-octelium")]
    Octelium(countersign_backend_octelium::OcteliumConfig),
    /// Any program speaking the exec JSON protocol.
    #[cfg(feature = "backend-exec")]
    Exec(countersign_backend_exec::ExecConfig),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ChannelConfig {
    /// Writes events to the daemon log. Useful for testing.
    Log {},
    /// Posts to a Discord channel; decisions via buttons over the Gateway.
    #[cfg(feature = "channel-discord")]
    Discord(countersign_channel_discord::DiscordConfig),
    /// Push notifications through an ntfy server, linking to the web UI.
    #[cfg(feature = "channel-ntfy")]
    Ntfy(countersign_channel_ntfy::NtfyConfig),
    /// Signed JSON events (Standard Webhooks), sent to a URL.
    #[cfg(feature = "channel-webhook")]
    Webhook(countersign_channel_webhook::WebhookConfig),
}

/// One file as written on disk.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MainFile {
    #[serde(default)]
    include: Vec<String>,
    server: ServerConfig,
    #[serde(default)]
    auth: AuthConfig,
    #[serde(default)]
    store: StoreConfig,
    #[serde(default)]
    engine: EngineConfig,
    #[serde(default)]
    backend: BTreeMap<BackendName, BackendConfig>,
    #[serde(default)]
    channel: BTreeMap<ChannelName, ChannelConfig>,
    #[serde(default)]
    approver: Vec<Approver>,
    #[serde(default)]
    policy: Vec<Policy>,
    #[serde(default)]
    intake: Option<crate::intake::IntakeConfig>,
}

/// An included file: only approvers and policies.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IncludeFile {
    #[serde(default)]
    approver: Vec<Approver>,
    #[serde(default)]
    policy: Vec<Policy>,
}

impl Config {
    /// Read, merge includes, and validate.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let main: MainFile = parse_file(path)?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        let mut approvers = main.approver;
        let mut policies = main.policy;
        for pattern in &main.include {
            for file in expand_include(base, pattern)? {
                let inc: IncludeFile = parse_file(&file)?;
                approvers.extend(inc.approver);
                policies.extend(inc.policy);
            }
        }
        let config = Self {
            server: main.server,
            auth: main.auth,
            store: main.store,
            engine: main.engine,
            backends: main.backend,
            channels: main.channel,
            approvers,
            policies: PolicySet { policies },
            intake: main.intake,
        };
        config.validate()?;
        Ok(config)
    }

    /// Parse a single file with no includes (for tests and tooling).
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let main: MainFile =
            toml::from_str(text).map_err(|e| ConfigError::Parse { path: "<inline>".into(), source: Box::new(e) })?;
        if !main.include.is_empty() {
            return Err(ConfigError::Invalid(vec!["include is not supported for inline configuration".into()]));
        }
        let config = Self {
            server: main.server,
            auth: main.auth,
            store: main.store,
            engine: main.engine,
            backends: main.backend,
            channels: main.channel,
            approvers: main.approver,
            policies: PolicySet { policies: main.policy },
            intake: main.intake,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut errors = Vec::new();

        if !(self.server.public_url.starts_with("https://") || self.server.public_url.starts_with("http://")) {
            errors.push(format!("server.public_url must be an http(s) URL, got {:?}", self.server.public_url));
        }
        if self.server.fresh_auth_window.is_zero() || self.server.fresh_auth_window > Duration::from_secs(3600) {
            errors.push("server.fresh_auth_window must be between 1s and 1h".into());
        }
        if self.server.session_ttl < Duration::from_secs(60) {
            errors.push("server.session_ttl must be at least 1m".into());
        }
        if self.engine.poll_interval < Duration::from_secs(1) {
            errors.push("engine.poll_interval must be at least 1s".into());
        }

        let mut ids = BTreeSet::new();
        for a in &self.approvers {
            if !ids.insert(&a.id) {
                errors.push(format!("approver {}: duplicate id", a.id));
            }
        }

        if let Err(es) = self.policies.validate() {
            errors.extend(es.into_iter().map(|e| e.to_string()));
        }
        for p in &self.policies.policies {
            if let Some(b) = &p.matcher.backend
                && !self.backends.contains_key(b)
            {
                errors.push(format!("policy {}: unknown backend {b}", p.name));
            }
            for sel in &p.approvers {
                match sel {
                    ApproverSelector::Approver(id) if !ids.contains(id) => {
                        errors.push(format!("policy {}: unknown approver {id}", p.name));
                    }
                    ApproverSelector::Group(g) if !self.approvers.iter().any(|a| a.groups.contains(g)) => {
                        errors.push(format!("policy {}: no approver is in group {g}", p.name));
                    }
                    _ => {}
                }
            }
        }

        let mut keys = BTreeSet::new();
        for (name, b) in &self.backends {
            if let BackendConfig::Host(h) = b {
                errors.extend(h.problems(name));
                for host in &h.hosts {
                    if !keys.insert(host.key_sha256.to_ascii_lowercase()) {
                        errors.push(format!("backend {name}: host {}: key_sha256 is used by another host", host.name));
                    }
                }
                if self.intake.is_none() {
                    errors.push(format!("backend {name}: host backends need an [intake] section"));
                }
            }
        }

        if errors.is_empty() { Ok(()) } else { Err(ConfigError::Invalid(errors)) }
    }

    /// The `host` backends, by name.
    pub fn host_backends(&self) -> BTreeMap<BackendName, crate::intake::HostBackendConfig> {
        self.backends
            .iter()
            .filter_map(|(n, b)| match b {
                BackendConfig::Host(h) => Some((n.clone(), h.clone())),
                #[allow(unreachable_patterns)]
                _ => None,
            })
            .collect()
    }

    pub fn approver_map(&self) -> BTreeMap<ApproverId, Approver> {
        self.approvers.iter().map(|a| (a.id.clone(), a.clone())).collect()
    }
}

fn parse_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read { path: path.into(), source })?;
    toml::from_str(&text).map_err(|e| ConfigError::Parse { path: path.into(), source: Box::new(e) })
}

/// Expand an include entry relative to `base`. Only the file-name part may
/// contain `*` (e.g. `policies.d/*.toml`); matches are sorted by name.
fn expand_include(base: &Path, pattern: &str) -> Result<Vec<PathBuf>, ConfigError> {
    let full = base.join(pattern);
    let name = full.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_owned();
    if !name.contains('*') {
        return Ok(vec![full]);
    }
    let dir = full.parent().unwrap_or(base).to_path_buf();
    // A wildcard over a directory that does not exist matches nothing.
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => return Err(ConfigError::Read { path: dir, source }),
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter(|e| e.file_name().to_str().is_some_and(|n| wildcard(&name, n)))
        .map(|e| e.path())
        .collect();
    files.sort();
    Ok(files)
}

/// `*`-only wildcard match.
fn wildcard(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !text.starts_with(first) || text.len() < first.len() + last.len() || !text.ends_with(last) {
        return false;
    }
    let mut rest = &text[first.len()..text.len() - last.len()];
    for mid in &parts[1..parts.len() - 1] {
        match rest.find(mid) {
            Some(i) => rest = &rest[i + mid.len()..],
            None => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) const EXAMPLE: &str = r#"
        [server]
        public_url = "https://countersign.example.ts.net"

        [store]
        path = "/tmp/cs.db"

        [engine]
        poll_interval = "10s"
        unmatched = "deny"

        [backend.oct]
        type = "octelium"
        domain = "oct.example.com"

        [channel.log]
        type = "log"

        [[approver]]
        id = "alice"
        groups = ["ops"]
        identities = ["oidc:https://id.example.com#alice"]

        [[policy]]
        name = "agents"
        match = { backend = "oct", requester_group = "agents" }
        approvers = ["group:ops"]
        max_ttl = "30m"
    "#;

    #[test]
    fn parses_example() {
        let c = Config::from_toml(EXAMPLE).unwrap();
        assert_eq!(c.engine.poll_interval, Duration::from_secs(10));
        assert_eq!(c.engine.unmatched, Unmatched::Deny);
        assert!(matches!(c.backends[&BackendName::from("oct")], BackendConfig::Octelium(_)));
        assert!(matches!(c.channels[&ChannelName::from("log")], ChannelConfig::Log {}));
        assert_eq!(c.approvers.len(), 1);
        assert_eq!(c.policies.policies.len(), 1);
    }

    #[test]
    fn defaults() {
        let c = Config::from_toml("[server]\npublic_url = \"http://localhost:8080\"\n").unwrap();
        assert_eq!(c.store.path, default_store_path());
        assert_eq!(c.engine, EngineConfig::default());
    }

    #[test]
    fn reports_all_reference_errors() {
        let text = r#"
            [server]
            public_url = "localhost"

            [[approver]]
            id = "a"
            [[approver]]
            id = "a"

            [[policy]]
            name = "p"
            match = { backend = "missing" }
            approvers = ["approver:ghost", "group:nobody"]
            max_ttl = "1m"
        "#;
        let ConfigError::Invalid(errs) = Config::from_toml(text).unwrap_err() else { panic!() };
        let all = errs.join("\n");
        for needle in
            ["public_url", "duplicate id", "unknown backend missing", "unknown approver ghost", "group nobody"]
        {
            assert!(all.contains(needle), "missing {needle:?} in:\n{all}");
        }
    }

    #[test]
    fn rejects_unknown_keys_and_types() {
        assert!(Config::from_toml("[server]\npublic_url='http://x'\npublic_ulr='y'\n").is_err());
        assert!(Config::from_toml("[server]\npublic_url='http://x'\n[backend.b]\ntype='nope'\n").is_err());
    }

    #[test]
    fn loads_includes_in_order() {
        let dir = std::env::temp_dir().join(format!("countersignd-config-{}", countersign_core::RequestId::new()));
        std::fs::create_dir_all(dir.join("policies.d")).unwrap();
        std::fs::write(
            dir.join("config.toml"),
            "include = [\"policies.d/*.toml\"]\n[server]\npublic_url = \"http://localhost\"\n\
             [[approver]]\nid = \"alice\"\ngroups = [\"ops\"]\n",
        )
        .unwrap();
        for (file, name) in [("20-b.toml", "second"), ("10-a.toml", "first")] {
            std::fs::write(
                dir.join("policies.d").join(file),
                format!("[[policy]]\nname = \"{name}\"\napprovers = [\"group:ops\"]\nmax_ttl = \"5m\"\n"),
            )
            .unwrap();
        }
        std::fs::write(dir.join("policies.d").join("ignored.txt"), "not toml").unwrap();

        let c = Config::load(&dir.join("config.toml")).unwrap();
        let names: Vec<_> = c.policies.policies.iter().map(|p| p.name.as_str().to_owned()).collect();
        assert_eq!(names, ["first", "second"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_include_dir_matches_nothing_but_missing_file_fails() {
        let dir = std::env::temp_dir().join(format!("countersignd-config-{}", countersign_core::RequestId::new()));
        std::fs::create_dir_all(&dir).unwrap();
        let main = dir.join("config.toml");
        std::fs::write(
            &main,
            "include = [\"policies.d/*.toml\"]
[server]
public_url = \"http://localhost\"
",
        )
        .unwrap();
        Config::load(&main).unwrap();
        std::fs::write(
            &main,
            "include = [\"extra.toml\"]
[server]
public_url = \"http://localhost\"
",
        )
        .unwrap();
        assert!(matches!(Config::load(&main), Err(ConfigError::Read { .. })));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn example_file_is_valid() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.example.toml");
        let c = Config::load(&path).unwrap();
        assert_eq!(c.policies.policies.len(), 1);
    }

    #[test]
    fn wildcard_cases() {
        assert!(wildcard("*.toml", "a.toml"));
        assert!(!wildcard("*.toml", "a.toml.bak"));
        assert!(wildcard("10-*.toml", "10-x.toml"));
        assert!(!wildcard("a*a", "a"));
    }
}
