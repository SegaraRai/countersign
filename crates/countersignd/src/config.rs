//! Configuration file loading and validation.
//!
//! The main file holds everything; `include` entries may add more persons,
//! workloads, groups, clients and policies (e.g. `policies.d/*.toml`).
//! Secrets never live here: components read them from `*_file` paths or
//! environment variables, and clients are known only by the SHA-256 of their
//! keys.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use countersign_core::host_key;
use countersign_core::{
    ActorId, BackendName, ChannelName, ClientId, Directory, GroupConfig, PersonConfig, Policy, PolicySet,
    QuestionPolicy, QuestionPolicySet, Roles, WorkloadConfig,
};

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
    pub persons: Vec<PersonConfig>,
    pub workloads: Vec<WorkloadConfig>,
    pub groups: Vec<GroupConfig>,
    pub roles: Roles,
    pub clients: Vec<ClientConfig>,
    pub policies: PolicySet,
    pub question_policies: QuestionPolicySet,
    /// Where clients submit requests and questions.
    pub intake: Option<crate::intake::IntakeConfig>,
    /// Built from persons, workloads, groups and roles by validation.
    directory: Directory,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Base URL of the web UI, used in links sent to channels and as the
    /// base of the login callback URL.
    pub public_url: String,
    /// Address the web UI listens on. Without `tls`, it serves plain HTTP
    /// for a reverse proxy or tunnel that terminates TLS: keep it on a
    /// loopback or private address.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Terminate TLS here instead.
    #[serde(default)]
    pub tls: Option<crate::tls::TlsConfig>,
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
    /// How long groups reported by the identity provider at sign-in count.
    /// Defaults to `session_ttl`.
    #[serde(default, with = "humantime_serde")]
    pub idp_groups_max_age: Option<Duration>,
}

impl ServerConfig {
    pub fn idp_max_age(&self) -> Duration {
        self.idp_groups_max_age.unwrap_or(self.session_ttl)
    }
}

/// Whether `ip` is reachable only from a private network (loopback, RFC 1918,
/// CGNAT/tailnet, link-local, IPv6 unique-local). The unspecified address
/// (all interfaces) is not.
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || (a == 100 && (64..128).contains(&b))
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            v6.is_loopback() || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
    }
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8080))
}

fn default_session_ttl() -> Duration {
    Duration::from_hours(12)
}

fn default_fresh_window() -> Duration {
    Duration::from_mins(5)
}

/// How persons sign in to the web UI.
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
    /// How long finished (terminal) requests, questions and delivered outbox
    /// entries are kept before automatic cleanup. Unset keeps them forever.
    #[serde(default, with = "humantime_serde")]
    pub retention: Option<Duration>,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self { path: default_store_path(), retention: None }
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
    /// `sudo` invocations that clients submit through the intake API.
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
    /// Posts to a Slack channel with Block Kit buttons; receives actions over Socket Mode.
    #[cfg(feature = "channel-slack")]
    Slack(countersign_channel_slack::SlackConfig),
    /// Signed JSON events (Standard Webhooks), sent to a URL.
    #[cfg(feature = "channel-webhook")]
    Webhook(countersign_channel_webhook::WebhookConfig),
    /// Browser Web Push (RFC 8291 + VAPID), sent only to eligible approvers/responders.
    #[cfg(feature = "channel-webpush")]
    Webpush(countersign_channel_webpush::WebPushConfig),
}

/// What a client key may be used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    /// Submit `sudo` approvals (`/intake/v1/requests`).
    Approval,
    /// Ask questions (`/intake/v1/questions`).
    Question,
}

/// `[[client]]`: a program that talks to the intake API with its own key.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// Also the namespace of the requesters it may name: `unix:<id>#<user>`,
    /// and the target of its `sudo` requests.
    pub id: ClientId,
    pub auth: ClientAuth,
    /// Defaults to `["approval"]`.
    #[serde(default = "default_scopes")]
    pub scopes: BTreeSet<Scope>,
    /// If set, requests with this key must come from one of these addresses.
    #[serde(default)]
    pub allowed_ips: Vec<IpAddr>,
    /// The `host` backend its approvals belong to. Needed only when there is
    /// more than one.
    #[serde(default)]
    pub backend: Option<BackendName>,
    /// The actor whose questions this client asks (e.g. an agent workload).
    #[serde(default)]
    pub actor: Option<ActorId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum ClientAuth {
    /// Static `cshk_` client key (stored as `sha256:<hex>`).
    HostKey {
        /// `sha256:` and the lowercase hex SHA-256 of the client's `cshk_` key,
        /// as printed by `countersign host-key`. Never the key itself.
        host_key: String,
    },
    /// CI OIDC JWT (GitHub Actions, GitLab CI, etc.), verified via JWKS.
    Oidc { oidc: OidcClientAuth },
}

impl ClientAuth {
    pub fn host_key(&self) -> Option<&str> {
        match self {
            Self::HostKey { host_key } => Some(host_key.as_str()),
            Self::Oidc { .. } => None,
        }
    }

    pub fn oidc(&self) -> Option<&OidcClientAuth> {
        match self {
            Self::Oidc { oidc } => Some(oidc),
            Self::HostKey { .. } => None,
        }
    }
}

/// OIDC JWT verification rules for a CI `[[client]]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcClientAuth {
    /// Expected `iss` claim and discovery base URL (`https://...`).
    pub issuer: String,
    /// Expected `aud` claim.
    pub audience: String,
    /// Optional required claim matches (glob patterns, e.g. `repository = "org/*"`).
    #[serde(default)]
    pub claims: BTreeMap<String, String>,
    /// Claim holding the initiator's subject (e.g. `"actor_id"` for GitHub).
    #[serde(default)]
    pub initiator_claim: Option<String>,
    /// Recognition identity scheme for `initiator_claim` (e.g. `"github"` -> `github:<val>`).
    #[serde(default)]
    pub initiator_scheme: Option<String>,
    /// Optional explicit JWKS URL (skips `.well-known/openid-configuration`).
    #[serde(default)]
    pub jwks_uri: Option<String>,
}

fn default_scopes() -> BTreeSet<Scope> {
    BTreeSet::from([Scope::Approval])
}

impl ClientConfig {
    pub fn has_scope(&self, scope: Scope) -> bool {
        self.scopes.contains(&scope)
    }
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
    roles: Roles,
    #[serde(default)]
    intake: Option<crate::intake::IntakeConfig>,
    #[serde(default)]
    person: Vec<PersonConfig>,
    #[serde(default)]
    workload: Vec<WorkloadConfig>,
    #[serde(default)]
    group: Vec<GroupConfig>,
    #[serde(default)]
    client: Vec<ClientConfig>,
    #[serde(default)]
    policy: Vec<Policy>,
    #[serde(default)]
    question_policy: Vec<QuestionPolicy>,
}

/// The tables that included files may add to.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Lists {
    #[serde(default)]
    person: Vec<PersonConfig>,
    #[serde(default)]
    workload: Vec<WorkloadConfig>,
    #[serde(default)]
    group: Vec<GroupConfig>,
    #[serde(default)]
    client: Vec<ClientConfig>,
    #[serde(default)]
    policy: Vec<Policy>,
    #[serde(default)]
    question_policy: Vec<QuestionPolicy>,
}

impl MainFile {
    fn extend(&mut self, other: Lists) {
        self.person.extend(other.person);
        self.workload.extend(other.workload);
        self.group.extend(other.group);
        self.client.extend(other.client);
        self.policy.extend(other.policy);
        self.question_policy.extend(other.question_policy);
    }
}

impl Config {
    /// Read, merge includes, and validate.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let mut main: MainFile = parse_file(path)?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        for pattern in std::mem::take(&mut main.include) {
            for file in expand_include(base, &pattern)? {
                let inc: Lists = parse_file(&file)?;
                main.extend(inc);
            }
        }
        Self::build(main)
    }

    /// Parse a single file with no includes (for tests and tooling).
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let main: MainFile =
            toml::from_str(text).map_err(|e| ConfigError::Parse { path: "<inline>".into(), source: Box::new(e) })?;
        if !main.include.is_empty() {
            return Err(ConfigError::Invalid(vec!["include is not supported for inline configuration".into()]));
        }
        Self::build(main)
    }

    fn build(main: MainFile) -> Result<Self, ConfigError> {
        let MainFile { person, workload, group, client, policy, question_policy, .. } = main;
        let mut config = Self {
            server: main.server,
            auth: main.auth,
            store: main.store,
            engine: main.engine,
            backends: main.backend,
            channels: main.channel,
            persons: person,
            workloads: workload,
            groups: group,
            roles: main.roles,
            clients: client,
            policies: PolicySet { policies: policy },
            question_policies: QuestionPolicySet { policies: question_policy },
            intake: main.intake,
            directory: Directory::default(),
        };
        config.validate()?;
        Ok(config)
    }

    /// Everyone in the configuration, checked.
    pub fn directory(&self) -> &Directory {
        &self.directory
    }

    fn validate(&mut self) -> Result<(), ConfigError> {
        let mut errors = Vec::new();

        if !countersign_core::url::is_secure(&self.server.public_url) {
            errors.push(format!(
                "server.public_url must be an https:// URL (http:// only for localhost), got {:?}",
                self.server.public_url
            ));
        }
        if let Some(intake) = &self.intake {
            errors.extend(intake.problems());
            if !intake.knows_client_address() {
                for c in self.clients.iter().filter(|c| !c.allowed_ips.is_empty()) {
                    errors.push(format!(
                        "client {}: allowed_ips cannot be checked behind a proxy without intake.client_ip_header",
                        c.id
                    ));
                }
            }
        }
        if self.server.fresh_auth_window.is_zero() || self.server.fresh_auth_window > Duration::from_secs(3600) {
            errors.push("server.fresh_auth_window must be between 1s and 1h".into());
        }
        if self.server.session_ttl < Duration::from_secs(60) {
            errors.push("server.session_ttl must be at least 1m".into());
        }
        if self.server.idp_groups_max_age.is_some_and(|d| d < Duration::from_secs(60)) {
            errors.push("server.idp_groups_max_age must be at least 1m".into());
        }
        if self.engine.poll_interval < Duration::from_secs(1) {
            errors.push("engine.poll_interval must be at least 1s".into());
        }
        if self.store.retention.is_some_and(|d| d < Duration::from_hours(1)) {
            errors.push("store.retention must be at least 1h".into());
        }

        match Directory::new(self.persons.clone(), self.workloads.clone(), self.groups.clone(), self.roles.clone()) {
            Ok(d) => self.directory = d,
            Err(es) => errors.extend(es),
        }
        let dir = &self.directory;

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
                if let Some(problem) = dir.selector_problem(sel) {
                    errors.push(format!("policy {}: {problem}", p.name));
                }
            }
            for ch in &p.channels {
                if !self.channels.contains_key(ch) {
                    errors.push(format!("policy {}: unknown channel {ch}", p.name));
                }
            }
        }
        if let Err(es) = self.question_policies.validate() {
            errors.extend(es);
        }
        for p in &self.question_policies.policies {
            for sel in &p.responders {
                if let Some(problem) = dir.selector_problem(sel) {
                    errors.push(format!("question_policy {}: {problem}", p.name));
                }
            }
            for ch in &p.channels {
                if !self.channels.contains_key(ch) {
                    errors.push(format!("question_policy {}: unknown channel {ch}", p.name));
                }
            }
        }

        errors.extend(self.client_problems());
        if self.roles.member.is_empty() {
            errors.push("roles.member is empty: nobody could decide or answer anything".into());
        }

        if errors.is_empty() { Ok(()) } else { Err(ConfigError::Invalid(errors)) }
    }

    fn client_problems(&self) -> Vec<String> {
        let mut errors = Vec::new();
        let hosts: Vec<&BackendName> =
            self.backends.iter().filter(|(_, b)| matches!(b, BackendConfig::Host(_))).map(|(n, _)| n).collect();
        let mut ids = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for c in &self.clients {
            let id = &c.id;
            if !countersign_core::actor::is_name(id.as_str()) {
                errors.push(format!("client {id:?}: ids are letters, digits, '-', '_' and '.'"));
            }
            if !ids.insert(id) {
                errors.push(format!("client {id}: duplicate id"));
            }
            match &c.auth {
                ClientAuth::HostKey { host_key } => {
                    if let Err(why) = host_key::parse_reference(host_key) {
                        errors.push(format!("client {id}: auth.host_key: {why}"));
                    } else if !keys.insert(host_key.clone()) {
                        errors.push(format!("client {id}: auth.host_key is used by another client"));
                    }
                }
                ClientAuth::Oidc { oidc } => {
                    if !countersign_core::url::is_secure(&oidc.issuer) {
                        errors.push(format!(
                            "client {id}: auth.oidc.issuer must be https:// (http:// only for localhost), got {:?}",
                            oidc.issuer
                        ));
                    }
                    if oidc.audience.trim().is_empty() {
                        errors.push(format!("client {id}: auth.oidc.audience must not be empty"));
                    }
                    if let Some(jwks) = &oidc.jwks_uri
                        && !countersign_core::url::is_secure(jwks)
                    {
                        errors.push(format!(
                            "client {id}: auth.oidc.jwks_uri must be https:// (http:// only for localhost), got {jwks:?}"
                        ));
                    }
                }
            }
            if c.scopes.is_empty() {
                errors.push(format!("client {id}: scopes is empty"));
            }
            if c.has_scope(Scope::Approval) {
                match &c.backend {
                    Some(b) if !hosts.contains(&b) => {
                        errors.push(format!("client {id}: backend {b} is not a host backend"));
                    }
                    None if hosts.len() != 1 => errors.push(format!(
                        "client {id}: the approval scope needs a host backend; set backend (there are {})",
                        hosts.len()
                    )),
                    _ => {}
                }
            } else if c.backend.is_some() {
                errors.push(format!("client {id}: backend is only used with the approval scope"));
            }
            if let Some(a) = &c.actor
                && self.directory.actor(a).is_none()
            {
                errors.push(format!("client {id}: unknown actor {a}"));
            }
            if c.actor.is_some() && !c.has_scope(Scope::Question) {
                errors.push(format!("client {id}: actor is only used with the question scope"));
            }
        }
        if !self.clients.is_empty() && self.intake.is_none() {
            errors.push("clients need an [intake] section".into());
        }
        if !hosts.is_empty() && self.intake.is_none() {
            errors.push("host backends need an [intake] section".into());
        }
        errors
    }

    /// The host backend a client's approvals go to.
    pub fn client_backend(&self, client: &ClientConfig) -> Option<BackendName> {
        client.backend.clone().or_else(|| {
            let mut hosts = self.backends.iter().filter(|(_, b)| matches!(b, BackendConfig::Host(_)));
            match (hosts.next(), hosts.next()) {
                (Some((n, _)), None) => Some(n.clone()),
                _ => None,
            }
        })
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

    const KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    pub(crate) const EXAMPLE: &str = r#"
        [server]
        public_url = "https://countersign.example.com"

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

        [[person]]
        id = "alice"
        identities = ["oidc:https://id.example.com#alice"]

        [[group]]
        name = "ops"
        members = ["alice"]

        [roles]
        member = ["group:ops"]

        [[policy]]
        name = "agents"
        match = { backend = "oct", backend_group = "agents" }
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
        assert_eq!(c.persons.len(), 1);
        assert!(c.directory().actor(&"alice".into()).is_some());
        assert_eq!(c.policies.policies.len(), 1);
        assert_eq!(c.server.idp_max_age(), c.server.session_ttl);
    }

    #[test]
    fn needs_members() {
        let ConfigError::Invalid(errs) =
            Config::from_toml("[server]\npublic_url = \"http://localhost:8080\"\n").unwrap_err()
        else {
            panic!()
        };
        assert!(errs.join("\n").contains("roles.member"));
    }

    #[test]
    fn reports_all_reference_errors() {
        let text = r#"
            [server]
            public_url = "localhost"

            [[person]]
            id = "a"
            [[person]]
            id = "a"

            [roles]
            member = ["person:a"]

            [[policy]]
            name = "p"
            match = { backend = "missing" }
            approvers = ["person:ghost", "group:nobody"]
            max_ttl = "1m"

            [[question_policy]]
            name = "q"
            responders = ["person:nobody"]
        "#;
        let ConfigError::Invalid(errs) = Config::from_toml(text).unwrap_err() else { panic!() };
        let all = errs.join("\n");
        for needle in ["public_url", "duplicate", "unknown backend missing", "ghost", "nobody", "question_policy q"] {
            assert!(all.contains(needle), "missing {needle:?} in:\n{all}");
        }
    }

    #[test]
    fn checks_clients() {
        let base = "[server]\npublic_url = 'https://x'\n[[person]]\nid = 'a'\n[roles]\nmember = ['person:a']\n\
             [intake]\nlisten = '127.0.0.1:9000'\nbehind_proxy = true\nsigning_key_file = 'k'\n[backend.h1]\ntype = 'host'\n"
            .to_string();
        let ok = format!(
            "{base}[[client]]\nid = 'web-1'\nauth = {{ host_key = 'sha256:{KEY}' }}\n\
             [[client]]\nid = 'agent'\nauth = {{ host_key = 'sha256:{}' }}\nscopes = ['question']\nactor = 'a'\n",
            KEY.replace('1', "2")
        );
        let c = Config::from_toml(&ok).unwrap();
        assert_eq!(c.client_backend(&c.clients[0]), Some("h1".into()), "the only host backend");
        assert!(!c.clients[1].has_scope(Scope::Approval));

        let bad = format!(
            "{base}[backend.h2]\ntype = 'host'\n\
             [[client]]\nid = 'web-1'\nauth = {{ host_key = 'sha256:{KEY}' }}\nactor = 'ghost'\n\
             [[client]]\nid = 'web-1'\nauth = {{ host_key = 'sha256:{KEY}' }}\nbackend = 'h1'\n"
        );
        let ConfigError::Invalid(errs) = Config::from_toml(&bad).unwrap_err() else { panic!() };
        let all = errs.join("\n");
        for needle in ["set backend", "duplicate id", "used by another client", "unknown actor ghost", "question scope"]
        {
            assert!(all.contains(needle), "missing {needle:?} in:\n{all}");
        }
    }

    #[test]
    fn public_url_must_be_https_except_on_this_machine() {
        let text =
            "[server]\npublic_url = 'http://cs.example.test'\n[[person]]\nid = 'a'\n[roles]\nmember = ['person:a']\n";
        let ConfigError::Invalid(errs) = Config::from_toml(text).unwrap_err() else { panic!() };
        assert!(errs.join("\n").contains("https://"), "{errs:?}");
    }

    #[test]
    fn intake_must_be_https_or_behind_a_private_proxy() {
        let base = "[server]\npublic_url = 'https://x'\n[[person]]\nid = 'a'\n[roles]\nmember = ['person:a']\n";
        let client = format!(
            "[[client]]\nid = 'web-1'\nauth = {{ host_key = 'sha256:{KEY}' }}\nscopes = ['question']\n\
             actor = 'a'\nallowed_ips = ['192.0.2.1']\n"
        );
        let errors = |intake: &str| match Config::from_toml(&format!(
            "{base}[intake]\nsigning_key_file = 'k'\n{intake}\n{client}"
        )) {
            Ok(_) => String::new(),
            Err(ConfigError::Invalid(e)) => e.join("\n"),
            Err(e) => panic!("{e}"),
        };
        assert!(errors("listen = '127.0.0.1:9000'").contains("set tls"));
        assert!(errors("listen = '0.0.0.0:9000'\nbehind_proxy = true").contains("loopback or private"));
        assert!(
            errors("listen = '127.0.0.1:9000'\nbehind_proxy = true\ntls = { cert_file = 'c', key_file = 'k' }")
                .contains("exclude each other")
        );
        assert!(errors("listen = '127.0.0.1:9000'\nbehind_proxy = true").contains("allowed_ips cannot be checked"));
        assert!(errors("listen = '127.0.0.1:9000'\nclient_ip_header = 'x-forwarded-for'").contains("only used with"));
        assert!(
            errors("listen = '127.0.0.1:9000'\nbehind_proxy = true\nclient_ip_header = 'bad header'")
                .contains("not a header name")
        );
        assert_eq!(errors("listen = '127.0.0.1:9000'\nbehind_proxy = true\nclient_ip_header = 'x-forwarded-for'"), "");
        // Terminating TLS itself, it may listen anywhere; the files are read at startup.
        assert_eq!(errors("listen = '0.0.0.0:9000'\ntls = { cert_file = 'c', key_file = 'k' }"), "");
    }

    #[test]
    fn rejects_unknown_keys_and_types() {
        assert!(Config::from_toml("[server]\npublic_url='http://x'\npublic_ulr='y'\n").is_err());
        assert!(Config::from_toml("[server]\npublic_url='http://x'\n[backend.b]\ntype='nope'\n").is_err());
        assert!(Config::from_toml("[server]\npublic_url='http://x'\n[[approver]]\nid='a'\n").is_err(), "old tables");
    }

    #[test]
    fn loads_includes_in_order() {
        let dir = std::env::temp_dir().join(format!("countersignd-config-{}", countersign_core::RequestId::new()));
        std::fs::create_dir_all(dir.join("policies.d")).unwrap();
        std::fs::write(
            dir.join("config.toml"),
            "include = [\"policies.d/*.toml\"]\n[server]\npublic_url = \"http://localhost\"\n\
             [roles]\nmember = [\"group:ops\"]\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("policies.d").join("00-people.toml"),
            "[[person]]\nid = \"alice\"\n[[group]]\nname = \"ops\"\nmembers = [\"alice\"]\n",
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
        assert_eq!(c.persons.len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_include_dir_matches_nothing_but_missing_file_fails() {
        let dir = std::env::temp_dir().join(format!("countersignd-config-{}", countersign_core::RequestId::new()));
        std::fs::create_dir_all(&dir).unwrap();
        let main = dir.join("config.toml");
        let head =
            "[server]\npublic_url = \"http://localhost\"\n[[person]]\nid = \"a\"\n[roles]\nmember = [\"person:a\"]\n";
        std::fs::write(&main, format!("include = [\"policies.d/*.toml\"]\n{head}")).unwrap();
        Config::load(&main).unwrap();
        std::fs::write(&main, format!("include = [\"extra.toml\"]\n{head}")).unwrap();
        assert!(matches!(Config::load(&main), Err(ConfigError::Read { .. })));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn example_file_is_valid() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.example.toml");
        let c = Config::load(&path).unwrap();
        assert_ne!(c.policies.policies, [] as [countersign_core::Policy; 0]);
        assert_ne!(c.question_policies.policies, [] as [countersign_core::QuestionPolicy; 0]);
    }

    #[test]
    fn wildcard_cases() {
        assert!(wildcard("*.toml", "a.toml"));
        assert!(!wildcard("*.toml", "a.toml.bak"));
        assert!(wildcard("10-*.toml", "10-x.toml"));
        assert!(!wildcard("a*a", "a"));
    }

    #[test]
    fn private_addresses() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.10",
            "100.127.255.1",
            "::1",
            "fd7a:115c:a1e0::1",
            "fe80::1",
        ] {
            assert!(is_private(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["0.0.0.0", "::", "8.8.8.8", "100.128.0.1", "2001:db8::1"] {
            assert!(!is_private(ip.parse().unwrap()), "{ip}");
        }
    }
}
