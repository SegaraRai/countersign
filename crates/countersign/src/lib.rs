//! Administration CLI for countersign, run on the daemon's host.
//!
//! It reads the same configuration and database as `countersignd`, so using
//! it takes the same access as reading those files. It deliberately offers no
//! way to *approve*: approvals go through the web UI or chat, where the
//! policy's assurance level is enforced. Denying and revoking only reduce
//! access and are recorded under the approver named with `--as`.

use std::fmt::Write as _;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use clap::{Subcommand, ValueEnum};
use countersign_core::{
    AccessBackend, ActionIntent, ApproverId, Assurance, ChannelName, Request, RequestFilter, RequestId, RequestState,
    Store, StoreError, Verdict,
};
use countersignd::config::Config;
use countersignd::engine::{Engine, EngineError};
use jiff::Timestamp;

/// Name recorded as the channel of decisions made here.
pub const VIA: &str = "cli";

#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    /// List requests (open ones unless --all).
    Requests {
        #[arg(long)]
        all: bool,
        #[arg(long, default_value_t = 50)]
        limit: u32,
        #[arg(long)]
        json: bool,
    },
    /// Show one request.
    Show {
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Deny a pending request on behalf of an approver.
    Deny {
        id: String,
        /// Approver to record the decision under (must be eligible).
        #[arg(long = "as", value_name = "APPROVER")]
        approver: String,
        #[arg(long)]
        comment: Option<String>,
    },
    /// End an active grant early on behalf of an approver.
    Revoke {
        id: String,
        #[arg(long = "as", value_name = "APPROVER")]
        approver: String,
    },
    /// List chat accounts linked to approvers.
    Links {
        #[arg(long)]
        json: bool,
    },
    /// Remove a chat account link.
    Unlink { channel: String, external_id: String },
    /// Write a new random secret to a file (mode 0600), e.g. for
    /// `server.session_key_file`, a webhook `secret_file`, or a host key
    /// (`--format host` also prints the `key_sha256` line for the
    /// configuration).
    Keygen {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = KeyFormat::Hex)]
        format: KeyFormat,
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum KeyFormat {
    /// 64 hex characters (256 bits).
    Hex,
    /// `whsec_<base64>` (Standard Webhooks, 256 bits).
    Whsec,
    /// A host key for the intake API (64 hex characters).
    Host,
}

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("{0}")]
    Usage(String),
    #[error(transparent)]
    Engine(#[from] EngineError),
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// What the commands that touch state need.
pub struct Context {
    pub config: Config,
    pub store: Arc<dyn Store>,
    pub backends: Vec<Arc<dyn AccessBackend>>,
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context").finish_non_exhaustive()
    }
}

/// Run a command that needs the configuration and database.
pub async fn execute(cmd: Command, ctx: Context, out: &mut dyn Write) -> Result<(), CliError> {
    let now = Timestamp::now();
    let engine = || Engine::new(Arc::clone(&ctx.store), ctx.backends.clone(), countersignd::rules_from(&ctx.config));
    match cmd {
        Command::Requests { all, limit, json } => {
            let list = ctx.store.list_requests(&RequestFilter { open_only: !all, limit: Some(limit) }).await?;
            if json {
                writeln!(out, "{}", serde_json::to_string_pretty(&list).map_err(std::io::Error::other)?)?;
            } else {
                out.write_all(table(&list).as_bytes())?;
            }
        }
        Command::Show { id, json } => {
            let r = ctx.store.get_request(parse_id(&id)?).await?.ok_or_else(|| not_found(&id))?;
            if json {
                writeln!(out, "{}", serde_json::to_string_pretty(&r).map_err(std::io::Error::other)?)?;
            } else {
                out.write_all(details(&r).as_bytes())?;
            }
        }
        Command::Deny { id, approver, comment } => {
            let intent = ActionIntent {
                request_id: parse_id(&id)?,
                verdict: Verdict::Deny,
                approver: ApproverId::new(approver),
                // Denials are accepted at any assurance; record the lowest.
                assurance: Assurance::Linked,
                via: ChannelName::new(VIA),
                comment: comment.map(|c| c.trim().to_owned()).filter(|c| !c.is_empty()),
            };
            let r = engine().decide(intent, now).await?;
            writeln!(out, "{}: {}", r.id, r.state.name())?;
        }
        Command::Revoke { id, approver } => {
            let r = engine().revoke(parse_id(&id)?, &ApproverId::new(approver), now).await?;
            writeln!(out, "{}: {}", r.id, r.state.name())?;
        }
        Command::Links { json } => {
            let links = ctx.store.list_account_links().await?;
            if json {
                writeln!(out, "{}", serde_json::to_string_pretty(&links).map_err(std::io::Error::other)?)?;
            } else {
                let rows: Vec<Vec<String>> = links
                    .iter()
                    .map(|l| {
                        let known = ctx.config.approvers.iter().any(|a| a.id == l.approver);
                        vec![
                            l.channel.to_string(),
                            l.external_id.clone(),
                            if known { l.approver.to_string() } else { format!("{} (unknown)", l.approver) },
                            short_time(l.linked_at),
                        ]
                    })
                    .collect();
                out.write_all(render_table(&["CHANNEL", "ACCOUNT", "APPROVER", "LINKED"], &rows).as_bytes())?;
            }
        }
        Command::Unlink { channel, external_id } => {
            if !ctx.store.unlink_account(&ChannelName::new(channel.clone()), &external_id).await? {
                return Err(CliError::Usage(format!("no link for {external_id} on {channel}")));
            }
            writeln!(out, "unlinked {external_id} on {channel}")?;
        }
        Command::Keygen { path, format, force } => {
            if let Some(line) = keygen(&path, format, force)? {
                writeln!(out, "{line}")?;
            }
        }
    }
    Ok(())
}

fn parse_id(id: &str) -> Result<RequestId, CliError> {
    id.parse().map_err(|_| CliError::Usage(format!("not a request id: {id}")))
}

fn not_found(id: &str) -> CliError {
    CliError::Usage(format!("no request {id}"))
}

fn short_time(t: Timestamp) -> String {
    t.strftime("%Y-%m-%d %H:%M:%SZ").to_string()
}

/// Untrusted text for a terminal: no control characters (escape sequences).
fn clean(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}

fn render_table(header: &[&str], rows: &[Vec<String>]) -> String {
    if rows.is_empty() {
        return "(none)\n".to_owned();
    }
    let mut widths: Vec<usize> = header.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let mut out = String::new();
    let mut line = |cells: &mut dyn Iterator<Item = &str>| {
        let parts: Vec<String> = cells.zip(&widths).map(|(c, w)| format!("{c:<w$}")).collect();
        let _ = writeln!(out, "{}", parts.join("  ").trim_end());
    };
    line(&mut header.iter().copied());
    for row in rows {
        line(&mut row.iter().map(String::as_str));
    }
    out
}

/// One line per request.
pub fn table(list: &[Request]) -> String {
    let rows: Vec<Vec<String>> = list
        .iter()
        .map(|r| {
            vec![
                r.id.to_string(),
                r.state.name().to_owned(),
                clean(&r.facts.requester.id),
                r.facts.target.as_deref().map(clean).unwrap_or_default(),
                r.requirements.policy.to_string(),
                short_time(r.created_at),
            ]
        })
        .collect();
    render_table(&["ID", "STATE", "REQUESTER", "TARGET", "POLICY", "CREATED"], &rows)
}

/// Everything about one request.
pub fn details(r: &Request) -> String {
    let f = &r.facts;
    let mut s = String::new();
    let mut kv = |k: &str, v: &str| {
        // Keys longer than the column still get a separating space.
        let _ = writeln!(s, "{k:<13} {v}");
    };
    kv("id", &r.id.to_string());
    kv("state", r.state.name());
    match &r.state {
        RequestState::Active { until } => kv("active until", &short_time(*until)),
        RequestState::Failed { error } => kv("error", &clean(error)),
        RequestState::Pending => kv("decide by", &short_time(r.pending_until)),
        _ => {}
    }
    kv("subject", &format!("{}/{}/{}", r.subject.backend, clean(&r.subject.kind), clean(&r.subject.id)));
    let name = f.requester.display_name.as_deref().map(|n| format!(" ({})", clean(n))).unwrap_or_default();
    kv("requester", &format!("{}{name}", clean(&f.requester.id)));
    if !f.requester.groups.is_empty() {
        kv("groups", &f.requester.groups.iter().map(|g| clean(g)).collect::<Vec<_>>().join(", "));
    }
    if let Some(t) = &f.target {
        kv("target", &clean(t));
    }
    if let Some(reason) = &f.reason {
        kv("reason", &clean(reason));
    }
    for (k, v) in &f.attributes {
        kv(&format!("attr.{}", clean(k)), &clean(v));
    }
    let q = &r.requirements;
    kv("policy", q.policy.as_str());
    kv(
        "needs",
        &format!(
            "{} approval(s) at {}, {} for {}s{}",
            q.quorum,
            q.min_assurance,
            q.grant.as_str(),
            q.ttl.as_secs(),
            if q.allow_self_approval { ", self-approval allowed" } else { "" }
        ),
    );
    kv("created", &short_time(r.created_at));
    for d in &r.decisions {
        let verdict = match d.verdict {
            Verdict::Approve => "approve",
            Verdict::Deny => "deny",
        };
        let comment = d.comment.as_deref().map(|c| format!(": {}", clean(c))).unwrap_or_default();
        kv(
            "decision",
            &format!("{verdict} by {} via {} ({}) at {}{comment}", d.approver, d.via, d.assurance, short_time(d.at)),
        );
    }
    for u in &r.uses {
        let what = u.attributes.get("command").map_or_else(|| clean(&u.subject.id), |c| clean(c));
        kv("used", &format!("{} {what}", short_time(u.at)));
    }
    s
}

fn random_bytes() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    out[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    // A v4 UUID fixes 6 bits; 2 x 122 random bits is plenty for a key.
    out
}

/// Write a new secret, readable only by the owner. For a host key, returns
/// the configuration line holding its hash.
pub fn keygen(path: &Path, format: KeyFormat, force: bool) -> Result<Option<String>, CliError> {
    let bytes = random_bytes();
    let text = match format {
        KeyFormat::Hex | KeyFormat::Host => bytes.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        }),
        KeyFormat::Whsec => format!("whsec_{}", base64::engine::general_purpose::STANDARD.encode(bytes)),
    };
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true);
    if force {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut file = opts.open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => {
            CliError::Usage(format!("{} exists; use --force to replace it", path.display()))
        }
        _ => CliError::Io(e),
    })?;
    #[cfg(unix)]
    {
        // `mode` only applies to newly created files.
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    writeln!(file, "{text}")?;
    Ok((format == KeyFormat::Host).then(|| format!("key_sha256 = \"{}\"", countersignd::intake::key_sha256(&text))))
}
