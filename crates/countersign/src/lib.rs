//! Administration CLI for countersign, run on the daemon's host.
//!
//! It reads the same configuration and database as `countersignd`, so using
//! it takes the same access as reading those files. It deliberately offers no
//! way to *approve* or *answer*: those go through the web UI or chat, where
//! the policy's assurance level is enforced. Denying and revoking only reduce
//! access and are recorded under the person named with `--as`; suspending,
//! reinstating and unlinking need an admin named with `--as`.
//!
//! The text of confidential questions and confidential answers is never
//! printed, not even here.

use std::fmt::Write as _;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use clap::{Subcommand, ValueEnum};
use countersign_core::{
    AccessBackend, ActionIntent, ActorId, Assurance, ChannelName, Item, Question, QuestionOutcome, Request,
    RequestFilter, RequestId, RequestState, Store, StoreError, Verdict,
};
use countersignd::config::Config;
use countersignd::engine::{Engine, EngineError};
use jiff::Timestamp;

/// Name recorded as the channel of decisions made here.
pub const VIA: &str = "cli";

#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    /// List approvals and questions (open ones unless --all).
    Requests {
        #[arg(long)]
        all: bool,
        #[arg(long, default_value_t = 50)]
        limit: u32,
        #[arg(long)]
        json: bool,
    },
    /// Show one approval or question.
    Show {
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Deny a pending approval on behalf of a person.
    Deny {
        id: String,
        /// Person to record the decision under (must be eligible).
        #[arg(long = "as", value_name = "PERSON")]
        person: String,
        #[arg(long)]
        comment: Option<String>,
    },
    /// End an active grant early on behalf of a person (an admin, or an
    /// eligible approver).
    Revoke {
        id: String,
        #[arg(long = "as", value_name = "PERSON")]
        person: String,
    },
    /// Suspend a person or workload at once.
    Suspend {
        actor: String,
        /// Admin to record the action under.
        #[arg(long = "as", value_name = "ADMIN")]
        admin: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Lift a suspension.
    Reinstate {
        actor: String,
        #[arg(long = "as", value_name = "ADMIN")]
        admin: String,
    },
    /// Revoke every active grant a person approved.
    RevokeApprovedBy {
        person: String,
        #[arg(long = "as", value_name = "ADMIN")]
        admin: String,
    },
    /// List chat accounts linked to persons.
    Links {
        #[arg(long)]
        json: bool,
    },
    /// Remove a chat account link.
    Unlink {
        channel: String,
        external_id: String,
        #[arg(long = "as", value_name = "ADMIN")]
        admin: String,
    },
    /// Write a new random secret to a file (mode 0600), e.g. for
    /// `server.session_key_file` or a webhook `secret_file`.
    Keygen {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = KeyFormat::Hex)]
        format: KeyFormat,
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
    },
    /// Write a new client key for the intake API to a file (mode 0600) and
    /// print the `auth` line for the client's `[[client]]` entry.
    HostKey {
        path: PathBuf,
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
    },
    /// Write a new approval signing key for `intake.signing_key_file` (mode
    /// 0600; make it readable by the daemon's group) and print the
    /// `server_keys` line clients pin. With `--public`, print the line for
    /// an existing key instead.
    SigningKey {
        path: PathBuf,
        /// Only print the public key of an existing key file.
        #[arg(long, conflicts_with = "force")]
        public: bool,
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

fn json(out: &mut dyn Write, v: &serde_json::Value) -> Result<(), CliError> {
    writeln!(out, "{v:#}")?;
    Ok(())
}

/// Run a command that needs the configuration and database.
#[allow(clippy::too_many_lines)] // one short arm per command
pub async fn execute(cmd: Command, ctx: Context, out: &mut dyn Write) -> Result<(), CliError> {
    let now = Timestamp::now();
    let engine = || Engine::new(Arc::clone(&ctx.store), ctx.backends.clone(), countersignd::rules_from(&ctx.config));
    match cmd {
        Command::Requests { all, limit, json: as_json } => {
            let filter = RequestFilter { open_only: !all, limit: Some(limit) };
            let approvals = ctx.store.list_requests(&filter).await?;
            let questions: Vec<Question> =
                ctx.store.list_questions(&filter).await?.iter().map(Question::for_chat).collect();
            if as_json {
                json(out, &serde_json::json!({ "approvals": approvals, "questions": questions }))?;
            } else {
                let mut items: Vec<Item<'_>> =
                    approvals.iter().map(Item::Approval).chain(questions.iter().map(Item::Question)).collect();
                items.sort_by_key(|i| std::cmp::Reverse(created(i)));
                items.truncate(limit as usize);
                out.write_all(table(&items).as_bytes())?;
            }
        }
        Command::Show { id, json: as_json } => {
            let rid = parse_id(&id)?;
            if let Some(r) = ctx.store.get_request(rid).await? {
                if as_json {
                    json(out, &serde_json::to_value(r).map_err(std::io::Error::other)?)?;
                } else {
                    out.write_all(details(&r).as_bytes())?;
                }
            } else if let Some(q) = ctx.store.get_question(rid).await? {
                let q = q.for_chat();
                if as_json {
                    json(out, &serde_json::to_value(q).map_err(std::io::Error::other)?)?;
                } else {
                    out.write_all(question_details(&q).as_bytes())?;
                }
            } else {
                return Err(not_found(&id));
            }
        }
        Command::Deny { id, person, comment } => {
            let intent = ActionIntent {
                request_id: parse_id(&id)?,
                verdict: Verdict::Deny,
                approver: ActorId::new(person),
                // Denials are accepted at any assurance; record the lowest.
                assurance: Assurance::Linked,
                via: ChannelName::new(VIA),
                comment: comment.map(|c| c.trim().to_owned()).filter(|c| !c.is_empty()),
            };
            let r = engine().decide(intent, now).await?;
            writeln!(out, "{}: {}", r.id, r.state.name())?;
        }
        Command::Revoke { id, person } => {
            let r = engine().revoke(parse_id(&id)?, &ActorId::new(person), now).await?;
            writeln!(out, "{}: {}", r.id, r.state.name())?;
        }
        Command::Suspend { actor, admin, reason } => {
            engine().suspend(&ActorId::new(actor.clone()), &ActorId::new(admin), reason, now).await?;
            writeln!(out, "suspended {actor}")?;
        }
        Command::Reinstate { actor, admin } => {
            if engine().reinstate(&ActorId::new(actor.clone()), &ActorId::new(admin), now).await? {
                writeln!(out, "reinstated {actor}")?;
            } else {
                writeln!(out, "{actor} was not suspended")?;
            }
        }
        Command::RevokeApprovedBy { person, admin } => {
            let revoked = engine().revoke_approved_by(&ActorId::new(person), &ActorId::new(admin), now).await?;
            for id in &revoked {
                writeln!(out, "{id}: revoked")?;
            }
            writeln!(out, "{} grant(s) revoked", revoked.len())?;
        }
        Command::Links { json: as_json } => {
            let links = ctx.store.list_account_links().await?;
            if as_json {
                json(out, &serde_json::to_value(links).map_err(std::io::Error::other)?)?;
            } else {
                let (rules, standing) = engine().standing().await?;
                let roster = rules.roster(&standing, now);
                let rows: Vec<Vec<String>> = links
                    .iter()
                    .map(|l| {
                        let active = roster.active_person(&l.person).is_some();
                        vec![
                            l.channel.to_string(),
                            l.external_id.clone(),
                            if active { l.person.to_string() } else { format!("{} (inactive)", l.person) },
                            short_time(l.linked_at),
                        ]
                    })
                    .collect();
                out.write_all(render_table(&["CHANNEL", "ACCOUNT", "PERSON", "LINKED"], &rows).as_bytes())?;
            }
        }
        Command::Unlink { channel, external_id, admin } => {
            if !engine().unlink(&ChannelName::new(channel.clone()), &external_id, &ActorId::new(admin), now).await? {
                return Err(CliError::Usage(format!("no link for {external_id} on {channel}")));
            }
            writeln!(out, "unlinked {external_id} on {channel}")?;
        }
        Command::Keygen { path, format, force } => keygen(&path, format, force)?,
        Command::HostKey { path, force } => writeln!(out, "{}", host_key(&path, force)?)?,
        Command::SigningKey { path, public, force } => writeln!(out, "{}", signing_key(&path, public, force)?)?,
    }
    Ok(())
}

fn created(i: &Item<'_>) -> Timestamp {
    match i {
        Item::Approval(r) => r.created_at,
        Item::Question(q) => q.created_at,
    }
}

fn parse_id(id: &str) -> Result<RequestId, CliError> {
    id.parse().map_err(|_| CliError::Usage(format!("not a request id: {id}")))
}

fn not_found(id: &str) -> CliError {
    CliError::Usage(format!("no request or question {id}"))
}

fn short_time(t: Timestamp) -> String {
    t.strftime("%Y-%m-%d %H:%M:%SZ").to_string()
}

/// Untrusted text for a terminal: control and other hidden characters
/// (escape sequences, bidirectional overrides) are written out.
fn clean(s: &str) -> String {
    countersign_core::text::escape(s)
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

/// One line per approval or question, newest first.
pub fn table(items: &[Item<'_>]) -> String {
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|i| {
            let from = match i {
                Item::Approval(r) => {
                    let target = r.facts.target.as_deref().map(|t| format!(" ({})", clean(t))).unwrap_or_default();
                    format!("{}{target}", clean(&r.facts.requester.id))
                }
                Item::Question(q) => clean(q.asker.client.as_str()),
            };
            vec![
                i.id().to_string(),
                i.kind().to_owned(),
                i.state().to_owned(),
                from,
                i.policy().to_owned(),
                short_time(created(i)),
            ]
        })
        .collect();
    render_table(&["ID", "KIND", "STATE", "FROM", "POLICY", "CREATED"], &rows)
}

fn kv(s: &mut String, k: &str, v: &str) {
    // Keys longer than the column still get a separating space.
    let _ = writeln!(s, "{k:<13} {v}");
}

/// Everything about one approval.
pub fn details(r: &Request) -> String {
    let f = &r.facts;
    let mut s = String::new();
    kv(&mut s, "id", &r.id.to_string());
    kv(&mut s, "kind", "approval");
    kv(&mut s, "state", r.state.name());
    match &r.state {
        RequestState::Active { until } => kv(&mut s, "active until", &short_time(*until)),
        RequestState::Failed { error } => kv(&mut s, "error", &clean(error)),
        RequestState::Pending => kv(&mut s, "decide by", &short_time(r.pending_until)),
        _ => {}
    }
    if r.sensitive {
        kv(&mut s, "sensitive", "yes (chat channels show only that it exists)");
    }
    if let Some(source) = &f.source {
        kv(&mut s, "source", &source.to_string());
    }
    kv(&mut s, "subject", &format!("{}/{}/{}", r.subject.backend, clean(&r.subject.kind), clean(&r.subject.id)));
    let name = f.requester.display_name.as_deref().map(|n| format!(" ({})", clean(n))).unwrap_or_default();
    kv(&mut s, "requester", &format!("{}{name}", clean(&f.requester.id)));
    if !f.requester.identity.is_empty() {
        let actor = f.requester.actor.as_ref().map_or_else(|| "not a known actor".to_owned(), ToString::to_string);
        kv(&mut s, "identity", &format!("{} ({actor})", clean(&f.requester.identity)));
    }
    if let Some(i) = &f.initiator {
        let actor = i.actor.as_ref().map_or_else(|| "not a known person".to_owned(), ToString::to_string);
        kv(&mut s, "initiator", &format!("{} ({actor})", clean(&i.identity)));
    }
    if !f.requester.groups.is_empty() {
        kv(&mut s, "groups", &f.requester.groups.iter().map(|g| clean(g)).collect::<Vec<_>>().join(", "));
    }
    if let Some(t) = &f.target {
        kv(&mut s, "target", &clean(t));
    }
    if let Some(reason) = &f.reason {
        kv(&mut s, "reason", &clean(reason));
    }
    for (k, v) in &f.attributes {
        kv(&mut s, &format!("attr.{}", clean(k)), &clean(v));
    }
    let q = &r.requirements;
    kv(&mut s, "policy", q.policy.as_str());
    let exclude: Vec<String> = q
        .exclude
        .iter()
        .filter_map(|e| serde_json::to_value(e).ok().and_then(|v| v.as_str().map(str::to_owned)))
        .collect();
    kv(
        &mut s,
        "needs",
        &format!(
            "{} approval(s) at {}, {} for {}s{}",
            q.quorum,
            q.min_assurance,
            q.grant.as_str(),
            q.ttl.as_secs(),
            if exclude.is_empty() { String::new() } else { format!(", excluding {}", exclude.join(", ")) }
        ),
    );
    kv(&mut s, "created", &short_time(r.created_at));
    for d in &r.decisions {
        let verdict = match d.verdict {
            Verdict::Approve => "approve",
            Verdict::Deny => "deny",
        };
        let comment = d.comment.as_deref().map(|c| format!(": {}", clean(c))).unwrap_or_default();
        kv(
            &mut s,
            "decision",
            &format!("{verdict} by {} via {} ({}) at {}{comment}", d.approver, d.via, d.assurance, short_time(d.at)),
        );
    }
    for u in &r.uses {
        let what = u.attributes.get("command").map_or_else(|| clean(&u.subject.id), |c| clean(c));
        kv(&mut s, "used", &format!("{} {what}", short_time(u.at)));
    }
    s
}

/// One question, as [`Question::for_chat`] leaves it: no confidential text
/// or answers.
pub fn question_details(q: &Question) -> String {
    let mut s = String::new();
    kv(&mut s, "id", &q.id.to_string());
    kv(&mut s, "kind", "question");
    kv(&mut s, "state", q.state());
    if q.is_pending() {
        kv(&mut s, "answer by", &short_time(q.pending_until));
    }
    let actor = q.asker.actor.as_ref().map(|a| format!(" for {a}")).unwrap_or_default();
    kv(&mut s, "asker", &format!("{}{actor}", q.asker.client));
    kv(&mut s, "policy", q.requirements.policy.as_str());
    let responders: Vec<String> = q.requirements.responders.iter().map(ToString::to_string).collect();
    kv(&mut s, "responders", &responders.join(", "));
    if q.question_confidential() {
        kv(&mut s, "message", "(confidential: read it in the web UI)");
    } else {
        kv(&mut s, "message", &clean(&q.message));
        for (k, v) in &q.context {
            kv(&mut s, &format!("context.{}", clean(k)), &clean(v));
        }
    }
    kv(&mut s, "created", &short_time(q.created_at));
    if let Some(result) = Item::question_result(q) {
        kv(&mut s, "result", &result);
    }
    match &q.outcome {
        Some(QuestionOutcome::Accepted { content: Some(c), .. }) => {
            for (k, v) in c {
                kv(&mut s, &format!("answer.{}", clean(k)), &clean(&v.to_string()));
            }
        }
        Some(QuestionOutcome::Declined { note: Some(n), .. }) => kv(&mut s, "note", &clean(n)),
        _ => {}
    }
    s
}

/// 32 bytes from the operating system's CSPRNG.
fn random_bytes() -> Result<[u8; 32], CliError> {
    let mut out = [0u8; 32];
    getrandom::getrandom(&mut out).map_err(|e| CliError::Usage(format!("no random numbers from the OS: {e}")))?;
    Ok(out)
}

/// Write a new secret, readable only by the owner.
pub fn keygen(path: &Path, format: KeyFormat, force: bool) -> Result<(), CliError> {
    let bytes = random_bytes()?;
    let text = match format {
        KeyFormat::Hex => bytes.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        }),
        KeyFormat::Whsec => format!("whsec_{}", base64::engine::general_purpose::STANDARD.encode(bytes)),
    };
    write_secret(path, &text, force)
}

/// Write a new client key, readable only by the owner. Returns the
/// `[[client]]` `auth` line holding its hash.
pub fn host_key(path: &Path, force: bool) -> Result<String, CliError> {
    let key = countersign_core::host_key::from_random(&random_bytes()?);
    write_secret(path, &key, force)?;
    Ok(format!("auth = {{ host_key = \"{}\" }}", countersign_core::host_key::reference(&key)))
}

/// Write a new approval signing key, or with `public` read an existing one.
/// Returns the `server_keys` line for clients.
pub fn signing_key(path: &Path, public: bool, force: bool) -> Result<String, CliError> {
    use countersign_core::approval_signing::ServerKey;
    let key = if public {
        let text = std::fs::read_to_string(path)?;
        ServerKey::parse(&text)
            .ok_or_else(|| CliError::Usage(format!("{} does not hold a signing key", path.display())))?
    } else {
        let text = ServerKey::generate(&random_bytes()?);
        write_secret(path, &text, force)?;
        ServerKey::parse(&text).ok_or_else(|| CliError::Usage("generated key does not parse".into()))?
    };
    Ok(format!("server_keys = [\"{}\"]", key.public()))
}

fn write_secret(path: &Path, text: &str, force: bool) -> Result<(), CliError> {
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
    Ok(())
}
