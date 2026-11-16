//! CLI commands against an in-memory store and a fake backend.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use countersign::{CliError, Command, Context, KeyFormat, execute, host_key, keygen};
use countersign_core::{
    AccessBackend, BackendCaps, BackendError, BackendName, GrantHandle, PendingSubject, RequestFilter, RequestState,
    Requester, Store, SubjectFacts, SubjectRef,
};
use countersign_store_sqlite::SqliteStore;
use countersignd::config::Config;
use countersignd::engine::Engine;
use jiff::Timestamp;

#[derive(Debug)]
struct OneSession {
    state: Mutex<&'static str>,
}

fn subject() -> SubjectRef {
    SubjectRef { backend: "oct".into(), kind: "session".into(), id: "s-1".into() }
}

fn facts() -> SubjectFacts {
    SubjectFacts {
        source: None,
        initiator: None,
        sensitive: false,
        requester: Requester {
            id: "agent\u{1b}[31m-7".into(),
            display_name: None,
            groups: BTreeSet::from(["agents".to_owned()]),
            ..Requester::default()
        },
        target: Some("db-prod".into()),
        requested_ttl: None,
        reason: Some("rotate keys".into()),
        attributes: BTreeMap::from([("session_type".to_owned(), "CLIENT".to_owned())]),
    }
}

#[async_trait]
impl AccessBackend for OneSession {
    fn name(&self) -> &BackendName {
        static NAME: std::sync::LazyLock<BackendName> = std::sync::LazyLock::new(|| BackendName::new("oct"));
        &NAME
    }

    fn capabilities(&self) -> BackendCaps {
        BackendCaps { discover: true, revoke: true, native_expiry: true }
    }

    async fn discover_pending(&self) -> Result<Vec<PendingSubject>, BackendError> {
        Ok(if *self.state.lock().unwrap() == "pending" {
            vec![PendingSubject { subject: subject(), facts: facts(), observed_at: Timestamp::now() }]
        } else {
            vec![]
        })
    }

    async fn verify(&self, _: &SubjectRef) -> Result<SubjectFacts, BackendError> {
        Ok(facts())
    }

    async fn grant(&self, s: &SubjectRef, _: Duration) -> Result<GrantHandle, BackendError> {
        *self.state.lock().unwrap() = "active";
        Ok(GrantHandle { subject: s.clone(), backend_ref: None, expires_at: None })
    }

    async fn deny(&self, _: &SubjectRef) -> Result<(), BackendError> {
        *self.state.lock().unwrap() = "rejected";
        Ok(())
    }

    fn identity_scheme(&self) -> &'static str {
        "oct"
    }

    async fn revoke(&self, _: &GrantHandle) -> Result<(), BackendError> {
        *self.state.lock().unwrap() = "revoked";
        Ok(())
    }
}

const CONFIG: &str = r#"
    [server]
    public_url = "https://cs.example.test"

    [[person]]
    id = "bob"

    [[person]]
    id = "mallory"

    [[person]]
    id = "carol"

    [[group]]
    name = "ops"
    members = ["bob", "carol"]

    [roles]
    member = ["group:ops", "person:mallory"]
    admin = ["person:carol"]

    [[policy]]
    name = "agents"
    match = { backend_group = "agents" }
    approvers = ["group:ops"]
    max_ttl = "30m"
    min_assurance = "linked"
"#;

struct Setup {
    store: Arc<dyn Store>,
    backend: Arc<OneSession>,
    id: String,
}

async fn setup() -> Setup {
    let store: Arc<dyn Store> = Arc::new(SqliteStore::in_memory().await.unwrap());
    let backend = Arc::new(OneSession { state: Mutex::new("pending") });
    let config = Config::from_toml(CONFIG).unwrap();
    let engine = Engine::new(
        Arc::clone(&store),
        vec![Arc::clone(&backend) as Arc<dyn AccessBackend>],
        countersignd::rules_from(&config),
    );
    engine.tick(Timestamp::now()).await;
    let id = store.list_requests(&RequestFilter::default()).await.unwrap()[0].id.to_string();
    Setup { store, backend, id }
}

impl Setup {
    async fn run(&self, cmd: Command) -> Result<String, CliError> {
        let ctx = Context {
            config: Config::from_toml(CONFIG).unwrap(),
            store: Arc::clone(&self.store),
            backends: vec![Arc::clone(&self.backend) as Arc<dyn AccessBackend>],
        };
        let mut out = Vec::new();
        execute(cmd, ctx, &mut out).await?;
        Ok(String::from_utf8(out).unwrap())
    }

    async fn state(&self) -> RequestState {
        self.store.list_requests(&RequestFilter::default()).await.unwrap()[0].state.clone()
    }
}

#[tokio::test]
async fn lists_and_shows_requests_without_terminal_escapes() {
    let s = setup().await;
    let out = s.run(Command::Requests { all: false, limit: 50, json: false }).await.unwrap();
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("ID") && lines[0].contains("KIND") && lines[0].contains("FROM"), "{out}");
    assert!(lines[1].starts_with(&s.id) && lines[1].contains("pending") && lines[1].contains("db-prod"), "{out}");
    assert!(!out.contains('\u{1b}'), "escape sequences are neutralized");

    let json = s.run(Command::Requests { all: true, limit: 50, json: true }).await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["approvals"][0]["id"], s.id);
    assert_eq!(v["questions"].as_array().unwrap().len(), 0);

    let out = s.run(Command::Show { id: s.id.clone(), json: false }).await.unwrap();
    assert!(out.contains("reason        rotate keys"), "{out}");
    assert!(out.contains("policy        agents"), "{out}");
    assert!(out.lines().all(|l| l.contains(' ')), "every key is separated from its value: {out}");
    assert!(!out.contains('\u{1b}'));

    assert!(matches!(s.run(Command::Show { id: "nope".into(), json: false }).await, Err(CliError::Usage(_))));
    let missing = countersign_core::RequestId::new().to_string();
    assert!(matches!(s.run(Command::Show { id: missing, json: true }).await, Err(CliError::Usage(_))));
}

#[tokio::test]
async fn deny_is_recorded_under_an_eligible_approver() {
    let s = setup().await;
    let e = s.run(Command::Deny { id: s.id.clone(), person: "mallory".into(), comment: None }).await.unwrap_err();
    assert!(e.to_string().contains("not eligible"), "{e}");
    let e = s.run(Command::Deny { id: s.id.clone(), person: "nobody".into(), comment: None }).await.unwrap_err();
    assert!(e.to_string().contains("member role"), "{e}");
    assert!(s.state().await.is_pending());

    let out =
        s.run(Command::Deny { id: s.id.clone(), person: "bob".into(), comment: Some(" looks off ".into()) }).await;
    assert_eq!(out.unwrap(), format!("{}: denied\n", s.id));
    assert_eq!(*s.backend.state.lock().unwrap(), "rejected");
    let r = &s.store.list_requests(&RequestFilter::default()).await.unwrap()[0];
    assert_eq!(r.decisions[0].via.as_str(), "cli");
    assert_eq!(r.decisions[0].comment.as_deref(), Some("looks off"));
}

#[tokio::test]
async fn revoke_ends_an_active_grant() {
    let s = setup().await;
    // Approve through the engine, as the web UI would.
    let engine = Engine::new(
        Arc::clone(&s.store),
        vec![Arc::clone(&s.backend) as Arc<dyn AccessBackend>],
        countersignd::rules_from(&Config::from_toml(CONFIG).unwrap()),
    );
    let intent = countersign_core::ActionIntent {
        request_id: s.id.parse().unwrap(),
        verdict: countersign_core::Verdict::Approve,
        approver: "bob".into(),
        assurance: countersign_core::Assurance::Linked,
        via: "discord".into(),
        comment: None,
    };
    engine.decide(intent, Timestamp::now()).await.unwrap();
    assert!(matches!(s.state().await, RequestState::Active { .. }));

    let out = s.run(Command::Revoke { id: s.id.clone(), person: "bob".into() }).await.unwrap();
    assert_eq!(out, format!("{}: revoked\n", s.id));
    assert_eq!(*s.backend.state.lock().unwrap(), "revoked");
}

async fn approve(s: &Setup, person: &str) {
    let engine = Engine::new(
        Arc::clone(&s.store),
        vec![Arc::clone(&s.backend) as Arc<dyn AccessBackend>],
        countersignd::rules_from(&Config::from_toml(CONFIG).unwrap()),
    );
    let intent = countersign_core::ActionIntent {
        request_id: s.id.parse().unwrap(),
        verdict: countersign_core::Verdict::Approve,
        approver: person.into(),
        assurance: countersign_core::Assurance::Linked,
        via: "discord".into(),
        comment: None,
    };
    engine.decide(intent, Timestamp::now()).await.unwrap();
}

#[tokio::test]
async fn admins_suspend_reinstate_and_revoke_what_a_person_approved() {
    let s = setup().await;
    approve(&s, "bob").await;
    assert!(matches!(s.state().await, RequestState::Active { .. }));

    let e = s.run(Command::Suspend { actor: "bob".into(), admin: "mallory".into(), reason: None }).await.unwrap_err();
    assert!(e.to_string().contains("admin"), "only admins: {e}");
    let e = s.run(Command::Suspend { actor: "carol".into(), admin: "carol".into(), reason: None }).await.unwrap_err();
    assert!(e.to_string().contains("themselves"), "{e}");

    let out = s.run(Command::RevokeApprovedBy { person: "bob".into(), admin: "carol".into() }).await.unwrap();
    assert!(out.contains(&format!("{}: revoked", s.id)) && out.ends_with("1 grant(s) revoked\n"), "{out}");
    assert_eq!(*s.backend.state.lock().unwrap(), "revoked");

    let out =
        s.run(Command::Suspend { actor: "bob".into(), admin: "carol".into(), reason: Some("lost laptop".into()) });
    assert_eq!(out.await.unwrap(), "suspended bob\n");
    s.store.link_account(&"discord".into(), "123", &"bob".into()).await.unwrap();
    let links = s.run(Command::Links { json: false }).await.unwrap();
    assert!(links.contains("bob (inactive)"), "{links}");
    let out = s.run(Command::Reinstate { actor: "bob".into(), admin: "carol".into() }).await.unwrap();
    assert_eq!(out, "reinstated bob\n");
    let out = s.run(Command::Reinstate { actor: "bob".into(), admin: "carol".into() }).await.unwrap();
    assert_eq!(out, "bob was not suspended\n");

    let actions = s.store.admin_actions(10).await.unwrap();
    let names: Vec<&str> = actions.iter().map(|a| a.action.as_str()).collect();
    for name in ["suspend", "reinstate", "revoke-approved-by"] {
        assert!(names.contains(&name), "{names:?}");
    }
}

#[tokio::test]
async fn links_can_be_listed_and_removed() {
    let s = setup().await;
    assert_eq!(s.run(Command::Links { json: false }).await.unwrap(), "(none)\n");
    s.store.link_account(&"discord".into(), "123", &"bob".into()).await.unwrap();
    s.store.link_account(&"discord".into(), "456", &"gone".into()).await.unwrap();
    let out = s.run(Command::Links { json: false }).await.unwrap();
    assert!(out.contains("discord  123      bob"), "{out}");
    assert!(out.contains("gone (inactive)"), "persons no longer configured are flagged: {out}");

    let unlink =
        |admin: &str| Command::Unlink { channel: "discord".into(), external_id: "123".into(), admin: admin.into() };
    let e = s.run(unlink("bob")).await.unwrap_err();
    assert!(e.to_string().contains("admin"), "{e}");
    let out = s.run(unlink("carol")).await.unwrap();
    assert_eq!(out, "unlinked 123 on discord\n");
    assert!(s.run(unlink("carol")).await.is_err());
    let v: serde_json::Value = serde_json::from_str(&s.run(Command::Links { json: true }).await.unwrap()).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 1);
}

#[test]
fn keygen_writes_usable_secrets_and_refuses_to_overwrite() {
    let dir = std::env::temp_dir().join(format!("cs-keygen-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let hex = dir.join("session.key");
    let _ = std::fs::remove_file(&hex);
    keygen(&hex, KeyFormat::Hex, false).unwrap();
    let a = std::fs::read_to_string(&hex).unwrap();
    assert_eq!(a.trim().len(), 64);
    assert!(a.trim().chars().all(|c| c.is_ascii_hexdigit()));
    assert!(matches!(keygen(&hex, KeyFormat::Hex, false), Err(CliError::Usage(_))));
    keygen(&hex, KeyFormat::Hex, true).unwrap();
    assert_ne!(std::fs::read_to_string(&hex).unwrap(), a, "a fresh secret");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(std::fs::metadata(&hex).unwrap().permissions().mode() & 0o777, 0o600);
    }

    let wh = dir.join("webhook.secret");
    let _ = std::fs::remove_file(&wh);
    keygen(&wh, KeyFormat::Whsec, false).unwrap();
    let w = std::fs::read_to_string(&wh).unwrap();
    assert!(w.starts_with("whsec_") && w.trim().len() == 6 + 44, "{w}");

    let host = dir.join("host.key");
    let _ = std::fs::remove_file(&host);
    let line = host_key(&host, false).unwrap();
    let key = std::fs::read_to_string(&host).unwrap();
    let key = key.trim();
    assert!(countersign_core::host_key::is_well_formed(key), "{key}");
    assert_eq!(line, format!("auth = {{ host_key_sha256 = \"{}\" }}", countersign_core::host_key::digest_hex(key)));
    assert!(!line.contains(key), "the key itself is not printed");
    assert!(matches!(host_key(&host, false), Err(CliError::Usage(_))));
    host_key(&host, true).unwrap();
    assert_ne!(std::fs::read_to_string(&host).unwrap().trim(), key, "a fresh key");
    let _ = std::fs::remove_dir_all(dir);
}
