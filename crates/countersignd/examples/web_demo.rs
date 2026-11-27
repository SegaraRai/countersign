//! The web UI against made-up data, for working on the pages.
//!
//! ```text
//! vp run build && cargo run -p countersignd --example web_demo
//! ```
//!
//! Then open <http://localhost:8790>. Signing in goes to a pretend identity
//! provider that lets you pick who you are. Nothing here is real: the
//! backend only remembers what was decided, and everything is gone when the
//! process stops.
//!
//! With `--dev <origin>` (what `vp run dev` starts, behind the Vite dev
//! server at `<origin>`), the pages are not served from here. Instead the UI
//! API answers at `/_dev/ui`, taking who is asking from the headers the dev
//! server forwards from the browser. Only for this example: countersignd
//! itself never lets anything but its own pages reach the UI API.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::extract::{Query, Request};
use axum::middleware::Next;
use axum::response::Html;
use axum::routing::get;
use jiff::Timestamp;

use countersign_core::{
    AccessBackend, Action, Asker, AuthError, Authenticator, BackendCaps, BackendError, BackendName, ClientId,
    Confidentiality, Detail, GrantHandle, LoginStart, PendingSubject, Requester, SubjectFacts, SubjectRef,
    VerifiedLogin,
};
use countersign_store_sqlite::SqliteStore;
use countersignd::Daemon;
use countersignd::config::Config;
use countersignd::engine::Ask;

const LISTEN: &str = "127.0.0.1:8790";
const PUBLIC_URL: &str = "http://localhost:8790";

const CONFIG: &str = r#"
    [server]
    public_url = "http://localhost:8790"
    fresh_auth_window = "5m"

    [[person]]
    id = "bob"
    display_name = "Bob Example"
    identities = ["oidc:demo#bob"]

    [[person]]
    id = "owner"
    display_name = "Olive Owner"
    identities = ["oidc:demo#owner"]

    [[person]]
    id = "carol"
    display_name = "Carol Admin"
    identities = ["oidc:demo#carol"]

    [[person]]
    id = "viewer"
    display_name = "Vic Auditor"
    identities = ["oidc:demo#viewer"]

    [[workload]]
    id = "agent"
    display_name = "Build agent"
    owners = ["owner"]
    identities = ["fake:fake#agent"]

    [[group]]
    name = "ops"
    members = ["bob", "owner", "carol"]

    [roles]
    member = ["group:ops"]
    auditor = ["person:viewer"]
    admin = ["person:carol"]

    [intake]
    listen = "127.0.0.1:0"
    behind_proxy = true
    signing_key_file = "set below"

    [[client]]
    id = "agent-host"
    auth = { host_key = "sha256:1111111111111111111111111111111111111111111111111111111111111111" }
    scopes = ["question"]

    [[question_policy]]
    name = "deploys"
    responders = ["group:ops"]
    min_assurance = "web"
    confidential = "allow"
    confidential_min_assurance = "fresh-auth"

    [[policy]]
    name = "agents"
    match = { backend_group = "agents" }
    approvers = ["group:ops"]
    exclude = ["requester", "owners"]
    max_ttl = "30m"
    min_assurance = "fresh-auth"
"#;

/// People to sign in as, with how long ago they "authenticated".
const PEOPLE: &[(&str, &str)] = &[
    ("bob", "Bob, an approver"),
    ("owner", "Olive, who owns the agent (cannot approve its requests)"),
    ("carol", "Carol, an admin"),
    ("viewer", "Vic, an auditor (sees, cannot act)"),
    ("stranger", "Someone countersign does not know"),
];

#[derive(Debug)]
struct DemoIdp;

#[async_trait]
impl Authenticator for DemoIdp {
    async fn begin(&self, fresh: bool) -> Result<LoginStart, AuthError> {
        Ok(LoginStart { redirect_url: format!("/demo-idp?fresh={fresh}"), state: "demo".into() })
    }
    async fn complete(&self, saved: &str, returned: &str, code: &str) -> Result<VerifiedLogin, AuthError> {
        if saved != returned {
            return Err(AuthError::StateMismatch);
        }
        let (identity, at) = code.split_once('|').ok_or(AuthError::StateMismatch)?;
        Ok(VerifiedLogin {
            identity: identity.into(),
            auth_time: at.parse().ok().and_then(|s| Timestamp::from_second(s).ok()),
            display_name: None,
            groups: None,
        })
    }
}

#[derive(serde::Deserialize)]
struct IdpQuery {
    #[serde(default)]
    fresh: bool,
}

async fn demo_idp(Query(q): Query<IdpQuery>) -> Html<String> {
    let now = Timestamp::now().as_second();
    let mut rows = String::new();
    for (id, what) in PEOPLE {
        for (age, label) in [(5, "just now"), (3600, "an hour ago")] {
            let _ = write!(
                rows,
                "<li><a href=\"/auth/callback?state=demo&amp;code=oidc:demo%23{id}%7C{}\">{what}, signed in {label}</a></li>",
                now - age
            );
        }
    }
    let fresh = if q.fresh { "<p><b>countersign asked for a fresh sign-in.</b></p>" } else { "" };
    Html(format!(
        "<!doctype html><meta charset=utf-8><title>Demo identity provider</title>\
         <h1>Demo identity provider</h1>{fresh}<p>Sign in as:</p><ul>{rows}</ul>"
    ))
}

/// Pending sessions that remember what was decided.
#[derive(Debug)]
struct DemoBackend {
    pending: Mutex<BTreeMap<String, SubjectFacts>>,
}

#[async_trait]
impl AccessBackend for DemoBackend {
    fn name(&self) -> &BackendName {
        static N: std::sync::OnceLock<BackendName> = std::sync::OnceLock::new();
        N.get_or_init(|| "fake".into())
    }
    fn capabilities(&self) -> BackendCaps {
        BackendCaps { discover: true, revoke: true, native_expiry: true }
    }
    fn identity_scheme(&self) -> &'static str {
        "fake"
    }
    async fn discover_pending(&self) -> Result<Vec<PendingSubject>, BackendError> {
        let pending = self.pending.lock().unwrap();
        Ok(pending
            .iter()
            .map(|(id, facts)| PendingSubject {
                subject: subject(id),
                facts: facts.clone(),
                observed_at: Timestamp::now(),
            })
            .collect())
    }
    async fn verify(&self, s: &SubjectRef) -> Result<SubjectFacts, BackendError> {
        self.pending.lock().unwrap().get(&s.id).cloned().ok_or(BackendError::NotFound)
    }
    async fn grant(&self, s: &SubjectRef, _: Duration) -> Result<GrantHandle, BackendError> {
        self.pending.lock().unwrap().remove(&s.id);
        Ok(GrantHandle { subject: s.clone(), backend_ref: None, expires_at: None })
    }
    async fn deny(&self, s: &SubjectRef) -> Result<(), BackendError> {
        self.pending.lock().unwrap().remove(&s.id);
        Ok(())
    }
    async fn revoke(&self, _: &GrantHandle) -> Result<(), BackendError> {
        Ok(())
    }
}

fn subject(id: &str) -> SubjectRef {
    SubjectRef { backend: "fake".into(), kind: "session".into(), id: id.into() }
}

fn facts(target: &str, reason: &str, action: Action) -> SubjectFacts {
    SubjectFacts {
        source: None,
        initiator: None,
        sensitive: false,
        binding: None,
        action: Some(action),
        requester: Requester {
            id: "agent".into(),
            groups: BTreeSet::from(["agents".to_owned()]),
            ..Requester::default()
        },
        target: Some(target.into()),
        requested_ttl: Some(Duration::from_mins(15)),
        reason: Some(reason.into()),
        attributes: BTreeMap::new(),
    }
}

fn seed() -> BTreeMap<String, SubjectFacts> {
    let command = |line: &[&str]| Action::Command {
        line: line.iter().map(|s| (*s).to_owned()).collect(),
        runas: "root".into(),
        cwd: Some("/srv/app".into()),
        notes: vec![],
    };
    BTreeMap::from([
        (
            "s1".to_owned(),
            facts(
                "web-01.internal",
                "Restart the app after the config change in OPS-412",
                command(&["sudo", "systemctl", "restart", "app.service"]),
            ),
        ),
        (
            "s2".to_owned(),
            facts(
                "db.internal:5432",
                "Run the nightly migration by hand",
                Action::Session {
                    kind: Some("client".into()),
                    device: Some("build-runner-7".into()),
                    client: Some("psql/17.2".into()),
                    credential: Some("token agent-ci".into()),
                    browser: false,
                },
            ),
        ),
        (
            "s3".to_owned(),
            facts(
                "backups",
                "Rotate <the> \"backup\" keys & check",
                Action::Generic {
                    title: "Key rotation".into(),
                    lines: vec![
                        Detail { label: "Bucket".into(), value: "r2://backups-eu".into() },
                        Detail { label: "Keys".into(), value: "3 of 5".into() },
                    ],
                },
            ),
        ),
    ])
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_env_filter("info,countersignd=debug").init();
    let mut args = std::env::args().skip(1);
    let dev_origin = match args.next().as_deref() {
        None => None,
        Some("--dev") => Some(args.next().ok_or("--dev needs the dev server's origin")?),
        Some(other) => return Err(format!("unknown argument {other}").into()),
    };
    if dev_origin.is_none() && !countersignd::web::pages_built_in() {
        return Err("the web UI is not built in: run `vp run build`, then build again".into());
    }

    let public_url = dev_origin.as_deref().unwrap_or(PUBLIC_URL);
    let mut config = Config::from_toml(&CONFIG.replace(PUBLIC_URL, public_url))?;
    let key_file = std::env::temp_dir().join("countersign-web-demo-signing.key");
    std::fs::write(&key_file, countersign_core::approval_signing::ServerKey::generate(&[7; 32]))?;
    config.intake.as_mut().ok_or("intake")?.signing_key_file = key_file;

    let store: Arc<dyn countersign_core::Store> = Arc::new(SqliteStore::in_memory().await?);
    let backend: Arc<dyn AccessBackend> = Arc::new(DemoBackend { pending: Mutex::new(seed()) });
    let mut daemon = Daemon::with_parts(&config, store, vec![backend], vec![])?;
    daemon.web.auth = Some(Arc::new(DemoIdp));
    // A fixed key, so restarting keeps you signed in.
    daemon.web.key = axum_extra::extract::cookie::Key::from(&[7; 64]);
    if dev_origin.is_none() {
        daemon.web.pages = countersignd::web::Pages::start(&daemon.web).await?;
    }
    daemon.engine.tick(Timestamp::now()).await;

    let asker = || Asker { client: ClientId::new("agent-host"), actor: None };
    let schema = serde_json::json!({
        "type": "object",
        "properties": {
            "env": { "type": "string", "enum": ["staging", "prod"], "title": "Environment" },
            "replicas": { "type": "integer", "minimum": 1, "maximum": 10, "title": "Replicas" },
            "canary": { "type": "boolean", "title": "Start with a canary" },
            "note": { "type": "string", "title": "Note for the agent" }
        },
        "required": ["env"]
    });
    daemon
        .engine
        .ask(
            Ask {
                asker: asker(),
                message: "Where should I deploy **v2.14.0**? The staging run passed.".into(),
                schema: schema.clone(),
                context: BTreeMap::from([
                    ("branch".to_owned(), "release/2.14".to_owned()),
                    ("commit".to_owned(), "9f3c2e1".to_owned()),
                ]),
                confidentiality: Confidentiality::default(),
            },
            Timestamp::now(),
        )
        .await?;
    daemon
        .engine
        .ask(
            Ask {
                asker: asker(),
                message: "Which vault key should the job use?".into(),
                schema: serde_json::json!({
                    "type": "object",
                    "properties": { "key": { "type": "string", "title": "Key name" } },
                    "required": ["key"]
                }),
                context: BTreeMap::new(),
                confidentiality: Confidentiality { question: true, answer_may_be: true },
            },
            Timestamp::now(),
        )
        .await?;

    let engine = Arc::clone(&daemon.engine);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            engine.tick(Timestamp::now()).await;
        }
    });

    let mut app = Router::new().route("/demo-idp", get(demo_idp));
    if dev_origin.is_some() {
        app = app.nest("/_dev/ui", dev_ui(&daemon.web));
    }
    let app = app.fallback_service(countersignd::web::router(daemon.web));
    let listener = tokio::net::TcpListener::bind(LISTEN).await?;
    tracing::info!("open {public_url}");
    axum::serve(listener, app).await?;
    Ok(())
}

/// The UI API for the Vite dev server, which forwards the browser's
/// `Cookie`, `Origin` and `Sec-Fetch-Site`: the trusted context countersignd
/// gives its own pages, worked out from those.
fn dev_ui(web: &countersignd::web::AppState) -> Router {
    let key = web.key.clone();
    let origin = web.settings.public_origin.clone();
    countersignd::web::ui_router(web.clone()).layer(axum::middleware::from_fn(move |mut req: Request, next: Next| {
        let context = countersignd::web::visit_context(req.headers(), &key, &origin);
        req.extensions_mut().insert(context);
        next.run(req)
    }))
}
