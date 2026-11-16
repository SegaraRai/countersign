//! The intake API: hosts submitting `sudo` invocations and waiting for the
//! outcome, and clients asking questions.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request as HttpRequest, StatusCode, header};
use countersign_core::host_key::digest_hex;
use countersign_core::{ActionIntent, AnswerIntent, Assurance, RequestState, Response, Store, Verdict};
use countersign_store_sqlite::SqliteStore;
use countersignd::config::Config;
use countersignd::{Daemon, build_backends};
use http_body_util::BodyExt;
use jiff::Timestamp;
use serde_json::{Value, json};
use tower::ServiceExt;

const WEB1: &str = "cshk_AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEDVuYWg";
const WEB2: &str = "cshk_AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIOJxDvA";
/// Well-formed, but configured for no host.
const UNKNOWN: &str = "cshk_AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMwVYYBQ";
/// Configured for a host, but not in the host key format.
const LEGACY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
/// A client that only asks questions.
static AGENT: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| countersign_core::host_key::from_random(&[4; 32]));

/// The intake terminates TLS itself, so the peer address is the client's.
/// The certificate files are only read when the daemon starts serving.
const OWN_TLS: &str = r#"tls = { cert_file = "unused.pem", key_file = "unused.pem" }"#;

fn config() -> Config {
    config_with(OWN_TLS)
}

/// The nonce test submissions carry.
const NONCE: &str = "bm9uY2Vub25jZW5vbmNlbm9uY2Vub25jZW5vbmNlbm8";

/// A signing key file for the daemon under test (one per test process).
fn signing_key_file() -> std::path::PathBuf {
    static PATH: std::sync::LazyLock<std::path::PathBuf> = std::sync::LazyLock::new(|| {
        let p = std::env::temp_dir().join(format!("countersign-test-signing-{}.key", std::process::id()));
        std::fs::write(&p, countersign_core::approval_signing::ServerKey::generate(&SIGNING_SEED)).unwrap();
        p
    });
    PATH.clone()
}

const SIGNING_SEED: [u8; 32] = [5; 32];

fn config_with(exposure: &str) -> Config {
    let text = format!(
        r#"
        [server]
        public_url = "https://cs.example.test"

        [intake]
        listen = "127.0.0.1:0"
        {exposure}
        signing_key_file = "set by the test"
        max_pending_per_client = 3

        [backend.sudo]
        type = "host"

        [[client]]
        id = "web-1"
        auth = {{ host_key = "sha256:{}" }}

        [[client]]
        id = "web-2"
        auth = {{ host_key = "sha256:{}" }}
        allowed_ips = ["100.64.0.22"]

        [[client]]
        id = "legacy"
        auth = {{ host_key = "sha256:{}" }}

        [[client]]
        id = "agent-host"
        auth = {{ host_key = "sha256:{}" }}
        scopes = ["question"]
        actor = "deployer"

        [[person]]
        id = "bob"

        [[person]]
        id = "alice"

        [[workload]]
        id = "agent"
        owners = ["alice"]
        identities = ["unix:web-1#agent", "unix:web-2#agent", "unix:legacy#agent"]

        [[workload]]
        id = "stranger"
        owners = ["alice"]
        identities = ["unix:web-1#stranger"]

        [[workload]]
        id = "deployer"
        owners = ["alice"]

        [[group]]
        name = "ops"
        members = ["bob"]

        [[group]]
        name = "agents"
        members = ["agent"]

        [roles]
        member = ["group:ops", "person:alice"]

        [[policy]]
        name = "packages"
        match = {{ backend = "sudo", attributes = {{ command = "apt *" }} }}
        grant = "window"
        max_ttl = "15m"
        approvers = ["group:ops"]
        min_assurance = "linked"

        [[policy]]
        name = "other"
        match = {{ backend = "sudo", requester_group = "agents" }}
        max_ttl = "1m"
        approvers = ["group:ops"]
        min_assurance = "linked"
        sensitive = "honor"

        [[question_policy]]
        name = "deploys"
        match = {{ asker = "agent-host" }}
        responders = ["group:ops"]
        min_assurance = "linked"
        confidential = "allow"
        confidential_min_assurance = "linked"
        "#,
        digest_hex(WEB1),
        digest_hex(WEB2),
        digest_hex(LEGACY),
        digest_hex(&AGENT),
    );
    Config::from_toml(&text).unwrap()
}

struct Setup {
    app: Router,
    daemon: Daemon,
    store: Arc<dyn Store>,
}

async fn setup() -> Setup {
    setup_with(config()).await
}

async fn setup_with(mut config: Config) -> Setup {
    config.intake.as_mut().unwrap().signing_key_file = signing_key_file();
    let store: Arc<dyn Store> = Arc::new(SqliteStore::in_memory().await.unwrap());
    let backends = build_backends(&config, &store).unwrap();
    let daemon = Daemon::with_parts(&config, Arc::clone(&store), backends, vec![]).unwrap();
    let app = countersignd::intake::router(daemon.intake.clone().unwrap());
    Setup { app, daemon, store }
}

struct Call<'a> {
    method: &'a str,
    path: String,
    key: Option<&'a str>,
    body: Option<Value>,
    peer: Option<&'a str>,
}

impl Setup {
    async fn call(&self, c: Call<'_>) -> (StatusCode, Value) {
        let mut req = HttpRequest::builder().method(c.method).uri(&c.path);
        if let Some(k) = c.key {
            req = req.header(header::AUTHORIZATION, format!("Bearer {k}"));
        }
        let mut req = req.body(c.body.map_or_else(Body::empty, |b| Body::from(b.to_string()))).unwrap();
        if let Some(p) = c.peer {
            let addr: SocketAddr = format!("{p}:40000").parse().unwrap();
            req.extensions_mut().insert(ConnectInfo(addr));
        }
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    async fn submit(&self, key: &str, user: &str, argv: &[&str]) -> (StatusCode, Value) {
        let body = json!({ "user": user, "argv": argv, "cwd": "/home/agent", "reason": "deploy", "nonce": NONCE });
        self.call(Call {
            method: "POST",
            path: "/intake/v1/requests".into(),
            key: Some(key),
            body: Some(body),
            peer: None,
        })
        .await
    }

    async fn status(&self, key: &str, id: &str, wait: u64) -> (StatusCode, Value) {
        let path = format!("/intake/v1/requests/{id}?wait={wait}");
        self.call(Call { method: "GET", path, key: Some(key), body: None, peer: None }).await
    }

    async fn decide(&self, id: &str, verdict: Verdict) {
        let intent = ActionIntent {
            request_id: id.parse().unwrap(),
            verdict,
            approver: "bob".into(),
            assurance: Assurance::Linked,
            via: "discord".into(),
            comment: None,
        };
        self.daemon.engine.decide(intent, Timestamp::now()).await.unwrap();
    }

    async fn request(&self, id: &str) -> countersign_core::Request {
        self.store.get_request(id.parse().unwrap()).await.unwrap().unwrap()
    }
}

fn id_of(v: &Value) -> String {
    v["id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn hosts_must_present_a_known_key_from_an_allowed_address() {
    let s = setup().await;
    let post = |key, peer| Call {
        method: "POST",
        path: "/intake/v1/requests".into(),
        key,
        body: Some(json!({ "user": "agent", "argv": ["true"], "nonce": NONCE })),
        peer,
    };
    assert_eq!(s.call(post(None, None)).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(s.call(post(Some("wrong"), None)).await.0, StatusCode::UNAUTHORIZED);
    let (status, unknown) = s.call(post(Some(UNKNOWN), None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // A key in another format is refused even though its hash is configured,
    // with the same answer as an unknown key.
    assert_eq!(s.call(post(Some(LEGACY), None)).await, (StatusCode::UNAUTHORIZED, unknown));
    let typo = format!("{WEB1}x");
    assert_eq!(s.call(post(Some(&typo), None)).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(s.call(post(Some(WEB2), None)).await.0, StatusCode::UNAUTHORIZED, "no peer address known");
    assert_eq!(s.call(post(Some(WEB2), Some("100.64.0.99"))).await.0, StatusCode::UNAUTHORIZED);
    let (status, v) = s.call(post(Some(WEB2), Some("100.64.0.22"))).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");

    // A body is not even parsed before authentication.
    let garbage =
        Call { method: "POST", path: "/intake/v1/requests".into(), key: None, body: Some(json!("nope")), peer: None };
    assert_eq!(s.call(garbage).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn behind_a_proxy_the_client_address_comes_from_its_header() {
    let s = setup_with(config_with("behind_proxy = true\nclient_ip_header = \"x-forwarded-for\"")).await;
    let post = |forwarded: &[&str]| {
        let mut req = HttpRequest::builder()
            .method("POST")
            .uri("/intake/v1/requests")
            .header(header::AUTHORIZATION, format!("Bearer {WEB2}"));
        for f in forwarded {
            req = req.header("x-forwarded-for", *f);
        }
        let mut req =
            req.body(Body::from(json!({ "user": "agent", "argv": ["true"], "nonce": NONCE }).to_string())).unwrap();
        // The proxy itself connects from loopback.
        req.extensions_mut().insert(ConnectInfo("127.0.0.1:40000".parse::<SocketAddr>().unwrap()));
        let app = s.app.clone();
        async move { app.oneshot(req).await.unwrap().status() }
    };
    assert_eq!(post(&[]).await, StatusCode::UNAUTHORIZED, "no header, no address");
    assert_eq!(post(&["100.64.0.99"]).await, StatusCode::UNAUTHORIZED);
    // Entries the client sent itself come first and do not count.
    assert_eq!(post(&["100.64.0.22, 100.64.0.99"]).await, StatusCode::UNAUTHORIZED);
    assert_eq!(post(&["100.64.0.22", "100.64.0.99"]).await, StatusCode::UNAUTHORIZED);
    assert_eq!(post(&["100.64.0.99, 100.64.0.22"]).await, StatusCode::CREATED);
}

#[tokio::test]
async fn approvals_are_signed_for_the_submission_and_the_client() {
    use countersign_core::approval_signing::{Approval, ServerKey, invocation_digest, verify};
    let s = setup().await;
    let public = vec![ServerKey::parse(&ServerKey::generate(&SIGNING_SEED)).unwrap().public()];
    let (status, v) = s.submit(WEB1, "agent", &["systemctl", "restart", "nginx"]).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert!(v.get("signature").is_none(), "nothing to sign while pending");
    let id = id_of(&v);
    s.decide(&id, Verdict::Approve).await;
    let v = s.status(WEB1, &id, 0).await.1;
    assert_eq!(v["state"], "approved");
    let sig = v["signature"].as_str().unwrap();
    let argv: Vec<String> = ["systemctl", "restart", "nginx"].map(String::from).to_vec();
    let digest = invocation_digest("agent", None, &argv);
    let client = countersign_core::host_key::digest_hex(WEB1);
    let approval = Approval { request: &id, client: &client, invocation: &digest, nonce: NONCE };
    assert!(verify(&public, &approval, sig));
    let other = invocation_digest("agent", None, &["reboot".to_owned()]);
    assert!(!verify(&public, &Approval { invocation: &other, ..approval }, sig));
    let web2 = countersign_core::host_key::digest_hex(WEB2);
    assert!(!verify(&public, &Approval { client: &web2, ..approval }, sig));

    // The key is public; anyone may fetch it (and must confirm it elsewhere).
    let req = HttpRequest::builder().uri("/intake/v1/server-key").body(Body::empty()).unwrap();
    let resp = s.app.clone().oneshot(req).await.unwrap();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap()["server_key"], public[0].as_str());

    // Without a usable nonce there is nothing to bind an approval to.
    let body = json!({ "user": "agent", "argv": ["true"], "nonce": "short" });
    let (status, _) = s
        .call(Call {
            method: "POST",
            path: "/intake/v1/requests".into(),
            key: Some(WEB1),
            body: Some(body),
            peer: None,
        })
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let body = json!({ "user": "agent", "argv": ["true"] });
    let (status, _) = s
        .call(Call {
            method: "POST",
            path: "/intake/v1/requests".into(),
            key: Some(WEB1),
            body: Some(body),
            peer: None,
        })
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_single_use_approval_is_collected_once_and_covers_nothing_else() {
    let s = setup().await;
    let (status, v) = s.submit(WEB1, "agent", &["systemctl", "restart", "nginx"]).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert_eq!(v["state"], "pending");
    let id = id_of(&v);
    assert_eq!(v["url"], format!("https://cs.example.test/requests/{id}"));

    let r = s.request(&id).await;
    assert_eq!(r.facts.target.as_deref(), Some("web-1"), "the target comes from the key");
    assert_eq!(r.facts.requester.identity, "unix:web-1#agent");
    assert_eq!(r.facts.requester.actor.as_ref().map(countersign_core::ActorId::as_str), Some("agent"));
    assert!(!r.sensitive);
    assert_eq!(r.facts.attributes["command"], "systemctl restart nginx");
    assert_eq!(r.facts.attributes["runas"], "root");
    assert_eq!(r.facts.reason.as_deref(), Some("deploy"));
    assert_eq!(r.requirements.policy.as_str(), "other");

    assert_eq!(s.status(WEB1, &id, 0).await.1["state"], "pending");
    s.decide(&id, Verdict::Approve).await;
    assert_eq!(s.status(WEB1, &id, 0).await.1["state"], "approved");
    assert_eq!(s.request(&id).await.state, RequestState::Ended, "collected");
    assert_eq!(s.status(WEB1, &id, 0).await.1["state"], "approved", "a retried read still sees the answer");

    let (status, v) = s.submit(WEB1, "agent", &["systemctl", "restart", "nginx"]).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_ne!(id_of(&v), id);
}

#[tokio::test]
async fn waiting_hosts_hear_about_decisions_promptly() {
    let s = Arc::new(setup().await);
    let (_, v) = s.submit(WEB1, "agent", &["reboot"]).await;
    let id = id_of(&v);
    let waiter = {
        let s = Arc::clone(&s);
        let id = id.clone();
        tokio::spawn(async move { s.status(WEB1, &id, 30).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let started = std::time::Instant::now();
    s.decide(&id, Verdict::Deny).await;
    let (status, v) = waiter.await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["state"], "denied");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn a_window_approves_later_matching_commands_and_records_them() {
    let s = setup().await;
    let (_, v) = s.submit(WEB1, "agent", &["apt", "update"]).await;
    let window = id_of(&v);
    s.decide(&window, Verdict::Approve).await;
    let (_, v) = s.status(WEB1, &window, 0).await;
    assert_eq!(v["state"], "approved");
    assert!(v["until"].is_string());
    assert!(matches!(s.request(&window).await.state, RequestState::Active { .. }), "a window stays open");

    let (status, v) = s.submit(WEB1, "agent", &["apt", "install", "jq"]).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["state"], "approved");
    assert_eq!(id_of(&v), window);
    let r = s.request(&window).await;
    assert_eq!(r.uses.len(), 1);
    assert_eq!(r.uses[0].attributes["command"], "apt install jq");

    // Other policies, other hosts and other users are not covered.
    let (status, _) = s.submit(WEB1, "agent", &["systemctl", "stop", "x"]).await;
    assert_eq!(status, StatusCode::CREATED);
    let peer = Call {
        method: "POST",
        path: "/intake/v1/requests".into(),
        key: Some(WEB2),
        body: Some(json!({ "user": "agent", "argv": ["apt", "install", "jq"], "nonce": NONCE })),
        peer: Some("100.64.0.22"),
    };
    assert_eq!(s.call(peer).await.0, StatusCode::CREATED);

    s.daemon.engine.revoke(window.parse().unwrap(), &"bob".into(), Timestamp::now()).await.unwrap();
    let (status, _) = s.submit(WEB1, "agent", &["apt", "install", "jq"]).await;
    assert_eq!(status, StatusCode::CREATED, "a revoked window covers nothing");
    assert_eq!(s.status(WEB1, &window, 0).await.1["state"], "revoked");
}

#[tokio::test]
async fn hosts_see_and_withdraw_only_their_own_requests() {
    let s = setup().await;
    let (_, v) = s.submit(WEB1, "agent", &["reboot"]).await;
    let id = id_of(&v);
    let other = Call {
        method: "GET",
        path: format!("/intake/v1/requests/{id}"),
        key: Some(WEB2),
        body: None,
        peer: Some("100.64.0.22"),
    };
    assert_eq!(s.call(other).await.0, StatusCode::NOT_FOUND);
    assert_eq!(s.status(WEB1, "not-an-id", 0).await.0, StatusCode::NOT_FOUND);

    let delete =
        |key| Call { method: "DELETE", path: format!("/intake/v1/requests/{id}"), key, body: None, peer: None };
    assert_eq!(s.call(delete(Some(WEB1))).await.0, StatusCode::NO_CONTENT);
    assert_eq!(s.request(&id).await.state, RequestState::Withdrawn);
    assert_eq!(s.call(delete(Some(WEB1))).await.0, StatusCode::CONFLICT);
    assert_eq!(s.status(WEB1, &id, 0).await.1["state"], "withdrawn");
}

#[tokio::test]
async fn refuses_unknown_users_unmatched_commands_and_floods() {
    let s = setup().await;
    let (status, v) = s.submit(WEB1, "root", &["id"]).await;
    assert_eq!((status, v["error"].as_str()), (StatusCode::FORBIDDEN, Some("unknown-user")));
    let (status, v) = s.submit(WEB1, "stranger", &["id"]).await;
    assert_eq!((status, v["error"].as_str()), (StatusCode::FORBIDDEN, Some("no-policy")));
    let (status, _) = s.submit(WEB1, "agent", &[]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    for _ in 0..3 {
        assert_eq!(s.submit(WEB1, "agent", &["reboot"]).await.0, StatusCode::CREATED);
    }
    let (status, v) = s.submit(WEB1, "agent", &["reboot"]).await;
    assert_eq!((status, v["error"].as_str()), (StatusCode::TOO_MANY_REQUESTS, Some("too-many-pending")));
}

#[tokio::test]
async fn commands_are_quoted_and_control_characters_neutralized() {
    let s = setup().await;
    let (_, v) = s.submit(WEB1, "agent", &["sh", "-c", "echo 'hi' \u{1b}[31m"]).await;
    let r = s.request(&id_of(&v)).await;
    let command = &r.facts.attributes["command"];
    assert_eq!(command, r"sh -c 'echo '\''hi'\'' \u{1b}[31m'");
    assert!(!command.contains('\u{1b}'));
}

#[tokio::test]
async fn commands_cannot_hide_what_they_are() {
    let s = setup().await;
    // A right-to-left override shows the text after it reversed, i.e. as
    // something other than what runs; a zero-width space is not seen at all.
    let (_, v) = s.submit(WEB1, "agent", &["echo", "\u{202e}rm -rf /", "x\u{200b}y"]).await;
    let r = s.request(&id_of(&v)).await;
    assert_eq!(r.facts.attributes["command"], r"echo '\u{202e}rm -rf /' 'x\u{200b}y'");

    // Commands too long to show in full are not offered for approval at all.
    let long = "a".repeat(countersignd::intake::MAX_COMMAND_CHARS);
    let (status, v) = s.submit(WEB1, "agent", &["echo", &long]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
    let (status, v) = s.submit(WEB1, "agent", &["echo", &long[5..]]).await;
    assert_eq!(status, StatusCode::CREATED, "exactly the limit: {v}");
}

#[tokio::test]
async fn a_single_use_approval_that_runs_out_before_collection_is_not_approved() {
    let s = setup().await;
    let (_, v) = s.submit(WEB1, "agent", &["reboot"]).await;
    let id = id_of(&v);
    s.decide(&id, Verdict::Approve).await;
    // The host only asks after the approval's time is up.
    let later = Timestamp::now() + jiff::SignedDuration::from_mins(5);
    s.daemon.engine.advance_open(later).await.unwrap();
    let r = s.request(&id).await;
    assert_eq!((r.state, r.collected_at), (RequestState::Ended, None));
    assert_eq!(s.status(WEB1, &id, 0).await.1["state"], "expired");
}

#[test]
fn configuration_mistakes_are_reported() {
    let ok = config();
    assert_eq!(ok.clients.len(), 4);

    let bad = r#"
        [server]
        public_url = "https://cs.example.test"
        [[person]]
        id = "bob"
        [roles]
        member = ["person:bob"]
        [backend.sudo]
        type = "host"
        [[client]]
        id = "a"
        auth = { host_key = "sha256:abc" }
        actor = "bob"
        [[client]]
        id = "b"
        auth = { host_key = "sha256:1111111111111111111111111111111111111111111111111111111111111111" }
        [[client]]
        id = "b"
        auth = { host_key = "sha256:1111111111111111111111111111111111111111111111111111111111111111" }
    "#;
    let e = Config::from_toml(bad).unwrap_err().to_string();
    assert!(e.contains("64 lowercase hex digits"), "{e}");
    assert!(e.contains("client b: duplicate id"), "{e}");
    assert!(e.contains("client b: auth.host_key is used by another client"), "{e}");
    assert!(e.contains("actor is only used with the question scope"), "{e}");
    assert!(e.contains("need an [intake] section"), "{e}");
}

#[tokio::test]
async fn sensitive_requests_are_marked_when_the_policy_honors_it() {
    let s = setup().await;
    let body = json!({ "user": "agent", "argv": ["cat", "/etc/shadow"], "sensitive": true, "nonce": NONCE });
    let call =
        Call { method: "POST", path: "/intake/v1/requests".into(), key: Some(WEB1), body: Some(body), peer: None };
    let (status, v) = s.call(call).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert!(s.request(&id_of(&v)).await.sensitive);
}

#[tokio::test]
async fn keys_only_work_within_their_scopes() {
    let s = setup().await;
    let (status, v) = s.submit(&AGENT, "agent", &["id"]).await;
    assert_eq!((status, v["error"].as_str()), (StatusCode::FORBIDDEN, Some("scope")));
    let ask = Call {
        method: "POST",
        path: "/intake/v1/questions".into(),
        key: Some(WEB1),
        body: Some(question("Go?", false)),
        peer: None,
    };
    let (status, v) = s.call(ask).await;
    assert_eq!((status, v["error"].as_str()), (StatusCode::FORBIDDEN, Some("scope")));
}

fn question(message: &str, confidential: bool) -> Value {
    json!({
        "message": message,
        "requestedSchema": {
            "type": "object",
            "properties": { "token": { "type": "string", "title": "Token" } },
            "required": ["token"]
        },
        "context": { "service": "api" },
        "confidentiality": { "question": confidential }
    })
}

impl Setup {
    async fn ask(&self, body: Value) -> (StatusCode, Value) {
        let call = Call {
            method: "POST",
            path: "/intake/v1/questions".into(),
            key: Some(AGENT.as_str()),
            body: Some(body),
            peer: None,
        };
        self.call(call).await
    }

    async fn question_status(&self, id: &str, wait: u64) -> (StatusCode, Value) {
        let path = format!("/intake/v1/questions/{id}?wait={wait}");
        self.call(Call { method: "GET", path, key: Some(AGENT.as_str()), body: None, peer: None }).await
    }

    async fn answer(&self, id: &str, content: Value, confidential: bool) {
        let intent = AnswerIntent {
            question_id: id.parse().unwrap(),
            responder: "bob".into(),
            response: Response::Accept { content: content.as_object().unwrap().clone(), confidential },
            assurance: Assurance::Linked,
            via: "web".into(),
        };
        self.daemon.engine.answer(intent, Timestamp::now()).await.unwrap();
    }
}

#[tokio::test]
async fn questions_are_asked_waited_on_and_answered() {
    let s = Arc::new(setup().await);
    let (status, v) = s.ask(question("Which token?", false)).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert_eq!(v["state"], "pending");
    let id = id_of(&v);
    assert_eq!(v["url"], format!("https://cs.example.test/requests/{id}"));

    let waiter = {
        let s = Arc::clone(&s);
        let id = id.clone();
        tokio::spawn(async move { s.question_status(&id, 30).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    s.answer(&id, json!({ "token": "t-123" }), false).await;
    let (status, v) = waiter.await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!((v["state"].as_str(), v["action"].as_str()), (Some("answered"), Some("accept")));
    assert_eq!(v["content"]["token"], "t-123");
    assert_eq!(v["answeredBy"], "bob");
    // Not confidential: it can be read again.
    assert_eq!(s.question_status(&id, 0).await.1["content"]["token"], "t-123");

    // Only the asking client sees it.
    let other =
        Call { method: "GET", path: format!("/intake/v1/questions/{id}"), key: Some(WEB1), body: None, peer: None };
    assert_ne!(s.call(other).await.0, StatusCode::OK);
}

#[tokio::test]
async fn a_confidential_answer_is_handed_over_once() {
    let s = setup().await;
    let (status, v) = s.ask(question("Recovery token for the vault?", true)).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    let id = id_of(&v);
    s.answer(&id, json!({ "token": "vault-777" }), true).await;

    let (_, first) = s.question_status(&id, 0).await;
    assert_eq!(first["content"]["token"], "vault-777");
    assert_eq!(first["confidential"], true);
    let (_, second) = s.question_status(&id, 0).await;
    assert!(second.get("content").is_none(), "{second}");
    assert_eq!(second["contentRemoved"], true);

    let stored = s.store.get_question(id.parse().unwrap()).await.unwrap().unwrap();
    let raw = serde_json::to_string(&stored).unwrap();
    assert!(!raw.contains("vault-777") && !raw.contains("Recovery token"), "{raw}");
}

#[tokio::test]
async fn askers_withdraw_their_questions_and_bad_questions_are_refused() {
    let s = setup().await;
    let (_, v) = s.ask(question("Still needed?", false)).await;
    let id = id_of(&v);
    let delete = Call {
        method: "DELETE",
        path: format!("/intake/v1/questions/{id}"),
        key: Some(AGENT.as_str()),
        body: None,
        peer: None,
    };
    assert_eq!(s.call(delete).await.0, StatusCode::NO_CONTENT);
    let (_, v) = s.question_status(&id, 0).await;
    assert_eq!((v["state"].as_str(), v["action"].as_str()), (Some("withdrawn"), Some("cancel")));

    let mut bad = question("Pick", false);
    bad["requestedSchema"]["properties"]["token"] = json!({ "type": "array" });
    assert_eq!(s.ask(bad).await.0, StatusCode::BAD_REQUEST);
    let (status, _) = s.ask(json!({ "message": "", "requestedSchema": question("x", false)["requestedSchema"] })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn decisions_made_by_another_process_reach_waiting_hosts() {
    let s = Arc::new(setup().await);
    let (_, v) = s.submit(WEB1, "agent", &["reboot"]).await;
    let id = id_of(&v);
    let waiter = {
        let s = Arc::clone(&s);
        let id = id.clone();
        tokio::spawn(async move { s.status(WEB1, &id, 30).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The CLI decides through its own engine on the same database.
    let config = config();
    let other = countersignd::engine::Engine::new(
        Arc::clone(&s.store),
        build_backends(&config, &s.store).unwrap(),
        countersignd::rules_from(&config),
    );
    let started = std::time::Instant::now();
    let intent = ActionIntent {
        request_id: id.parse().unwrap(),
        verdict: Verdict::Deny,
        approver: "bob".into(),
        assurance: Assurance::Linked,
        via: "cli".into(),
        comment: None,
    };
    other.decide(intent, Timestamp::now()).await.unwrap();
    let (_, v) = waiter.await.unwrap();
    assert_eq!(v["state"], "denied");
    assert!(started.elapsed() < Duration::from_secs(5), "took {:?}", started.elapsed());
}
