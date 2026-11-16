//! The intake API: hosts submitting `sudo` invocations and waiting for the outcome.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request as HttpRequest, StatusCode, header};
use countersign_core::host_key::digest_hex;
use countersign_core::{ActionIntent, Assurance, RequestState, Store, Verdict};
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

fn config() -> Config {
    let text = format!(
        r#"
        [server]
        public_url = "https://cs.example.test"

        [intake]
        listen = "127.0.0.1:0"
        max_pending_per_host = 3

        [backend.sudo]
        type = "host"
        users = {{ agent = ["agents"], stranger = [] }}

        [[backend.sudo.host]]
        name = "web-1"
        key_sha256 = "{}"

        [[backend.sudo.host]]
        name = "web-2"
        key_sha256 = "{}"
        allowed_ips = ["100.64.0.22"]

        [[backend.sudo.host]]
        name = "legacy"
        key_sha256 = "{}"

        [[approver]]
        id = "bob"
        groups = ["ops"]

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
        "#,
        digest_hex(WEB1),
        digest_hex(WEB2).to_uppercase(),
        digest_hex(LEGACY),
    );
    Config::from_toml(&text).unwrap()
}

struct Setup {
    app: Router,
    daemon: Daemon,
    store: Arc<dyn Store>,
}

async fn setup() -> Setup {
    let config = config();
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
        let body = json!({ "user": user, "argv": argv, "cwd": "/home/agent", "reason": "deploy" });
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
        body: Some(json!({ "user": "agent", "argv": ["true"] })),
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
async fn a_single_use_approval_is_collected_once_and_covers_nothing_else() {
    let s = setup().await;
    let (status, v) = s.submit(WEB1, "agent", &["systemctl", "restart", "nginx"]).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert_eq!(v["state"], "pending");
    let id = id_of(&v);
    assert_eq!(v["url"], format!("https://cs.example.test/requests/{id}"));

    let r = s.request(&id).await;
    assert_eq!(r.facts.target.as_deref(), Some("web-1"), "the target comes from the key");
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
        body: Some(json!({ "user": "agent", "argv": ["apt", "install", "jq"] })),
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

#[test]
fn configuration_mistakes_are_reported() {
    let ok = config();
    assert_eq!(ok.host_backends().len(), 1);

    let bad = r#"
        [server]
        public_url = "https://cs.example.test"
        [backend.sudo]
        type = "host"
        users = { agent = [] }
        [[backend.sudo.host]]
        name = "a"
        key_sha256 = "abc"
        [[backend.sudo.host]]
        name = "a"
        key_sha256 = "abc"
    "#;
    let e = Config::from_toml(bad).unwrap_err().to_string();
    assert!(e.contains("64 hex digits"), "{e}");
    assert!(e.contains("duplicate host a"), "{e}");
    assert!(e.contains("used by another host"), "{e}");
    assert!(e.contains("need an [intake] section"), "{e}");
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
