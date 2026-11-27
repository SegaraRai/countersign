//! The helper against a fake `/proc` and a real countersign intake server.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use countersign_core::{ActionIntent, Assurance, RequestFilter, RequestState, Store, Verdict};
use countersign_store_sqlite::SqliteStore;
use countersign_sudo::invocation::{Host, read};
use countersign_sudo::{Client, Config, Enroll, Error, Invocation, Outcome};
use countersignd::config::Config as DaemonConfig;
use countersignd::{Daemon, build_backends};
use jiff::Timestamp;

fn args(s: &[&str]) -> Vec<String> {
    s.iter().map(|a| (*a).to_owned()).collect()
}

/// A sudo process (pid 42) run by uid 1000 (`agent`).
struct FakeHost {
    exe: &'static str,
    real_uid: &'static str,
    cmdline: &'static [u8],
    environ: &'static [u8],
}

impl Default for FakeHost {
    fn default() -> Self {
        Self {
            exe: "/usr/lib/cargo/bin/sudo",
            real_uid: "1000",
            cmdline: b"sudo\0apt\0install\0jq\0",
            environ: b"HOME=/home/agent\0COUNTERSIGN_REASON= install jq for the deploy script \0",
        }
    }
}

impl Host for FakeHost {
    fn exe(&self, pid: u32) -> std::io::Result<PathBuf> {
        assert_eq!(pid, 42);
        Ok(self.exe.into())
    }
    fn cmdline(&self, _: u32) -> std::io::Result<Vec<u8>> {
        Ok(self.cmdline.to_vec())
    }
    fn environ(&self, _: u32) -> std::io::Result<Vec<u8>> {
        Ok(self.environ.to_vec())
    }
    fn cwd(&self, _: u32) -> std::io::Result<PathBuf> {
        Ok("/home/agent/app".into())
    }
    fn status(&self, _: u32) -> std::io::Result<String> {
        Ok(format!("Name:\tsudo\nUid:\t{}\t0\t0\t0\nGid:\t1000\t1000\t1000\t1000\n", self.real_uid))
    }
    fn passwd(&self) -> std::io::Result<String> {
        Ok("root:x:0:0:root:/root:/bin/bash\nagent:x:1000:1000::/home/agent:/bin/bash\n".into())
    }
}

fn pam_env(user: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("PAM_TYPE".into(), "auth".into()),
        ("PAM_SERVICE".into(), "sudo".into()),
        ("PAM_USER".into(), user.into()),
        ("PAM_TTY".into(), "/dev/pts/3".into()),
    ])
}

fn binaries() -> Vec<PathBuf> {
    countersign_sudo::invocation::DEFAULT_SUDO_BINARIES.iter().map(PathBuf::from).collect()
}

#[test]
fn reads_the_invocation_from_the_calling_sudo() {
    let inv = read(&FakeHost::default(), 42, &pam_env("agent"), &binaries()).unwrap();
    assert_eq!(
        inv,
        Invocation {
            user: "agent".into(),
            sudo_argv: args(&["sudo", "apt", "install", "jq"]),
            cwd: Some("/home/agent/app".into()),
            tty: Some("/dev/pts/3".into()),
            reason: Some("install jq for the deploy script".into()),
            sensitive: false,
        }
    );

    let host = FakeHost { environ: b"COUNTERSIGN_SENSITIVE=1\0", ..FakeHost::default() };
    let inv = read(&host, 42, &pam_env("agent"), &binaries()).unwrap();
    assert!(inv.sensitive && inv.reason.is_none());
    let host = FakeHost { environ: b"COUNTERSIGN_SENSITIVE=0\0", ..FakeHost::default() };
    assert!(!read(&host, 42, &pam_env("agent"), &binaries()).unwrap().sensitive);
}

#[test]
fn refuses_anything_but_sudo_authenticating_its_own_caller() {
    let fail =
        |host: FakeHost, env: BTreeMap<String, String>| read(&host, 42, &env, &binaries()).unwrap_err().to_string();

    assert!(fail(FakeHost { exe: "/usr/bin/su", ..FakeHost::default() }, pam_env("agent")).contains("not sudo"));
    assert!(
        fail(FakeHost { real_uid: "0", ..FakeHost::default() }, pam_env("agent")).contains("not the user running sudo")
    );
    assert!(fail(FakeHost::default(), pam_env("root")).contains("not the user running sudo"));
    assert!(fail(FakeHost::default(), pam_env("nobody")).contains("not the user running sudo"));

    let mut env = pam_env("agent");
    env.insert("PAM_TYPE".into(), "session".into());
    assert!(fail(FakeHost::default(), env).contains("PAM_TYPE"));
    let mut env = pam_env("agent");
    env.insert("PAM_SERVICE".into(), "login".into());
    assert!(fail(FakeHost::default(), env).contains("not a sudo PAM service"));
}

#[test]
fn config_defaults_and_validation() {
    let keys = format!("server_keys = [{:?}]", pinned()[0]);
    let c = Config::parse(&format!("server = \"https://cs.example.test:8443\"\n{keys}")).unwrap();
    assert_eq!(c.key_file, PathBuf::from("/etc/countersign/host.key"));
    assert_eq!(c.timeout, Duration::from_secs(300));
    assert_eq!(c.ca_file, None);
    assert!(c.sudo_binaries.contains(&PathBuf::from("/usr/bin/sudo")));
    assert!(
        Config::parse(&format!("server = \"http://127.0.0.1:8081\"\n{keys}")).is_ok(),
        "plain HTTP to this machine"
    );
    for bad in [
        format!("server = \"cs.example.test:8443\"\n{keys}"),
        format!("server = \"http://cs.example.test:8443\"\n{keys}"),
        format!("server = \"https://x\"\ntimeout = \"0s\"\n{keys}"),
        format!("server = \"https://x\"\nkey = \"inline\"\n{keys}"),
        "server = \"https://x\"".to_owned(),
        "server = \"https://x\"\nserver_keys = []".to_owned(),
        format!("server = \"https://x\"\nserver_keys = [{KEY:?}]"),
    ] {
        assert!(matches!(Config::parse(&bad), Err(Error::Config(_))), "{bad}");
    }
}

#[test]
fn a_ca_file_must_hold_certificates() {
    let dir = std::env::temp_dir().join(format!("cs-sudo-ca-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let garbage = dir.join("garbage.pem");
    std::fs::write(&garbage, "not a certificate").unwrap();
    let err = |p: &std::path::Path| match Client::new("https://x", KEY.to_owned(), Some(p), pinned()) {
        Err(Error::Config(e)) => e,
        other => panic!("{other:?}"),
    };
    assert!(err(&dir.join("missing.pem")).contains("missing.pem"));
    assert!(err(&garbage).contains("no certificate"));
}

#[cfg(unix)]
#[test]
fn refuses_a_key_file_others_can_read() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = std::env::temp_dir().join(format!("cs-sudo-key-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("host.key");
    std::fs::write(&path, "cshk_AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEDVuYWg\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(countersign_sudo::read_key(&path).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(countersign_sudo::read_key(&path).unwrap(), "cshk_AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEDVuYWg");
    // Anything but a host key is refused before it is sent anywhere.
    std::fs::write(&path, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n").unwrap();
    let e = countersign_sudo::read_key(&path).unwrap_err().to_string();
    assert!(e.contains("countersign host-key"), "{e}");
    let _ = std::fs::remove_dir_all(dir);
}

// ---------------------------------------------------------------- end to end

const KEY: &str = "cshk_AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEDVuYWg";

struct Server {
    url: String,
    daemon: Daemon,
    store: Arc<dyn Store>,
}

/// A signing key file for the daemon under test (one per test process).
fn signing_key_file() -> std::path::PathBuf {
    static PATH: std::sync::LazyLock<std::path::PathBuf> = std::sync::LazyLock::new(|| {
        let p = std::env::temp_dir().join(format!("countersign-test-signing-{}.key", std::process::id()));
        std::fs::write(&p, countersign_core::approval_signing::ServerKey::generate(&SIGNING_SEED)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        p
    });
    PATH.clone()
}

const SIGNING_SEED: [u8; 32] = [5; 32];

/// The public key the daemon under test signs with.
fn pinned() -> Vec<String> {
    vec![
        countersign_core::approval_signing::ServerKey::parse(&countersign_core::approval_signing::ServerKey::generate(
            &SIGNING_SEED,
        ))
        .unwrap()
        .public(),
    ]
}

async fn server() -> Server {
    let text = format!(
        r#"
        [server]
        public_url = "https://cs.example.test"
        [intake]
        listen = "127.0.0.1:0"
        behind_proxy = true
        signing_key_file = "set by the test"
        [backend.sudo]
        type = "host"
        [[client]]
        id = "web-1"
        auth = {{ host_key = "sha256:{}" }}
        [[person]]
        id = "bob"
        [[workload]]
        id = "agent"
        owners = ["bob"]
        identities = ["unix:web-1#agent"]
        [[group]]
        name = "ops"
        members = ["bob"]
        [roles]
        member = ["group:ops"]
        [[policy]]
        name = "packages"
        match = {{ backend = "sudo", attributes = {{ command = "apt *" }} }}
        grant = "window"
        max_ttl = "15m"
        approvers = ["group:ops"]
        min_assurance = "linked"
        [[policy]]
        name = "other"
        match = {{ backend = "sudo" }}
        max_ttl = "1m"
        approvers = ["group:ops"]
        min_assurance = "linked"
        sensitive = "honor"
        "#,
        countersign_core::host_key::digest_hex(KEY)
    );
    let mut config = DaemonConfig::from_toml(&text).unwrap();
    config.intake.as_mut().unwrap().signing_key_file = signing_key_file();
    let store: Arc<dyn Store> = Arc::new(SqliteStore::in_memory().await.unwrap());
    let backends = build_backends(&config, &store).unwrap();
    let daemon = Daemon::with_parts(&config, Arc::clone(&store), backends, vec![]).unwrap();
    let app = countersignd::intake::router(daemon.intake.clone().unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await.unwrap();
    });
    Server { url, daemon, store }
}

impl Server {
    /// Decide the most recent pending request as soon as it appears.
    fn decide_when_pending(&self, verdict: Verdict) -> tokio::task::JoinHandle<()> {
        let engine = Arc::clone(&self.daemon.engine);
        let store = Arc::clone(&self.store);
        tokio::spawn(async move {
            loop {
                let open = store.list_requests(&RequestFilter { open_only: true, limit: None }).await.unwrap();
                if let Some(r) = open.iter().find(|r| r.state.is_pending()) {
                    let intent = ActionIntent {
                        request_id: r.id,
                        verdict,
                        approver: "bob".into(),
                        assurance: Assurance::Linked,
                        via: "discord".into(),
                        comment: None,
                    };
                    engine.decide(intent, Timestamp::now()).await.unwrap();
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
    }

    async fn states(&self) -> Vec<RequestState> {
        self.store.list_requests(&RequestFilter::default()).await.unwrap().into_iter().map(|r| r.state).collect()
    }
}

fn invocation(argv: &[&str]) -> Invocation {
    Invocation {
        user: "agent".into(),
        sudo_argv: std::iter::once("sudo").chain(argv.iter().copied()).map(str::to_owned).collect(),
        cwd: Some("/home/agent".into()),
        tty: None,
        reason: Some("testing".into()),
        sensitive: false,
    }
}

async fn ask(s: &Server, key: &str, argv: &[&str], timeout: Duration) -> (Outcome, Vec<String>) {
    ask_pinned(s, key, argv, timeout, pinned()).await
}

async fn ask_pinned(
    s: &Server,
    key: &str,
    argv: &[&str],
    timeout: Duration,
    keys: Vec<String>,
) -> (Outcome, Vec<String>) {
    let client = Client::new(&s.url, key.to_owned(), None, keys).unwrap();
    let mut said = Vec::new();
    let outcome =
        client.ask(&invocation(argv), timeout, std::future::pending(), &mut |m: &str| said.push(m.to_owned())).await;
    (outcome, said)
}

#[tokio::test]
async fn approval_lets_the_command_run_and_shows_the_link_while_waiting() {
    let s = server().await;
    let decider = s.decide_when_pending(Verdict::Approve);
    let (outcome, said) = ask(&s, KEY, &["systemctl", "restart", "nginx"], Duration::from_secs(10)).await;
    decider.await.unwrap();
    assert_eq!(outcome, Outcome::Approved { window: false });
    assert_eq!(said.len(), 1);
    assert!(said[0].starts_with("countersign: waiting for approval: https://cs.example.test/requests/"), "{said:?}");
    assert_eq!(s.states().await, [RequestState::Ended], "single-use approval collected");
}

#[tokio::test]
async fn a_window_covers_the_next_matching_command_without_waiting() {
    let s = server().await;
    let decider = s.decide_when_pending(Verdict::Approve);
    assert_eq!(ask(&s, KEY, &["apt", "update"], Duration::from_secs(10)).await.0, Outcome::Approved { window: false });
    decider.await.unwrap();
    let (outcome, said) = ask(&s, KEY, &["apt", "install", "jq"], Duration::from_secs(10)).await;
    assert_eq!(outcome, Outcome::Approved { window: true });
    assert!(said.is_empty(), "no waiting message");
}

#[tokio::test]
async fn denial_timeout_and_bad_keys_fail_closed() {
    let s = server().await;
    let decider = s.decide_when_pending(Verdict::Deny);
    assert_eq!(ask(&s, KEY, &["reboot"], Duration::from_secs(10)).await.0, Outcome::Refused("request denied".into()));
    decider.await.unwrap();

    let (outcome, _) = ask(&s, KEY, &["reboot"], Duration::from_millis(1500)).await;
    assert_eq!(outcome, Outcome::Refused("no decision in time; request withdrawn".into()));
    assert!(s.states().await.contains(&RequestState::Withdrawn));

    let Outcome::Refused(why) =
        ask(&s, "cshk_BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQX7m8Nw", &["reboot"], Duration::from_secs(5)).await.0
    else {
        panic!("a wrong key must not be approved")
    };
    assert!(why.contains("unknown client key"), "{why}");

    let Outcome::Refused(why) = ask(&s, KEY, &[], Duration::from_secs(5)).await.0 else { panic!() };
    assert!(why.contains("bad-request"), "{why}");
}

#[tokio::test]
async fn approvals_without_a_valid_signature_do_not_count() {
    use countersign_core::approval_signing::ServerKey;
    // Approved by a person, but signed by a key this host does not pin.
    let s = server().await;
    let decider = s.decide_when_pending(Verdict::Approve);
    let elsewhere = vec![ServerKey::parse(&ServerKey::generate(&[6; 32])).unwrap().public()];
    let (outcome, _) = ask_pinned(&s, KEY, &["reboot"], Duration::from_secs(10), elsewhere).await;
    decider.await.unwrap();
    assert!(matches!(&outcome, Outcome::Refused(m) if m.contains("not signed")), "{outcome:?}");

    // Something in between answers "approved" on its own.
    let fake = axum::Router::new().route(
        "/intake/v1/requests",
        axum::routing::post(|| async {
            axum::Json(
                serde_json::json!({ "id": "01a1e45e-662b-734f-950f-cd451a032aa3", "state": "approved", "url": "" }),
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, fake).await.unwrap() });
    let client = Client::new(&url, KEY.to_owned(), None, pinned()).unwrap();
    let outcome =
        client.ask(&invocation(&["reboot"]), Duration::from_secs(5), std::future::pending(), &mut |_: &str| {}).await;
    assert!(matches!(&outcome, Outcome::Refused(m) if m.contains("not signed")), "{outcome:?}");
}

#[tokio::test]
async fn enrolling_pins_the_key_and_writes_the_configuration() {
    let s = server().await;
    let dir = std::env::temp_dir().join(format!("cs-enroll-{}", countersign_core::RequestId::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let e = countersign_sudo::Enroll {
        server: s.url.clone(),
        ca_file: None,
        server_key: None,
        config: dir.join("sudo.toml"),
        key_file: dir.join("host.key"),
    };
    // Declined: nothing is written.
    let mut shown = String::new();
    let err = countersign_sudo::enroll(&e, &mut |k: &str| {
        shown = k.to_owned();
        false
    })
    .await
    .unwrap_err();
    assert!(err.to_string().contains("not trusted"), "{err}");
    assert_eq!(shown, pinned()[0]);
    assert!(!e.config.exists() && !e.key_file.exists());

    // A key given in advance that does not match is refused.
    let wrong = countersign_core::approval_signing::ServerKey::parse(
        &countersign_core::approval_signing::ServerKey::generate(&[6; 32]),
    )
    .unwrap()
    .public();
    let err = countersign_sudo::enroll(&Enroll { server_key: Some(wrong), ..e.clone() }, &mut |_: &str| true)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("something is in between"), "{err}");

    // The expected key: config and host key are written.
    let client =
        countersign_sudo::enroll(&Enroll { server_key: Some(pinned()[0].clone()), ..e.clone() }, &mut |_: &str| {
            panic!("no question when the key was given")
        })
        .await
        .unwrap();
    let config = Config::load(&e.config).unwrap();
    assert_eq!(config.server_keys, pinned());
    let key = countersign_sudo::read_key(&e.key_file).unwrap();
    assert!(client.contains(&countersign_core::host_key::digest_hex(&key)), "{client}");
    let err = countersign_sudo::enroll(&e, &mut |_: &str| true).await.unwrap_err();
    assert!(err.to_string().contains("exists"), "never overwrites: {err}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn cancelling_withdraws_the_request() {
    let s = server().await;
    let client = Client::new(&s.url, KEY.to_owned(), None, pinned()).unwrap();
    let cancel = tokio::time::sleep(Duration::from_millis(300));
    let outcome = client.ask(&invocation(&["reboot"]), Duration::from_secs(30), cancel, &mut |_: &str| {}).await;
    assert_eq!(outcome, Outcome::Refused("interrupted; request withdrawn".into()));
    assert_eq!(s.states().await, [RequestState::Withdrawn]);
}

#[tokio::test]
async fn an_unreachable_server_fails_closed() {
    let client = Client::new("http://127.0.0.1:9", KEY.to_owned(), None, pinned()).unwrap();
    let outcome =
        client.ask(&invocation(&["reboot"]), Duration::from_secs(5), std::future::pending(), &mut |_: &str| {}).await;
    assert!(matches!(outcome, Outcome::Refused(m) if m.contains("network")));
}
