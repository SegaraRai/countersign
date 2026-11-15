//! The helper against a fake `/proc` and a real countersign intake server.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use countersign_core::{ActionIntent, Assurance, RequestFilter, RequestState, Store, Verdict};
use countersign_store_sqlite::SqliteStore;
use countersign_sudo::invocation::{Host, Parsed, parse_sudo_args, read};
use countersign_sudo::{Client, Config, Error, Invocation, Outcome};
use countersignd::config::Config as DaemonConfig;
use countersignd::{Daemon, build_backends};
use jiff::Timestamp;

fn args(s: &[&str]) -> Vec<String> {
    s.iter().map(|a| (*a).to_owned()).collect()
}

fn parsed(s: &[&str]) -> Parsed {
    parse_sudo_args(&args(s))
}

fn cmd(s: &[&str]) -> Vec<String> {
    args(s)
}

#[test]
fn parses_common_sudo_command_lines() {
    assert_eq!(
        parsed(&["sudo", "apt", "upgrade", "-y"]),
        Parsed { runas: None, command: cmd(&["apt", "upgrade", "-y"]) }
    );
    assert_eq!(
        parsed(&["/usr/bin/sudo", "-u", "postgres", "psql", "-c", "select 1"]),
        Parsed { runas: Some("postgres".into()), command: cmd(&["psql", "-c", "select 1"]) }
    );
    assert_eq!(parsed(&["sudo", "-nupostgres", "id"]).runas.as_deref(), Some("postgres"));
    assert_eq!(
        parsed(&["sudo", "--user=www", "--", "ls", "-l"]),
        Parsed { runas: Some("www".into()), command: cmd(&["ls", "-l"]) }
    );
    assert_eq!(parsed(&["sudo", "--user", "www", "-E", "env"]).command, cmd(&["env"]));
    assert_eq!(parsed(&["sudo", "-D", "/srv", "make"]).command, cmd(&["make"]));
    assert_eq!(parsed(&["sudo", "-i"]).command, cmd(&["(login shell)"]));
    assert_eq!(
        parsed(&["sudo", "-iu", "deploy"]),
        Parsed { runas: Some("deploy".into()), command: cmd(&["(login shell)"]) }
    );
    assert_eq!(parsed(&["sudo", "-s"]).command, cmd(&["(shell)"]));
    assert_eq!(parsed(&["sudo", "-i", "whoami"]).command, cmd(&["whoami"]));
    assert_eq!(parsed(&["sudo", "-v"]).command, cmd(&["(validate)"]));
    assert_eq!(parsed(&["sudo", "-l"]).command, cmd(&["(list privileges)"]));
    assert_eq!(parsed(&["sudo", "-e", "/etc/hosts"]).command, cmd(&["sudoedit", "/etc/hosts"]));
    assert_eq!(parsed(&["sudoedit", "/etc/hosts"]).command, cmd(&["sudoedit", "/etc/hosts"]));
}

#[test]
fn unknown_options_send_the_raw_arguments() {
    // Unrecognised syntax must not be mistaken for an innocuous command.
    assert_eq!(parsed(&["sudo", "-X", "apt", "upgrade"]).command, cmd(&["-X", "apt", "upgrade"]));
    assert_eq!(parsed(&["sudo", "--frobnicate", "apt"]).command, cmd(&["--frobnicate", "apt"]));
    assert_eq!(parsed(&["sudo", "-u"]).command, cmd(&["-u"]));
    assert_eq!(parsed(&["sudo"]).command, Vec::<String>::new());
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
            runas: None,
            argv: cmd(&["apt", "install", "jq"]),
            cwd: Some("/home/agent/app".into()),
            tty: Some("/dev/pts/3".into()),
            reason: Some("install jq for the deploy script".into()),
        }
    );
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
    let c = Config::parse(r#"server = "http://100.64.0.10:8443""#).unwrap();
    assert_eq!(c.key_file, PathBuf::from("/etc/countersign/host.key"));
    assert_eq!(c.timeout, Duration::from_secs(300));
    assert!(c.sudo_binaries.contains(&PathBuf::from("/usr/bin/sudo")));
    assert!(matches!(Config::parse(r#"server = "100.64.0.10:8443""#), Err(Error::Config(_))));
    assert!(matches!(Config::parse("server = \"http://x\"\ntimeout = \"0s\""), Err(Error::Config(_))));
    assert!(matches!(Config::parse("server = \"http://x\"\nkey = \"inline\""), Err(Error::Config(_))));
}

#[cfg(unix)]
#[test]
fn refuses_a_key_file_others_can_read() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = std::env::temp_dir().join(format!("cs-sudo-key-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("host.key");
    std::fs::write(&path, "secret\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(countersign_sudo::read_key(&path).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(countersign_sudo::read_key(&path).unwrap(), "secret");
    let _ = std::fs::remove_dir_all(dir);
}

// ---------------------------------------------------------------- end to end

const KEY: &str = "host-key-for-web-1";

struct Server {
    url: String,
    daemon: Daemon,
    store: Arc<dyn Store>,
}

async fn server() -> Server {
    let text = format!(
        r#"
        [server]
        public_url = "https://cs.example.test"
        [intake]
        listen = "127.0.0.1:0"
        [backend.sudo]
        type = "host"
        users = {{ agent = ["agents"] }}
        [[backend.sudo.host]]
        name = "web-1"
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
        match = {{ backend = "sudo" }}
        max_ttl = "1m"
        approvers = ["group:ops"]
        min_assurance = "linked"
        "#,
        countersignd::intake::key_sha256(KEY)
    );
    let config = DaemonConfig::from_toml(&text).unwrap();
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
        runas: None,
        argv: args(argv),
        cwd: Some("/home/agent".into()),
        tty: None,
        reason: Some("testing".into()),
    }
}

async fn ask(s: &Server, key: &str, argv: &[&str], timeout: Duration) -> (Outcome, Vec<String>) {
    let client = Client::new(&s.url, key.to_owned()).unwrap();
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

    let Outcome::Refused(why) = ask(&s, "wrong-key", &["reboot"], Duration::from_secs(5)).await.0 else {
        panic!("a wrong key must not be approved")
    };
    assert!(why.contains("unknown host key"), "{why}");

    let Outcome::Refused(why) = ask(&s, KEY, &[], Duration::from_secs(5)).await.0 else { panic!() };
    assert!(why.contains("bad-request"), "{why}");
}

#[tokio::test]
async fn cancelling_withdraws_the_request() {
    let s = server().await;
    let client = Client::new(&s.url, KEY.to_owned()).unwrap();
    let cancel = tokio::time::sleep(Duration::from_millis(300));
    let outcome = client.ask(&invocation(&["reboot"]), Duration::from_secs(30), cancel, &mut |_: &str| {}).await;
    assert_eq!(outcome, Outcome::Refused("interrupted; request withdrawn".into()));
    assert_eq!(s.states().await, [RequestState::Withdrawn]);
}

#[tokio::test]
async fn an_unreachable_server_fails_closed() {
    let client = Client::new("http://127.0.0.1:9", KEY.to_owned()).unwrap();
    let outcome =
        client.ask(&invocation(&["reboot"]), Duration::from_secs(5), std::future::pending(), &mut |_: &str| {}).await;
    assert!(matches!(outcome, Outcome::Refused(m) if m.contains("network")));
}
