use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};

use countersign_core::{AccessBackend, BackendError, BackendName, GrantHandle, SubjectRef};

use super::{CmdOutput, ExecBackend, ExecConfig, RunError, Runner};

/// Replays canned outputs and records what it was asked.
#[derive(Debug, Default)]
struct Fake {
    replies: Mutex<VecDeque<Result<CmdOutput, RunError>>>,
    calls: Mutex<Vec<(String, Value)>>,
}

impl Fake {
    fn ok(self, stdout: &Value) -> Self {
        self.replies.lock().unwrap().push_back(Ok(CmdOutput {
            success: true,
            stdout: serde_json::to_vec(stdout).unwrap(),
            stderr: String::new(),
        }));
        self
    }

    fn fail(self, stdout: &str, stderr: &str) -> Self {
        self.replies.lock().unwrap().push_back(Ok(CmdOutput {
            success: false,
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.to_owned(),
        }));
        self
    }

    fn timeout(self) -> Self {
        self.replies.lock().unwrap().push_back(Err(RunError::Timeout(Duration::from_secs(1))));
        self
    }
}

#[async_trait]
impl Runner for Fake {
    async fn run(&self, op: &str, input: &[u8]) -> Result<CmdOutput, RunError> {
        self.calls.lock().unwrap().push((op.to_owned(), serde_json::from_slice(input).unwrap()));
        self.replies.lock().unwrap().pop_front().expect("unexpected call")
    }
}

fn config(extra: &str) -> ExecConfig {
    toml::from_str(&format!("command = [\"/bin/helper\", \"--flag\"]\n{extra}")).unwrap()
}

fn backend(fake: Fake) -> ExecBackend<Fake> {
    ExecBackend::with_runner(BackendName::new("sudo"), &config(""), fake)
}

fn subject() -> SubjectRef {
    SubjectRef { backend: "sudo".into(), kind: "rule".into(), id: "r-1".into() }
}

fn facts() -> Value {
    json!({ "requester": { "id": "alice", "groups": ["dev"] }, "target": "staging-1", "requested_ttl": "15m",
            "reason": "deploy", "attributes": { "cmd": "systemctl" },
            "summary": { "title": "a restart of nginx", "lines": [{ "label": "Unit", "value": "nginx.service" }] } })
}

#[tokio::test]
async fn discover_maps_subjects_and_facts() {
    let b = backend(Fake::default().ok(&json!({ "pending": [
        { "kind": "rule", "id": "r-1", "facts": facts(), "observed_at": "2026-01-02T03:04:05Z" },
        { "kind": "rule", "id": "r-2", "facts": { "requester": { "id": "bob" } } },
    ]})));
    let pending = b.discover_pending().await.unwrap();
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].subject, subject());
    assert_eq!(pending[0].facts.requester.id, "alice");
    assert_eq!(pending[0].facts.requested_ttl, Some(Duration::from_mins(15)));
    assert_eq!(pending[0].facts.attributes["cmd"], "systemctl");
    assert_eq!(
        pending[0].facts.action,
        Some(countersign_core::Action::Generic {
            title: "a restart of nginx".into(),
            lines: vec![countersign_core::Detail::new("Unit", "nginx.service")],
        })
    );
    assert_eq!(pending[1].facts.action, None);
    assert_eq!(pending[0].observed_at.to_string(), "2026-01-02T03:04:05Z");
    assert_eq!(pending[1].facts.target, None);

    let calls = b.runner.calls.lock().unwrap();
    assert_eq!(calls[0], ("discover".to_owned(), json!({ "version": 1, "op": "discover" })));
}

#[tokio::test]
async fn helpers_cannot_smuggle_in_odd_subject_ids() {
    for bad in ["", "a\nb", &"x".repeat(300)] {
        let b = backend(Fake::default().ok(&json!({ "pending": [
            { "kind": "rule", "id": bad, "facts": { "requester": { "id": "x" } } }
        ]})));
        assert!(b.discover_pending().await.is_err(), "{bad:?}");
    }
}

#[tokio::test]
async fn grant_verify_deny_revoke_send_the_documented_requests() {
    let b = backend(
        Fake::default()
            .ok(&json!({ "facts": facts() }))
            .ok(&json!({ "backend_ref": "tok-9", "expires_at": "2026-01-02T03:19:05Z" }))
            .ok(&json!({}))
            .fail("", ""), // revoke with no message: treated as unavailable
    );
    let facts = b.verify(&subject()).await.unwrap();
    assert_eq!(facts.reason.as_deref(), Some("deploy"));

    let g = b.grant(&subject(), Duration::from_mins(15)).await.unwrap();
    assert_eq!(g.backend_ref.as_deref(), Some("tok-9"));
    assert_eq!(g.expires_at.unwrap().to_string(), "2026-01-02T03:19:05Z");

    b.deny(&subject()).await.unwrap();
    assert!(b.revoke(&g).await.unwrap_err().is_retryable());

    let calls = b.runner.calls.lock().unwrap();
    let s = json!({ "kind": "rule", "id": "r-1" });
    assert_eq!(calls[0].1, json!({ "version": 1, "op": "verify", "subject": s }));
    assert_eq!(calls[1].1, json!({ "version": 1, "op": "grant", "subject": s, "ttl_seconds": 900 }));
    assert_eq!(calls[2].1, json!({ "version": 1, "op": "deny", "subject": s }));
    assert_eq!(calls[3].1, json!({ "version": 1, "op": "revoke", "subject": s, "backend_ref": "tok-9" }));
}

#[tokio::test]
async fn structured_errors_are_classified() {
    let err = |kind: &str| format!(r#"{{"error": {{"kind": "{kind}", "message": "because"}}}}"#);
    let b = backend(
        Fake::default()
            .fail(&err("not-found"), "")
            .fail(&err("conflict"), "")
            .fail(&err("unavailable"), "")
            .fail(&err("unsupported"), "")
            .fail(&err("weird"), "")
            .fail("garbage", "Traceback: boom")
            .timeout()
            .fail(&err("not-found"), ""),
    );
    let s = subject();
    assert!(matches!(b.deny(&s).await, Err(BackendError::NotFound)));
    assert!(matches!(b.deny(&s).await, Err(BackendError::Conflict(m)) if m == "because"));
    assert!(matches!(b.deny(&s).await, Err(BackendError::Unavailable(m)) if m == "because"));
    assert!(matches!(b.deny(&s).await, Err(BackendError::Unsupported)));
    let e = b.deny(&s).await.unwrap_err();
    assert!(!e.is_retryable() && e.to_string().contains("because"), "{e}");
    let e = b.deny(&s).await.unwrap_err();
    assert!(e.is_retryable() && e.to_string().contains("Traceback: boom"), "{e}");
    assert!(b.deny(&s).await.unwrap_err().is_retryable(), "timeouts are retried");
    // Revoking something already gone is fine.
    let g = GrantHandle { subject: s, backend_ref: None, expires_at: None };
    b.revoke(&g).await.unwrap();
}

#[tokio::test]
async fn bad_responses_and_foreign_subjects_are_errors() {
    let b = backend(Fake::default().ok(&json!({ "nope": true })));
    assert!(b.discover_pending().await.is_err());
    let foreign = SubjectRef { backend: "other".into(), kind: "rule".into(), id: "r-1".into() };
    assert!(b.deny(&foreign).await.is_err(), "no call is made for another backend's subject");
    assert_eq!(b.runner.calls.lock().unwrap().len(), 1);
}

#[test]
fn config_validation() {
    assert!(ExecBackend::new(BackendName::new("x"), &config("")).is_ok());
    assert!(ExecBackend::new(BackendName::new("x"), &toml::from_str("command = []").unwrap()).is_err());
    let no_end = config("revoke = false");
    assert!(ExecBackend::new(BackendName::new("x"), &no_end).is_err(), "grants must end somehow");
    let native = config("revoke = false\nnative_expiry = true");
    let b = ExecBackend::new(BackendName::new("x"), &native).unwrap();
    assert!(!b.capabilities().revoke && b.capabilities().native_expiry);
    assert!(toml::from_str::<ExecConfig>("command = [\"x\"]\nshell = true").is_err());
}

/// End to end with a real process, if Python is around.
#[tokio::test]
async fn real_helper_process() {
    let Some(python) = find_python() else {
        eprintln!("skipping: no python found");
        return;
    };
    let script = r#"
import json, os, sys
op = sys.argv[-1]
req = json.load(sys.stdin)
assert req["op"] == op and req["version"] == 1
leaked = [k for k in os.environ if k.startswith("CARGO")]
if leaked:
    print(json.dumps({"error": {"kind": "other", "message": "leaked " + ",".join(leaked)}}))
    sys.exit(1)
if op == "verify":
    print(json.dumps({"facts": {"requester": {"id": os.environ["WHO"]}}}))
elif op == "deny":
    print(json.dumps({"error": {"kind": "conflict", "message": "already decided"}}))
    sys.exit(3)
elif op == "grant":
    import time; time.sleep(10)
"#;
    let dir = std::env::temp_dir().join(format!("cs-exec-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("helper.py");
    std::fs::write(&path, script).unwrap();
    let toml_str = |s: &std::path::Path| s.display().to_string().replace('\\', "/");
    let config: ExecConfig = toml::from_str(&format!(
        "command = [\"{}\", \"{}\"]\nenv = {{ WHO = \"carol\" }}\ntimeout = \"2s\"",
        toml_str(&python),
        toml_str(&path)
    ))
    .unwrap();
    // cargo runs tests with CARGO* variables set; the helper must not see them.
    assert!(std::env::vars().any(|(k, _)| k.starts_with("CARGO")), "precondition");
    let b = ExecBackend::new(BackendName::new("sudo"), &config).unwrap();

    assert_eq!(b.verify(&subject()).await.unwrap().requester.id, "carol");
    assert!(matches!(b.deny(&subject()).await, Err(BackendError::Conflict(m)) if m == "already decided"));
    let e = b.grant(&subject(), Duration::from_secs(60)).await.unwrap_err();
    assert!(e.is_retryable() && e.to_string().contains("did not finish"), "{e}");
    let _ = std::fs::remove_dir_all(dir);
}

fn find_python() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        for name in ["python3", "python3.exe", "python.exe"] {
            let p = dir.join(name);
            // Skip the Windows Store alias stub, which is not a real interpreter.
            if p.is_file() && !p.to_string_lossy().contains("WindowsApps") {
                return Some(p);
            }
        }
    }
    None
}

#[tokio::test]
async fn facts_carry_an_initiator_and_refuse_unknown_keys() {
    let facts =
        json!({ "requester": { "id": "ci" }, "initiator": { "identity": "github:42", "display_name": "alice" } });
    let b = backend(Fake::default().ok(&json!({ "facts": facts })));
    let f = b.verify(&subject()).await.unwrap();
    let i = f.initiator.unwrap();
    assert_eq!((i.identity.as_str(), i.actor), ("github:42", None));
    assert_eq!(f.requester.identity, "", "countersign names the requester");
    assert_eq!(b.identity_scheme(), "exec");

    // A helper cannot claim an identity or actor for the requester.
    let claimed = json!({ "facts": { "requester": { "id": "ci", "identity": "oidc:x#y" } } });
    assert!(backend(Fake::default().ok(&claimed)).verify(&subject()).await.is_err());
}
