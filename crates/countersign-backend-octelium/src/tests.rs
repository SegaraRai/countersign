use std::sync::Mutex;

use serde_json::json;

use super::*;

/// Answers commands from a script keyed by the joined argument list and
/// records every call.
#[derive(Debug, Default)]
struct FakeRunner {
    responses: Mutex<HashMap<String, Vec<CmdOutput>>>,
    calls: Mutex<Vec<String>>,
}

impl FakeRunner {
    fn on(self, args: &str, out: CmdOutput) -> Self {
        self.responses.lock().unwrap().entry(args.to_owned()).or_default().push(out);
        self
    }
    fn ok_json(self, args: &str, v: &serde_json::Value) -> Self {
        self.on(args, CmdOutput { success: true, stdout: v.to_string().into_bytes(), stderr: String::new() })
    }
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl Runner for FakeRunner {
    async fn run(&self, args: &[String]) -> Result<CmdOutput, RunError> {
        let key = args.join(" ");
        self.calls.lock().unwrap().push(key.clone());
        let mut r = self.responses.lock().unwrap();
        let queue = r.get_mut(&key).unwrap_or_else(|| panic!("unexpected command: {key}"));
        // Replay the last response forever; earlier ones are consumed in order.
        Ok(if queue.len() > 1 { queue.remove(0) } else { queue[0].clone() })
    }
}

const D: &str = "--domain oct.example.com";

fn config() -> OcteliumConfig {
    OcteliumConfig {
        domain: "oct.example.com".into(),
        octeliumctl: "octeliumctl".into(),
        homedir: None,
        command_timeout: Duration::from_secs(5),
        identity_providers: BTreeMap::from([("pocket".to_owned(), "oidc:https://id.example.com".to_owned())]),
    }
}

fn backend(r: FakeRunner) -> OcteliumBackend<FakeRunner> {
    OcteliumBackend::with_runner("oct".into(), config(), r).unwrap()
}

fn session(name: &str, user: &str, state: &str) -> serde_json::Value {
    json!({
        "apiVersion": "core/v1", "kind": "Session",
        "metadata": { "name": name, "createdAt": "2026-11-15T17:48:47.310158229Z", "uid": "x" },
        "spec": { "state": state, "expiresAt": "2027-02-13T17:48:47Z" },
        "status": {
            "userRef": { "name": user, "kind": "User" },
            "type": "CLIENT",
            "authentication": { "info": {
                "type": "CREDENTIAL",
                "credential": { "credentialRef": { "name": "agent-token" }, "type": "AUTH_TOKEN" },
                "downstream": { "userAgent": "octelium-cli/v0.51.0" }
            }},
            "somethingNew": { "ignored": true }
        }
    })
}

fn user(groups: &[&str], identities: &serde_json::Value) -> serde_json::Value {
    json!({ "kind": "User", "metadata": { "name": "u" },
            "spec": { "type": "WORKLOAD", "groups": groups, "authentication": { "identities": identities } } })
}

fn list(items: &[serde_json::Value]) -> serde_json::Value {
    json!({ "kind": "SessionList", "items": items, "listResponseMeta": { "totalCount": items.len() } })
}

fn subject(id: &str) -> SubjectRef {
    SubjectRef { backend: "oct".into(), kind: KIND_SESSION.into(), id: id.into() }
}

#[tokio::test]
async fn discover_returns_pending_sessions_with_user_facts() {
    let r = FakeRunner::default()
        .ok_json(
            &format!("get session -o json --page 1 --items-per-page 200 {D}"),
            &list(&[
                session("agent-aaa", "agent", "PENDING"),
                session("agent-bbb", "agent", "PENDING"),
                session("human-ccc", "human", "ACTIVE"),
            ]),
        )
        .ok_json(
            &format!("get user -o json {D} -- agent"),
            &user(&["agents-elevated"], &json!([{ "identityProvider": "pocket", "identifier": "sub-1" }])),
        );
    let b = backend(r);
    let found = b.discover_pending().await.unwrap();

    assert_eq!(found.iter().map(|p| p.subject.id.as_str()).collect::<Vec<_>>(), ["agent-aaa", "agent-bbb"]);
    let f = &found[0].facts;
    assert_eq!(f.requester.id, "agent");
    assert!(f.requester.groups.contains("agents-elevated"));
    assert_eq!(
        f.requester.identities,
        BTreeSet::from([
            "octelium:oct.example.com:user:agent".to_owned(),
            "oidc:https://id.example.com#sub-1".to_owned()
        ])
    );
    assert_eq!(f.attributes["user_type"], "WORKLOAD");
    assert_eq!(f.attributes["auth_type"], "CREDENTIAL");
    assert_eq!(f.attributes["credential"], "agent-token");
    assert_eq!(found[0].observed_at, "2026-11-15T17:48:47.310158229Z".parse().unwrap());

    let user_lookups = b.runner.calls().iter().filter(|c| c.starts_with("get user")).count();
    assert_eq!(user_lookups, 1, "each user is looked up once per discovery");
}

#[tokio::test]
async fn discover_pages_through_long_lists() {
    let page1: Vec<_> = (0..200).map(|i| session(&format!("s-{i}"), "agent", "ACTIVE")).collect();
    let mut l1 = list(&page1);
    l1["listResponseMeta"]["totalCount"] = json!(201);
    let r = FakeRunner::default()
        .ok_json(&format!("get session -o json --page 1 --items-per-page 200 {D}"), &l1)
        .ok_json(
            &format!("get session -o json --page 2 --items-per-page 200 {D}"),
            &list(&[session("s-last", "agent", "PENDING")]),
        )
        .ok_json(&format!("get user -o json {D} -- agent"), &user(&[], &json!([])));
    let found = backend(r).discover_pending().await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].subject.id, "s-last");
}

#[tokio::test]
async fn unmapped_idp_gets_a_backend_scoped_identity() {
    let r = FakeRunner::default()
        .ok_json(&format!("get session -o json {D} -- s1"), &session("s1", "agent", "PENDING"))
        .ok_json(
            &format!("get user -o json {D} -- agent"),
            &user(&[], &json!([{ "identityProvider": "github", "identifier": "42" }])),
        );
    let facts = backend(r).verify(&subject("s1")).await.unwrap();
    assert!(facts.requester.identities.contains("octelium:oct.example.com:idp:github#42"));
}

#[tokio::test]
async fn grant_approves_with_expiry_and_reads_it_back() {
    let r = FakeRunner::default()
        .ok_json(&format!("get session -o json {D} -- s1"), &session("s1", "agent", "PENDING"))
        .ok_json(&format!("get session -o json {D} -- s1"), &{
            let mut s = session("s1", "agent", "ACTIVE");
            s["spec"]["expiresAt"] = json!("2026-11-16T10:30:00Z");
            s
        })
        .on(
            &format!("update session --approve --expire-in 1800s {D} -- s1"),
            CmdOutput { success: true, ..Default::default() },
        );
    let b = backend(r);
    let g = b.grant(&subject("s1"), Duration::from_secs(1800)).await.unwrap();
    assert_eq!(g.expires_at, Some("2026-11-16T10:30:00Z".parse().unwrap()));
    assert_eq!(g.subject, subject("s1"));
    assert_eq!(b.runner.calls()[1], format!("update session --approve --expire-in 1800s {D} -- s1"));
}

#[tokio::test]
async fn grant_and_deny_refuse_non_pending_sessions() {
    let r = FakeRunner::default().ok_json(&format!("get session -o json {D} -- s1"), &session("s1", "agent", "ACTIVE"));
    let b = backend(r);
    assert!(matches!(b.grant(&subject("s1"), Duration::from_secs(60)).await, Err(BackendError::Conflict(_))));
    assert!(matches!(b.deny(&subject("s1")).await, Err(BackendError::Conflict(_))));
    assert!(b.runner.calls().iter().all(|c| c.starts_with("get ")), "nothing was changed");
}

#[tokio::test]
async fn deny_rejects() {
    let r = FakeRunner::default()
        .ok_json(&format!("get session -o json {D} -- s1"), &session("s1", "agent", "PENDING"))
        .on(&format!("update session --reject {D} -- s1"), CmdOutput { success: true, ..Default::default() });
    let b = backend(r);
    b.deny(&subject("s1")).await.unwrap();
    assert_eq!(b.runner.calls().last().unwrap(), &format!("update session --reject {D} -- s1"));
}

#[tokio::test]
async fn revoke_deletes_and_tolerates_missing() {
    let r = FakeRunner::default().on(
        &format!("delete session {D} -- s1"),
        CmdOutput {
            success: false,
            stdout: b"gRPC error NotFound: core.v1.Session s1 does not exist
"
            .to_vec(),
            stderr: "Usage:
  octeliumctl delete session [flags]
"
            .into(),
        },
    );
    let g = GrantHandle { subject: subject("s1"), backend_ref: None, expires_at: None };
    backend(r).revoke(&g).await.unwrap();
}

#[tokio::test]
async fn rejects_foreign_or_malicious_subjects_without_running_anything() {
    let b = backend(FakeRunner::default());
    for id in ["--reject", "S1", "", "a b", "s1;rm"] {
        assert!(b.grant(&subject(id), Duration::from_secs(60)).await.is_err(), "{id:?}");
    }
    let foreign = SubjectRef { backend: "other".into(), kind: KIND_SESSION.into(), id: "s1".into() };
    assert!(b.deny(&foreign).await.is_err());
    assert_eq!(b.runner.calls(), Vec::<String>::new());
}

#[tokio::test]
async fn classifies_failures() {
    let fail = |stderr: &str| CmdOutput { success: false, stdout: vec![], stderr: stderr.into() };
    let r = FakeRunner::default()
        .on(&format!("get session -o json {D} -- gone"), fail("rpc error: code = NotFound desc = session not found"))
        .on(
            &format!("get session -o json {D} -- down"),
            fail("rpc error: code = Unavailable desc = connection refused"),
        )
        .on(&format!("get session -o json {D} -- denied"), fail("rpc error: code = PermissionDenied desc = nope"));
    let b = backend(r);
    assert!(matches!(b.verify(&subject("gone")).await, Err(BackendError::NotFound)));
    let e = b.verify(&subject("down")).await.unwrap_err();
    assert!(e.is_retryable(), "{e}");
    let e = b.verify(&subject("denied")).await.unwrap_err();
    assert!(!e.is_retryable());
    assert!(e.to_string().contains("PermissionDenied"));
}

#[tokio::test]
async fn reads_errors_from_stdout_not_usage_text() {
    // What octeliumctl v0.51 actually prints for a missing session.
    let out = CmdOutput {
        success: false,
        stdout: b"gRPC error NotFound: core.v1.Session gone does not exist
"
        .to_vec(),
        stderr: "Usage:
  octeliumctl get session [flags]

Flags:
  -o, --out string  Output format
"
        .into(),
    };
    let unavailable = CmdOutput {
        success: false,
        stdout: b"gRPC error Unavailable: connection error
"
        .to_vec(),
        stderr: "Usage:
  octeliumctl get session [flags]
"
        .into(),
    };
    let r = FakeRunner::default()
        .on(&format!("get session -o json {D} -- gone"), out)
        .on(&format!("get session -o json {D} -- down"), unavailable);
    let b = backend(r);
    assert!(matches!(b.verify(&subject("gone")).await, Err(BackendError::NotFound)));
    let e = b.verify(&subject("down")).await.unwrap_err();
    assert!(e.is_retryable());
    assert!(!e.to_string().contains("Usage"), "{e}");
}

#[test]
fn config_parses_with_defaults_and_rejects_bad_domain() {
    let c: OcteliumConfig = toml::from_str("domain = \"oct.example.com\"").unwrap();
    assert_eq!(c.octeliumctl, PathBuf::from("octeliumctl"));
    assert_eq!(c.command_timeout, Duration::from_secs(30));
    let c = OcteliumConfig { domain: "--evil".into(), ..c };
    assert!(OcteliumBackend::with_runner("oct".into(), c, FakeRunner::default()).is_err());
}
