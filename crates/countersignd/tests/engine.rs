//! End-to-end engine and dispatcher behaviour against an in-memory store and
//! fake backend/channels.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use countersign_core::{
    AccessBackend, ActionIntent, Assurance, BackendCaps, BackendError, BackendName, Channel, ChannelCaps, ChannelError,
    ChannelName, GrantHandle, MessageRef, Notification, PendingSubject, RequestFilter, RequestState, Requester, Store,
    SubjectFacts, SubjectRef, TransitionError, Verdict,
};
use countersign_store_sqlite::SqliteStore;
use countersignd::Daemon;
use countersignd::config::Config;
use countersignd::engine::EngineError;
use jiff::Timestamp;

fn t(secs: i64) -> Timestamp {
    Timestamp::from_second(1_800_000_000 + secs).unwrap()
}

// ---------------------------------------------------------------- backend

#[derive(Debug, Clone, PartialEq, Eq)]
enum SessionState {
    Pending,
    Active { ttl: Duration },
    Rejected,
}

#[derive(Debug, Default)]
struct FakeBackend {
    sessions: Mutex<BTreeMap<String, (String, SessionState)>>,
    groups: Mutex<BTreeMap<String, BTreeSet<String>>>,
    /// Number of upcoming grant calls that fail with a retryable error.
    flaky_grants: Mutex<u32>,
    native_expiry: bool,
    calls: Mutex<Vec<String>>,
}

impl FakeBackend {
    fn new() -> Self {
        Self { native_expiry: true, ..Self::default() }
    }
    fn add(&self, session: &str, user: &str) {
        self.sessions.lock().unwrap().insert(session.into(), (user.into(), SessionState::Pending));
    }
    fn set_groups(&self, user: &str, groups: &[&str]) {
        self.groups.lock().unwrap().insert(user.into(), groups.iter().map(|g| (*g).to_owned()).collect());
    }
    fn state(&self, session: &str) -> Option<SessionState> {
        self.sessions.lock().unwrap().get(session).map(|s| s.1.clone())
    }
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
    fn facts(&self, user: &str) -> SubjectFacts {
        SubjectFacts {
            requester: Requester {
                id: user.into(),
                display_name: None,
                groups: self.groups.lock().unwrap().get(user).cloned().unwrap_or_default(),
                identities: [format!("test:user:{user}")].into(),
            },
            target: None,
            requested_ttl: None,
            reason: None,
            attributes: BTreeMap::new(),
        }
    }
}

fn subject(id: &str) -> SubjectRef {
    SubjectRef { backend: "fake".into(), kind: "session".into(), id: id.into() }
}

#[async_trait]
impl AccessBackend for FakeBackend {
    fn name(&self) -> &BackendName {
        static NAME: std::sync::OnceLock<BackendName> = std::sync::OnceLock::new();
        NAME.get_or_init(|| "fake".into())
    }
    fn capabilities(&self) -> BackendCaps {
        BackendCaps { discover: true, revoke: true, native_expiry: self.native_expiry }
    }
    async fn discover_pending(&self) -> Result<Vec<PendingSubject>, BackendError> {
        let sessions = self.sessions.lock().unwrap().clone();
        Ok(sessions
            .into_iter()
            .filter(|(_, (_, s))| *s == SessionState::Pending)
            .map(|(id, (user, _))| PendingSubject {
                subject: subject(&id),
                facts: self.facts(&user),
                observed_at: t(0),
            })
            .collect())
    }
    async fn verify(&self, s: &SubjectRef) -> Result<SubjectFacts, BackendError> {
        let user = self.sessions.lock().unwrap().get(&s.id).map(|x| x.0.clone()).ok_or(BackendError::NotFound)?;
        Ok(self.facts(&user))
    }
    async fn grant(&self, s: &SubjectRef, ttl: Duration) -> Result<GrantHandle, BackendError> {
        self.calls.lock().unwrap().push(format!("grant {} {}s", s.id, ttl.as_secs()));
        {
            let mut flaky = self.flaky_grants.lock().unwrap();
            if *flaky > 0 {
                *flaky -= 1;
                return Err(BackendError::Unavailable("try later".into()));
            }
        }
        let mut sessions = self.sessions.lock().unwrap();
        let entry = sessions.get_mut(&s.id).ok_or(BackendError::NotFound)?;
        if entry.1 != SessionState::Pending {
            return Err(BackendError::Conflict("not pending".into()));
        }
        entry.1 = SessionState::Active { ttl };
        Ok(GrantHandle { subject: s.clone(), backend_ref: None, expires_at: None })
    }
    async fn deny(&self, s: &SubjectRef) -> Result<(), BackendError> {
        self.calls.lock().unwrap().push(format!("deny {}", s.id));
        let mut sessions = self.sessions.lock().unwrap();
        let entry = sessions.get_mut(&s.id).ok_or(BackendError::NotFound)?;
        if entry.1 != SessionState::Pending {
            return Err(BackendError::Conflict("not pending".into()));
        }
        entry.1 = SessionState::Rejected;
        Ok(())
    }
    async fn revoke(&self, g: &GrantHandle) -> Result<(), BackendError> {
        self.calls.lock().unwrap().push(format!("revoke {}", g.subject.id));
        self.sessions.lock().unwrap().remove(&g.subject.id);
        Ok(())
    }
}

// ---------------------------------------------------------------- channel

#[derive(Debug)]
struct RecordingChannel {
    name: ChannelName,
    can_update: bool,
    /// Number of upcoming calls that fail with a retryable error.
    flaky: Mutex<u32>,
    log: Mutex<Vec<String>>,
}

impl RecordingChannel {
    fn new(name: &str, can_update: bool) -> Self {
        Self { name: name.into(), can_update, flaky: Mutex::new(0), log: Mutex::default() }
    }
    fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
    fn maybe_fail(&self) -> Result<(), ChannelError> {
        let mut f = self.flaky.lock().unwrap();
        if *f > 0 {
            *f -= 1;
            return Err(ChannelError::Unavailable("503".into()));
        }
        Ok(())
    }
}

#[async_trait]
impl Channel for RecordingChannel {
    fn name(&self) -> &ChannelName {
        &self.name
    }
    fn capabilities(&self) -> ChannelCaps {
        ChannelCaps { update: self.can_update, interactive: false, max_assurance: None }
    }
    async fn notify(&self, n: Notification<'_>) -> Result<Option<MessageRef>, ChannelError> {
        self.maybe_fail()?;
        self.log.lock().unwrap().push(format!("notify {} {}", n.event.kind(), n.request.state.name()));
        Ok(self.can_update.then(|| MessageRef { channel: self.name.clone(), id: format!("msg-{}", n.request.id) }))
    }
    async fn update(&self, m: &MessageRef, n: Notification<'_>) -> Result<(), ChannelError> {
        self.maybe_fail()?;
        assert_eq!(m.id, format!("msg-{}", n.request.id));
        self.log.lock().unwrap().push(format!("update {} {}", n.event.kind(), n.request.state.name()));
        Ok(())
    }
}

// ---------------------------------------------------------------- harness

const CONFIG: &str = r#"
    [server]
    public_url = "https://cs.example.test/"

    [[approver]]
    id = "bob"
    groups = ["ops"]

    [[approver]]
    id = "carol"
    groups = ["ops"]

    [[approver]]
    id = "agent-owner"
    groups = ["ops"]
    identities = ["test:user:agent"]

    [[policy]]
    name = "pair"
    match = { requester_group = "needs-two" }
    approvers = ["group:ops"]
    quorum = 2
    max_ttl = "1h"

    [[policy]]
    name = "agents"
    match = { requester_group = "agents" }
    approvers = ["group:ops"]
    max_ttl = "30m"
    pending_timeout = "5m"
    min_assurance = "web"
"#;

struct Harness {
    daemon: Daemon,
    backend: Arc<FakeBackend>,
    store: Arc<dyn Store>,
}

async fn harness_with(extra: &str, backend: FakeBackend, channels: Vec<Arc<dyn Channel>>) -> Harness {
    let config = Config::from_toml(&format!("{CONFIG}\n{extra}")).unwrap();
    let store: Arc<dyn Store> = Arc::new(SqliteStore::in_memory().await.unwrap());
    let backend = Arc::new(backend);
    backend.set_groups("agent", &["agents"]);
    backend.set_groups("pairuser", &["needs-two"]);
    let daemon =
        Daemon::with_parts(&config, Arc::clone(&store), vec![Arc::clone(&backend) as Arc<dyn AccessBackend>], channels)
            .unwrap();
    Harness { daemon, backend, store }
}

async fn harness() -> Harness {
    harness_with("", FakeBackend::new(), vec![]).await
}

impl Harness {
    async fn only_request(&self) -> countersign_core::Request {
        let all = self.store.list_requests(&RequestFilter::default()).await.unwrap();
        assert_eq!(all.len(), 1, "{all:#?}");
        all.into_iter().next().unwrap()
    }
    async fn decide(
        &self,
        id: countersign_core::RequestId,
        who: &str,
        v: Verdict,
        now: Timestamp,
    ) -> Result<countersign_core::Request, EngineError> {
        self.daemon.engine.decide(intent(id, who, v, Assurance::FreshAuth, "web"), now).await
    }
}

fn intent(
    id: countersign_core::RequestId,
    who: &str,
    verdict: Verdict,
    assurance: Assurance,
    via: &str,
) -> ActionIntent {
    ActionIntent { request_id: id, verdict, approver: who.into(), assurance, via: via.into(), comment: None }
}

// ---------------------------------------------------------------- tests

#[tokio::test]
async fn approve_flow_grants_with_policy_ttl() {
    let h = harness().await;
    h.backend.add("s1", "agent");
    h.daemon.engine.tick(t(0)).await;
    h.daemon.engine.tick(t(1)).await; // idempotent
    let r = h.only_request().await;
    assert_eq!(r.requirements.policy.as_str(), "agents");

    let r = h.decide(r.id, "bob", Verdict::Approve, t(10)).await.unwrap();
    assert_eq!(r.state, RequestState::Active { until: t(10 + 1800) });
    assert_eq!(h.backend.state("s1"), Some(SessionState::Active { ttl: Duration::from_secs(1800) }));

    // The grant ends on its own (native expiry): no revoke call.
    h.daemon.engine.tick(t(10 + 1800)).await;
    assert_eq!(h.only_request().await.state, RequestState::Ended);
    assert!(!h.backend.calls().iter().any(|c| c.starts_with("revoke")));
}

#[tokio::test]
async fn deny_rejects_at_backend_and_is_not_reopened() {
    let h = harness().await;
    h.backend.add("s1", "agent");
    h.daemon.engine.tick(t(0)).await;
    let r = h.only_request().await;
    let r = h.decide(r.id, "bob", Verdict::Deny, t(1)).await.unwrap();
    assert_eq!(r.state, RequestState::Denied);
    assert_eq!(h.backend.state("s1"), Some(SessionState::Rejected));

    // Even if the backend still showed it as pending, no new request opens.
    h.backend.sessions.lock().unwrap().get_mut("s1").unwrap().1 = SessionState::Pending;
    h.daemon.engine.tick(t(2)).await;
    assert_eq!(h.only_request().await.id, r.id);
    assert_eq!(h.backend.state("s1"), Some(SessionState::Rejected), "rejected again");
}

#[tokio::test]
async fn pending_timeout_expires_and_rejects() {
    let h = harness().await;
    h.backend.add("s1", "agent");
    h.daemon.engine.tick(t(0)).await;
    h.daemon.engine.tick(t(299)).await;
    assert!(h.only_request().await.state.is_pending());
    h.daemon.engine.tick(t(300)).await;
    assert_eq!(h.only_request().await.state, RequestState::Expired);
    assert_eq!(h.backend.state("s1"), Some(SessionState::Rejected));
}

#[tokio::test]
async fn vanished_subject_is_withdrawn() {
    let h = harness().await;
    h.backend.add("s1", "agent");
    h.daemon.engine.tick(t(0)).await;
    h.backend.sessions.lock().unwrap().clear();
    h.daemon.engine.tick(t(1)).await;
    assert_eq!(h.only_request().await.state, RequestState::Withdrawn);
}

#[tokio::test]
async fn unmatched_subjects_are_ignored_or_denied() {
    let h = harness().await;
    h.backend.add("s1", "stranger");
    h.daemon.engine.tick(t(0)).await;
    assert_eq!(h.store.list_requests(&RequestFilter::default()).await.unwrap(), []);
    assert_eq!(h.backend.state("s1"), Some(SessionState::Pending));

    let h = harness_with("", FakeBackend::new(), vec![]).await;
    let mut rules = (*h.daemon.engine.rules()).clone();
    rules.unmatched = countersignd::config::Unmatched::Deny;
    h.daemon.engine.set_rules(rules);
    h.backend.add("s1", "stranger");
    h.daemon.engine.tick(t(0)).await;
    assert_eq!(h.backend.state("s1"), Some(SessionState::Rejected));
}

#[tokio::test]
async fn quorum_needs_two_distinct_approvers() {
    let h = harness().await;
    h.backend.add("s1", "pairuser");
    h.daemon.engine.tick(t(0)).await;
    let id = h.only_request().await.id;
    assert!(h.decide(id, "bob", Verdict::Approve, t(1)).await.unwrap().state.is_pending());
    assert!(matches!(
        h.decide(id, "bob", Verdict::Approve, t(2)).await,
        Err(EngineError::Transition(TransitionError::AlreadyDecided))
    ));
    assert!(matches!(h.decide(id, "carol", Verdict::Approve, t(3)).await.unwrap().state, RequestState::Active { .. }));
}

#[tokio::test]
async fn refuses_self_unknown_and_weak_approvals() {
    let h = harness().await;
    h.backend.add("s1", "agent");
    h.daemon.engine.tick(t(0)).await;
    let id = h.only_request().await.id;
    assert!(matches!(
        h.decide(id, "agent-owner", Verdict::Approve, t(1)).await,
        Err(EngineError::Transition(TransitionError::SelfApproval))
    ));
    assert!(matches!(h.decide(id, "mallory", Verdict::Approve, t(1)).await, Err(EngineError::UnknownApprover(_))));
    let weak = h.daemon.engine.decide(intent(id, "bob", Verdict::Approve, Assurance::Linked, "chat"), t(1)).await;
    assert!(matches!(weak, Err(EngineError::Transition(TransitionError::InsufficientAssurance { .. }))));
    assert_eq!(h.backend.state("s1"), Some(SessionState::Pending));
}

#[tokio::test]
async fn transient_grant_failure_is_retried_on_tick() {
    let backend = FakeBackend::new();
    *backend.flaky_grants.lock().unwrap() = 1;
    let h = harness_with("", backend, vec![]).await;
    h.backend.add("s1", "agent");
    h.daemon.engine.tick(t(0)).await;
    let id = h.only_request().await.id;
    assert_eq!(h.decide(id, "bob", Verdict::Approve, t(1)).await.unwrap().state, RequestState::Approved);
    h.daemon.engine.tick(t(5)).await;
    assert!(matches!(h.only_request().await.state, RequestState::Active { .. }));
    assert_eq!(h.backend.calls().iter().filter(|c| c.starts_with("grant")).count(), 2);
}

#[tokio::test]
async fn changed_requester_fails_the_grant() {
    let h = harness().await;
    h.backend.add("s1", "agent");
    h.daemon.engine.tick(t(0)).await;
    let id = h.only_request().await.id;
    h.backend.sessions.lock().unwrap().get_mut("s1").unwrap().0 = "someone-else".into();
    let r = h.decide(id, "bob", Verdict::Approve, t(1)).await.unwrap();
    assert!(matches!(r.state, RequestState::Failed { ref error } if error.contains("requester changed")));
    assert!(!h.backend.calls().iter().any(|c| c.starts_with("grant")));
}

#[tokio::test]
async fn revoke_and_manual_expiry() {
    let mut backend = FakeBackend::new();
    backend.native_expiry = false;
    let h = harness_with("", backend, vec![]).await;
    h.backend.add("s1", "agent");
    h.backend.add("s2", "agent");
    h.daemon.engine.tick(t(0)).await;
    let all = h.store.list_requests(&RequestFilter::default()).await.unwrap();
    for r in &all {
        h.decide(r.id, "bob", Verdict::Approve, t(1)).await.unwrap();
    }

    let first = all.iter().find(|r| r.subject.id == "s1").unwrap().id;
    let r = h.daemon.engine.revoke(first, &"carol".into(), t(2)).await.unwrap();
    assert_eq!(r.state, RequestState::Revoked);

    // Without native expiry the engine revokes when time is up.
    h.daemon.engine.tick(t(1 + 1800)).await;
    let calls = h.backend.calls();
    assert!(calls.contains(&"revoke s1".to_owned()));
    assert!(calls.contains(&"revoke s2".to_owned()));
}

#[tokio::test]
async fn dispatcher_posts_then_updates_and_retries() {
    let chat = Arc::new(RecordingChannel::new("chat", true));
    let push = Arc::new(RecordingChannel::new("push", false));
    *chat.flaky.lock().unwrap() = 1;
    let h = harness_with(
        "",
        FakeBackend::new(),
        vec![Arc::clone(&chat) as Arc<dyn Channel>, Arc::clone(&push) as Arc<dyn Channel>],
    )
    .await;
    h.backend.add("s1", "agent");
    h.daemon.engine.tick(t(0)).await;

    // First attempt: chat fails (retryable), push succeeds.
    assert_eq!(h.daemon.dispatcher.run_once(t(0)).await.unwrap(), 1);
    assert_eq!(chat.log(), Vec::<String>::new());
    assert_eq!(push.log(), ["notify requested pending"]);

    // Not due yet; then the retry reaches chat only — push already handled it.
    assert_eq!(h.daemon.dispatcher.run_once(t(1)).await.unwrap(), 0);
    h.daemon.dispatcher.run_once(t(5)).await.unwrap();
    assert_eq!(chat.log(), ["notify requested pending"]);
    assert_eq!(push.log(), ["notify requested pending"], "no duplicate on another channel's retry");

    let id = h.only_request().await.id;
    h.decide(id, "bob", Verdict::Approve, t(10)).await.unwrap();
    h.daemon.dispatcher.run_once(t(10)).await.unwrap();

    assert_eq!(
        chat.log(),
        [
            "notify requested pending",
            "update decision-recorded active",
            "update approved active",
            "update granted active",
        ]
    );
    assert_eq!(push.log().last().unwrap(), "notify granted active");
    assert!(!push.log().iter().any(|l| l.contains("decision-recorded")));

    // Retried delivery of `requested` never double-posts to chat.
    assert_eq!(chat.log().iter().filter(|l| l.starts_with("notify")).count(), 1);
}
