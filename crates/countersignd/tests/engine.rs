//! End-to-end engine and dispatcher behaviour against an in-memory store and
//! fake backend/channels.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use jiff::Timestamp;
use serde_json::json;

use countersign_core::{
    AccessBackend, ActionIntent, AnswerIntent, Asker, Assurance, BackendCaps, BackendError, BackendName, Channel,
    ChannelCaps, ChannelError, ChannelName, ClientId, Confidentiality, Exclusion, GrantHandle, Initiator, Item,
    MessageRef, Notification, PendingSubject, QuestionOutcome, RequestFilter, RequestState, Requester, Response, Store,
    SubjectFacts, SubjectRef, TransitionError, Verdict,
};
use countersign_store_sqlite::SqliteStore;
use countersignd::Daemon;
use countersignd::config::Config;
use countersignd::engine::{Ask, EngineError};

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
    initiators: Mutex<BTreeMap<String, String>>,
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
            source: None,
            sensitive: false,
            binding: None,
            action: None,
            requester: Requester {
                id: user.into(),
                display_name: None,
                groups: self.groups.lock().unwrap().get(user).cloned().unwrap_or_default(),
                ..Requester::default()
            },
            initiator: self.initiators.lock().unwrap().get(user).map(|i| Initiator {
                identity: i.clone(),
                display_name: None,
                actor: None,
            }),
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
    fn identity_scheme(&self) -> &'static str {
        "fake"
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
        self.log.lock().unwrap().push(format!("notify {} {}", n.event.kind(), n.item.state()));
        Ok(self.can_update.then(|| MessageRef { channel: self.name.clone(), id: format!("msg-{}", n.item.id()) }))
    }
    async fn update(&self, m: &MessageRef, n: Notification<'_>) -> Result<(), ChannelError> {
        self.maybe_fail()?;
        assert_eq!(m.id, format!("msg-{}", n.item.id()));
        if let Item::Question(q) = n.item {
            assert!(!q.question_confidential() || q.message.is_empty() || n.item.withheld());
        }
        self.log.lock().unwrap().push(format!("update {} {}", n.event.kind(), n.item.state()));
        Ok(())
    }
}

// ---------------------------------------------------------------- harness

const CONFIG: &str = r#"
    [server]
    public_url = "https://cs.example.test/"

    [[person]]
    id = "bob"
    identities = ["github:1001"]

    [[person]]
    id = "carol"

    [[person]]
    id = "agent-owner"

    [[person]]
    id = "dave"

    [[workload]]
    id = "agent"
    owners = ["agent-owner"]
    identities = ["fake:fake#agent"]

    [[group]]
    name = "ops"
    members = ["bob", "carol", "agent-owner"]

    [roles]
    member = ["group:ops", "person:dave"]
    admin = ["person:carol"]

    [[policy]]
    name = "pair"
    match = { backend_group = "needs-two" }
    approvers = ["group:ops"]
    quorum = 2
    max_ttl = "1h"

    [[policy]]
    name = "agents"
    match = { backend_group = "agents" }
    approvers = ["group:ops"]
    exclude = ["requester", "owners", "initiator"]
    max_ttl = "30m"
    pending_timeout = "5m"
    min_assurance = "web"

    [[policy]]
    name = "ci"
    match = { backend_group = "ci" }
    approvers = ["group:ops"]
    exclude = ["requester", "initiator"]
    require_initiator = true
    max_ttl = "10m"

    [intake]
    listen = "127.0.0.1:0"
    behind_proxy = true
    signing_key_file = "set by the test"

    [[client]]
    id = "agent-host"
    auth = { host_key = "sha256:1111111111111111111111111111111111111111111111111111111111111111" }
    scopes = ["question"]
    actor = "agent"

    [[question_policy]]
    name = "deploys"
    match = { asker = "agent-host" }
    responders = ["group:ops"]
    min_assurance = "linked"
    confidential = "allow"
    max_pending = 2
"#;

struct Harness {
    daemon: Daemon,
    backend: Arc<FakeBackend>,
    store: Arc<dyn Store>,
}

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

async fn harness_with(extra: &str, backend: FakeBackend, channels: Vec<Arc<dyn Channel>>) -> Harness {
    let mut config = Config::from_toml(&format!("{CONFIG}\n{extra}")).unwrap();
    config.intake.as_mut().unwrap().signing_key_file = signing_key_file();
    let store: Arc<dyn Store> = Arc::new(SqliteStore::in_memory().await.unwrap());
    let backend = Arc::new(backend);
    backend.set_groups("agent", &["agents"]);
    backend.set_groups("pairuser", &["needs-two"]);
    backend.set_groups("runner", &["ci"]);
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
async fn requesters_are_recognized_and_owners_excluded() {
    let h = harness().await;
    h.backend.add("s1", "agent");
    h.daemon.engine.tick(t(0)).await;
    let r = h.only_request().await;
    assert_eq!(r.facts.requester.identity, "fake:fake#agent", "set by countersign from the backend");
    assert_eq!(r.facts.requester.actor.as_ref().map(countersign_core::ActorId::as_str), Some("agent"));
    assert_eq!(r.facts.source.as_ref().map(|s| s.name().to_owned()).as_deref(), Some("fake"));
    assert!(matches!(
        h.decide(r.id, "agent-owner", Verdict::Approve, t(1)).await,
        Err(EngineError::Transition(TransitionError::Excluded(Exclusion::Owners)))
    ));
}

#[tokio::test]
async fn initiators_are_resolved_excluded_and_can_be_required() {
    let h = harness().await;
    h.backend.initiators.lock().unwrap().insert("runner".into(), "github:1001".into());
    h.backend.add("s1", "runner");
    h.daemon.engine.tick(t(0)).await;
    let r = h.only_request().await;
    assert_eq!(
        r.facts.initiator.as_ref().and_then(|i| i.actor.as_ref()).map(countersign_core::ActorId::as_str),
        Some("bob")
    );
    assert!(matches!(
        h.decide(r.id, "bob", Verdict::Approve, t(1)).await,
        Err(EngineError::Transition(TransitionError::Excluded(Exclusion::Initiator)))
    ));
    assert!(matches!(
        h.decide(r.id, "carol", Verdict::Approve, t(1)).await.unwrap().state,
        RequestState::Active { .. }
    ));

    // Without an initiator a policy that needs one fails the request.
    let h = harness().await;
    h.backend.add("s2", "runner");
    h.daemon.engine.tick(t(0)).await;
    let r = h.only_request().await;
    assert!(matches!(r.state, RequestState::Failed { ref error } if error.contains("initiator")), "{:?}", r.state);
}

#[tokio::test]
async fn suspension_stops_deciding_and_uncounts_approvals() {
    let h = harness().await;
    h.backend.add("s1", "pairuser");
    h.daemon.engine.tick(t(0)).await;
    let id = h.only_request().await.id;
    assert!(h.decide(id, "bob", Verdict::Approve, t(1)).await.unwrap().state.is_pending());

    let e = h.daemon.engine.suspend(&"bob".into(), &"dave".into(), None, t(2)).await.unwrap_err();
    assert!(matches!(e, EngineError::Forbidden(_)), "only admins suspend: {e}");
    h.daemon.engine.suspend(&"bob".into(), &"carol".into(), Some("phone lost".into()), t(2)).await.unwrap();
    assert!(matches!(
        h.decide(id, "bob", Verdict::Deny, t(3)).await,
        Err(EngineError::Forbidden(_) | EngineError::Transition(TransitionError::Inactive))
    ));
    // Bob's approval no longer counts: one more is not enough.
    assert!(h.decide(id, "agent-owner", Verdict::Approve, t(4)).await.unwrap().state.is_pending());
    assert!(matches!(h.decide(id, "carol", Verdict::Approve, t(5)).await.unwrap().state, RequestState::Active { .. }));

    assert!(h.daemon.engine.reinstate(&"bob".into(), &"carol".into(), t(6)).await.unwrap());
    let audit = h.store.admin_actions(10).await.unwrap();
    assert_eq!(audit.iter().map(|a| a.action.as_str()).collect::<Vec<_>>(), ["reinstate", "suspend"]);
}

#[tokio::test]
async fn suspending_a_workload_withdraws_its_requests() {
    let h = harness().await;
    h.backend.add("s1", "agent");
    h.daemon.engine.tick(t(0)).await;
    h.daemon.engine.suspend(&"agent".into(), &"carol".into(), None, t(1)).await.unwrap();
    let state = h.only_request().await.state;
    assert!(!state.is_pending(), "{state:?}");
}

fn ask(message: &str, schema: serde_json::Value, confidential: bool) -> Ask {
    Ask {
        asker: Asker { client: ClientId::new("agent-host"), actor: Some("agent".into()) },
        message: message.into(),
        schema,
        context: BTreeMap::from([("service".to_owned(), "api".to_owned())]),
        confidentiality: Confidentiality { question: confidential, answer_may_be: false },
    }
}

fn answer(q: countersign_core::RequestId, who: &str, response: Response, assurance: Assurance) -> AnswerIntent {
    AnswerIntent { question_id: q, responder: who.into(), response, assurance, via: "web".into() }
}

fn accept(content: &serde_json::Value, confidential: bool) -> Response {
    Response::Accept { content: content.as_object().unwrap().clone(), confidential }
}

#[tokio::test]
async fn questions_are_answered_once_by_an_eligible_responder() {
    let chat = Arc::new(RecordingChannel::new("chat", true));
    let h = harness_with("", FakeBackend::new(), vec![Arc::clone(&chat) as Arc<dyn Channel>]).await;
    let e = &h.daemon.engine;
    let schema = json!({"type": "object", "properties": {"go": {"type": "boolean"}}, "required": ["go"]});
    let q = e.ask(ask("Release v2?", schema.clone(), false), t(0)).await.unwrap();
    assert_eq!(q.requirements.policy.as_str(), "deploys");

    // The owner of the asking workload is one of the responders, but the
    // question is asked for the workload itself, not for them.
    let bad = e.answer(answer(q.id, "dave", accept(&json!({"go": true}), false), Assurance::FreshAuth), t(1)).await;
    assert!(bad.is_err(), "dave is not a responder");
    let bad = e.answer(answer(q.id, "bob", accept(&json!({"go": "yes"}), false), Assurance::FreshAuth), t(1)).await;
    assert!(matches!(bad, Err(EngineError::Answer(_))), "{bad:?}");
    let q2 = e.answer(answer(q.id, "bob", accept(&json!({"go": true}), false), Assurance::Linked), t(2)).await.unwrap();
    assert_eq!(q2.state(), "answered");
    let again = e.answer(answer(q.id, "carol", Response::Decline { note: None }, Assurance::Linked), t(3)).await;
    assert!(again.is_err(), "answered once");

    let read = e.read_question(q.id, &ClientId::new("agent-host"), t(4)).await.unwrap();
    assert!(
        matches!(read.outcome, Some(QuestionOutcome::Accepted { content: Some(ref c), .. }) if c["go"] == json!(true))
    );
    assert!(e.read_question(q.id, &ClientId::new("other"), t(4)).await.is_err(), "only the asker reads it");

    h.daemon.dispatcher.run_once(t(5)).await.unwrap();
    // Delivered after the answer: both carry the current snapshot.
    assert_eq!(chat.log(), ["notify requested answered", "update answered answered"]);
}

#[tokio::test]
async fn questions_are_limited_per_asker_and_need_a_policy() {
    let h = harness().await;
    let e = &h.daemon.engine;
    let schema = json!({"type": "object", "properties": {"ok": {"type": "boolean"}}});
    e.ask(ask("one", schema.clone(), false), t(0)).await.unwrap();
    e.ask(ask("two", schema.clone(), false), t(0)).await.unwrap();
    assert!(matches!(e.ask(ask("three", schema.clone(), false), t(0)).await, Err(EngineError::Refused(_))));

    let mut stranger = ask("hi", schema.clone(), false);
    stranger.asker.client = ClientId::new("unknown-host");
    assert!(matches!(e.ask(stranger, t(0)).await, Err(EngineError::Refused(_))));
    let bad_schema = json!({"type": "object", "properties": {"x": {"type": "array"}}});
    assert!(matches!(e.ask(ask("bad", bad_schema, false), t(0)).await, Err(EngineError::Invalid(_))));

    // A suspended workload cannot ask.
    e.suspend(&"agent".into(), &"carol".into(), None, t(1)).await.unwrap();
    assert!(matches!(e.ask(ask("four", schema, false), t(2)).await, Err(EngineError::Forbidden(_))));
}

#[tokio::test]
async fn confidential_content_is_removed_once_read_and_unanswered_questions_expire() {
    let h = harness().await;
    let e = &h.daemon.engine;
    let schema = json!({"type": "object", "properties": {"code": {"type": "string"}}, "required": ["code"]});
    let q = e.ask(ask("Which recovery code?", schema.clone(), true), t(0)).await.unwrap();
    // Confidential questions need the stronger assurance to answer.
    let weak = e.answer(answer(q.id, "bob", accept(&json!({"code": "K-1"}), true), Assurance::Linked), t(1)).await;
    assert!(weak.is_err());
    let weak = e.answer(answer(q.id, "bob", accept(&json!({"code": "K-1"}), false), Assurance::FreshAuth), t(1)).await;
    assert!(weak.is_err(), "the answer to a confidential question stays confidential");
    e.answer(answer(q.id, "bob", accept(&json!({"code": "K-1"}), true), Assurance::FreshAuth), t(2)).await.unwrap();

    let stored = h.store.get_question(q.id).await.unwrap().unwrap();
    assert!(stored.message.is_empty() && stored.content_removed, "the text goes once the question is closed");
    let read = e.read_question(q.id, &ClientId::new("agent-host"), t(3)).await.unwrap();
    assert!(matches!(read.outcome, Some(QuestionOutcome::Accepted { content: Some(ref c), .. }) if c["code"] == "K-1"));
    let stored = h.store.get_question(q.id).await.unwrap().unwrap();
    assert!(matches!(stored.outcome, Some(QuestionOutcome::Accepted { content: None, .. })), "{stored:?}");
    assert!(!stored.holds_content());
    let again = e.read_question(q.id, &ClientId::new("agent-host"), t(4)).await.unwrap();
    assert!(matches!(again.outcome, Some(QuestionOutcome::Accepted { content: None, .. })), "handed over once");

    let q = e.ask(ask("Still there?", schema, false), t(10)).await.unwrap();
    e.tick(t(10 + 30 * 60)).await;
    assert_eq!(h.store.get_question(q.id).await.unwrap().unwrap().state(), "expired");
}

#[tokio::test]
async fn refuses_unknown_and_weak_approvals() {
    let h = harness().await;
    h.backend.add("s1", "agent");
    h.daemon.engine.tick(t(0)).await;
    let id = h.only_request().await.id;
    assert!(matches!(h.decide(id, "mallory", Verdict::Approve, t(1)).await, Err(EngineError::Forbidden(_))));
    assert!(matches!(
        h.decide(id, "dave", Verdict::Approve, t(1)).await,
        Err(EngineError::Transition(TransitionError::NotEligible))
    ));
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
