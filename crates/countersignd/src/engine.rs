//! Applies the core state machine against backends and the store.
//!
//! The engine is driven by these calls:
//! - [`Engine::tick`], run periodically, discovers pending subjects, sweeps
//!   timeouts, retries grants that could not be applied yet, enforces
//!   suspensions, and removes confidential content that is no longer needed.
//! - [`Engine::decide`] / [`Engine::revoke`], run when a person acts on an
//!   approval; [`Engine::answer`] when one answers a question.
//! - [`Engine::submit`], run when a client pushes a subject (e.g. a `sudo`
//!   invocation waiting for approval); [`Engine::ask`] when it asks a question.
//! - [`Engine::suspend`] and friends, run by admins.
//!
//! Who is active, in which groups and with which roles is read from the
//! configuration and the store at the moment of each decision, so a
//! suspension or a group change takes effect immediately.
//!
//! Every method takes `now` so tests control time.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use jiff::Timestamp;
use serde_json::Value;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use countersign_core::actor::is_identity;
use countersign_core::{
    AccessBackend, ActionIntent, ActorId, AdminAction, AnswerError, AnswerIntent, Asker, BackendError, BackendName,
    ClientId, ConfidentialMode, Confidentiality, Directory, DomainEvent, FormSchema, GrantMode, PendingSubject,
    PolicySet, Purpose, Question, QuestionPolicySet, Request, RequestFilter, RequestId, RequestState, Role, Roster,
    Source, Standing, Store, StoreError, Suspension, TransitionError,
};

use crate::config::{ClientConfig, Unmatched};

/// How many times to retry a change that lost an optimistic-concurrency race.
const CONFLICT_RETRIES: usize = 3;

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("request {0} not found")]
    UnknownRequest(RequestId),
    #[error("question {0} not found")]
    UnknownQuestion(RequestId),
    #[error("backend {0} is not configured")]
    UnknownBackend(BackendName),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    Refused(String),
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Transition(#[from] TransitionError),
    #[error(transparent)]
    Answer(#[from] AnswerError),
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("backend: {0}")]
    Backend(#[from] BackendError),
    #[error("the request kept changing concurrently; try again")]
    Busy,
}

/// The parts of the configuration that can be swapped at runtime.
#[derive(Debug, Clone, Default)]
pub struct Rules {
    pub directory: Directory,
    pub policies: PolicySet,
    pub question_policies: QuestionPolicySet,
    pub clients: BTreeMap<ClientId, ClientConfig>,
    pub unmatched: Unmatched,
    /// How long identity-provider groups from a sign-in count.
    pub idp_max_age: Duration,
    /// How long closed requests/questions are kept before automatic cleanup.
    pub retention: Option<Duration>,
}

impl Rules {
    pub fn roster<'a>(&'a self, standing: &'a Standing, now: Timestamp) -> Roster<'a> {
        Roster { directory: &self.directory, standing, now, idp_max_age: self.idp_max_age }
    }
}

/// Receives high-visibility administrative actions to announce to channels.
pub type AdminNotifier =
    Arc<dyn Fn(AdminAction) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync>;

pub struct Engine {
    store: Arc<dyn Store>,
    backends: BTreeMap<BackendName, Arc<dyn AccessBackend>>,
    rules: RwLock<Arc<Rules>>,
    /// Unmatched subjects already logged, to avoid repeating the warning.
    unmatched_seen: std::sync::Mutex<BTreeSet<String>>,
    /// Bumped whenever a request or question is stored, so waiters can re-check.
    changes: watch::Sender<u64>,
    /// Optional hook to announce suspensions and bulk revokes to all channels.
    admin_notifier: RwLock<Option<AdminNotifier>>,
}

/// Outcome of [`Engine::submit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Submitted {
    /// A new request was opened. It may already have failed (no eligible
    /// approvers, no initiator where one is required).
    Opened(Request),
    /// An active window approved the subject; this is the window request,
    /// with the use recorded.
    Covered(Request),
    /// No policy matches; nothing was stored.
    Unmatched,
    /// The requester is a suspended actor (or a workload without an active
    /// owner); nothing was stored.
    Inactive,
}

/// A question as a client asks it.
#[derive(Debug, Clone, PartialEq)]
pub struct Ask {
    pub asker: Asker,
    pub message: String,
    pub schema: Value,
    pub context: BTreeMap<String, String>,
    pub confidentiality: Confidentiality,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine").field("backends", &self.backends.keys().collect::<Vec<_>>()).finish_non_exhaustive()
    }
}

/// Counts from one [`Engine::sync_backend`] run.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SyncReport {
    pub opened: usize,
    pub withdrawn: usize,
    pub denied_unmatched: usize,
    pub denied_closed: usize,
}

/// Whether a submission or question text fits, with hidden characters
/// written out.
fn clean_text(s: &str, max: usize, what: &str) -> Result<String, EngineError> {
    if s.chars().count() > max {
        return Err(EngineError::Invalid(format!("{what} is longer than {max} characters")));
    }
    Ok(countersign_core::text::escape(s))
}

impl Engine {
    pub fn new(store: Arc<dyn Store>, backends: Vec<Arc<dyn AccessBackend>>, rules: Rules) -> Self {
        Self {
            store,
            backends: backends.into_iter().map(|b| (b.name().clone(), b)).collect(),
            rules: RwLock::new(Arc::new(rules)),
            unmatched_seen: std::sync::Mutex::default(),
            changes: watch::Sender::new(0),
            admin_notifier: RwLock::new(None),
        }
    }

    /// Install a callback invoked on high-visibility admin actions (suspension,
    /// bulk revoke) so channels can be notified.
    pub fn set_admin_notifier(&self, notifier: AdminNotifier) {
        *self.admin_notifier.write().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(notifier);
    }

    /// A receiver that changes whenever any request or question is stored.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    fn changed(&self) {
        self.changes.send_modify(|v| *v = v.wrapping_add(1));
    }

    pub fn store(&self) -> &Arc<dyn Store> {
        &self.store
    }

    pub fn rules(&self) -> Arc<Rules> {
        Arc::clone(&self.rules.read().unwrap_or_else(std::sync::PoisonError::into_inner))
    }

    /// Replace the directory, policies and clients. Requests already open
    /// keep the requirements they were opened with; who is eligible is
    /// checked against the new directory from now on.
    pub fn set_rules(&self, rules: Rules) {
        *self.rules.write().unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(rules);
    }

    /// The rules and the current standing (suspensions, sign-in groups).
    pub async fn standing(&self) -> Result<(Arc<Rules>, Standing), EngineError> {
        Ok((self.rules(), self.store.standing().await?))
    }

    fn backend(&self, name: &BackendName) -> Result<&Arc<dyn AccessBackend>, EngineError> {
        self.backends.get(name).ok_or_else(|| EngineError::UnknownBackend(name.clone()))
    }

    /// One periodic pass: discover, then advance every open request and
    /// question.
    pub async fn tick(&self, now: Timestamp) {
        for (name, backend) in &self.backends {
            if !backend.capabilities().discover {
                continue;
            }
            match self.sync_backend(name, now).await {
                Ok(r) if r != SyncReport::default() => debug!(backend = %name, ?r, "synced"),
                Ok(_) => {}
                Err(e) => warn!(backend = %name, error = %e, "sync failed"),
            }
        }
        if let Err(e) = self.enforce_standing(now).await {
            warn!(error = %e, "enforcing suspensions failed");
        }
        if let Err(e) = self.advance_open(now).await {
            warn!(error = %e, "advancing open requests failed");
        }
        if let Err(e) = self.advance_questions(now).await {
            warn!(error = %e, "advancing questions failed");
        }
        if let Some(retention) = self.rules().retention
            && let Ok(dur) = jiff::SignedDuration::try_from(retention)
            && let Ok(cutoff) = now.checked_sub(dur)
        {
            match self.store.purge_before(cutoff).await {
                Ok(0) => {}
                Ok(n) => info!(purged = n, "purged expired records past retention"),
                Err(e) => warn!(error = %e, "purging expired records failed"),
            }
        }
    }

    /// Fill in what countersign, not the source, decides about a subject:
    /// the source, the requester's identity in the source's namespace, and
    /// which actors the requester and initiator are.
    fn normalize(&self, rules: &Rules, p: &mut PendingSubject) -> Result<(), EngineError> {
        let facts = &mut p.facts;
        // Intake sets a client source and the identity itself; anything a
        // backend reports is put in that backend's namespace.
        if !matches!(facts.source, Some(Source::Client(_))) {
            let backend = self.backend(&p.subject.backend)?;
            facts.source = Some(Source::Backend(p.subject.backend.clone()));
            facts.requester.identity =
                format!("{}:{}#{}", backend.identity_scheme(), p.subject.backend, facts.requester.id);
        }
        facts.requester.actor =
            rules.directory.by_identity(&facts.requester.identity, Purpose::Recognition).map(|a| a.id.clone());
        if facts.initiator.as_ref().is_some_and(|i| !is_identity(&i.identity)) {
            facts.initiator = None;
        }
        if let Some(i) = &mut facts.initiator {
            i.actor = rules
                .directory
                .by_identity(&i.identity, Purpose::Recognition)
                .filter(|a| a.is_person())
                .map(|a| a.id.clone());
        }
        Ok(())
    }

    /// Reconcile one backend's pending subjects with stored requests.
    pub async fn sync_backend(&self, name: &BackendName, now: Timestamp) -> Result<SyncReport, EngineError> {
        let backend = self.backend(name)?;
        let pending = backend.discover_pending().await?;
        let mut report = SyncReport::default();
        let mut seen = BTreeSet::new();

        for p in pending {
            seen.insert(p.subject.clone());
            match self.store.find_latest_by_subject(&p.subject).await? {
                Some(r) if !r.state.is_terminal() => {}
                Some(r) => {
                    // Decided (or timed out) earlier but still pending at the
                    // backend, e.g. because the rejection failed: reject again.
                    debug!(request = %r.id, subject = %p.subject.id, state = r.state.name(), "re-rejecting closed subject");
                    if self.deny_at_backend(backend.as_ref(), &p).await {
                        report.denied_closed += 1;
                    }
                }
                None => {
                    let subject = p.subject.clone();
                    let requester = p.facts.requester.id.clone();
                    match self.admit(p, now).await {
                        Ok(Submitted::Opened(_)) => report.opened += 1,
                        // Covered by an open window, or opened concurrently.
                        Ok(Submitted::Covered(_)) | Err(EngineError::Store(StoreError::Duplicate)) => {}
                        Ok(outcome @ (Submitted::Unmatched | Submitted::Inactive)) => {
                            let why = if outcome == Submitted::Unmatched {
                                "no policy matches"
                            } else {
                                "the requester is suspended"
                            };
                            match self.rules().unmatched {
                                Unmatched::Deny => {
                                    info!(subject = %subject.id, %requester, "{why}; rejecting");
                                    if self.deny_ref(backend.as_ref(), &subject).await {
                                        report.denied_unmatched += 1;
                                    }
                                }
                                Unmatched::Ignore => {
                                    let key = format!("{}/{}", subject.backend, subject.id);
                                    if self
                                        .unmatched_seen
                                        .lock()
                                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                                        .insert(key)
                                    {
                                        warn!(subject = %subject.id, %requester, "{why}; ignoring");
                                    }
                                }
                            }
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
        }

        // Pending requests whose subject vanished were withdrawn at the backend.
        let open = self.store.list_requests(&RequestFilter { open_only: true, limit: None }).await?;
        for mut r in open {
            if r.subject.backend != *name || !r.state.is_pending() || seen.contains(&r.subject) {
                continue;
            }
            let v = r.version;
            let events = r.withdraw(now)?;
            if self.save(&r, v, &events).await? {
                info!(request = %r.id, "subject no longer pending; withdrawn");
                report.withdrawn += 1;
            }
        }
        Ok(report)
    }

    /// Take a subject pushed by its source: approve it under an active
    /// window of the same policy, or open a request for it.
    pub async fn submit(&self, p: PendingSubject, now: Timestamp) -> Result<Submitted, EngineError> {
        self.admit(p, now).await
    }

    async fn admit(&self, mut p: PendingSubject, now: Timestamp) -> Result<Submitted, EngineError> {
        self.backend(&p.subject.backend)?;
        let (rules, standing) = self.standing().await?;
        let roster = rules.roster(&standing, now);
        self.normalize(&rules, &mut p)?;

        let groups = match &p.facts.requester.actor {
            Some(a) if !roster.is_active(a) => {
                info!(subject = %p.subject.id, requester = %a, "the requester is suspended; refusing");
                return Ok(Submitted::Inactive);
            }
            Some(a) => roster.groups(a),
            None => BTreeSet::new(),
        };
        let Some(policy) = rules.policies.find(&p, &groups) else {
            info!(subject = %p.subject.id, requester = %p.facts.requester.identity, "no policy matches");
            return Ok(Submitted::Unmatched);
        };

        if policy.grant == GrantMode::Window {
            for _ in 0..CONFLICT_RETRIES {
                let open = self.store.list_requests(&RequestFilter { open_only: true, limit: None }).await?;
                let Some(mut window) =
                    open.into_iter().find(|r| r.requirements.policy == policy.name && r.window_covers(&p, now))
                else {
                    break;
                };
                let v = window.version;
                window.record_use(&p, now)?;
                if self.save(&window, v, &[]).await? {
                    info!(request = %window.id, subject = %p.subject.id, "approved under an active window");
                    return Ok(Submitted::Covered(window));
                }
            }
        }

        let reqs = policy.requirements_for(&p);
        let sensitive = policy.sensitive.resolve(p.facts.sensitive);
        let (mut request, mut events) = Request::open(p, reqs, sensitive, now);
        let no_initiator = request.requirements.require_initiator
            && request.facts.initiator.as_ref().and_then(|i| i.actor.as_ref()).is_none();
        let failure = if no_initiator {
            Some("the policy requires an initiator, and the source named nobody countersign knows")
        } else if request.potential_deciders(&roster) < usize::from(request.requirements.quorum) {
            Some("not enough eligible approvers")
        } else {
            None
        };
        if let Some(reason) = failure {
            events.extend(request.fail_pending(reason.to_owned(), now)?);
        }
        self.store.insert_request(&request, &events).await?;
        self.changed();
        if let Some(reason) = failure {
            warn!(request = %request.id, policy = %request.requirements.policy, reason, "request failed when opened");
            self.deny_subject(&request).await;
        } else {
            info!(request = %request.id, subject = %request.subject.id, policy = %request.requirements.policy, "opened request");
        }
        Ok(Submitted::Opened(request))
    }

    /// Expire, grant, and end open requests as their time comes.
    pub async fn advance_open(&self, now: Timestamp) -> Result<(), EngineError> {
        let open = self.store.list_requests(&RequestFilter { open_only: true, limit: None }).await?;
        for r in open {
            let id = r.id;
            if let Err(e) = self.advance(r, now).await {
                warn!(request = %id, error = %e, "could not advance request");
            }
        }
        Ok(())
    }

    async fn advance(&self, mut r: Request, now: Timestamp) -> Result<(), EngineError> {
        let v = r.version;
        match r.state {
            RequestState::Pending => {
                let events = r.expire_pending(now)?;
                if !events.is_empty() && self.save(&r, v, &events).await? {
                    info!(request = %r.id, "expired without a decision");
                    self.deny_subject(&r).await;
                }
            }
            RequestState::Approved => {
                self.apply_grant(r, now).await?;
            }
            RequestState::Active { .. } => {
                let backend = self.backend(&r.subject.backend)?;
                let events = r.end_if_elapsed(now)?;
                if events.is_empty() {
                    return Ok(());
                }
                if !backend.capabilities().native_expiry
                    && let Some(g) = &r.grant
                {
                    backend.revoke(g).await?;
                }
                if self.save(&r, v, &events).await? {
                    info!(request = %r.id, "grant ended");
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Withdraw or revoke what suspended requesters and removed clients
    /// still have open, and withdraw their pending questions.
    pub async fn enforce_standing(&self, now: Timestamp) -> Result<(), EngineError> {
        let (rules, standing) = self.standing().await?;
        let roster = rules.roster(&standing, now);
        let gone = |source: Option<&Source>, actor: Option<&ActorId>| {
            actor.is_some_and(|a| !roster.is_active(a))
                || matches!(source, Some(Source::Client(c)) if !rules.clients.contains_key(c))
        };

        let open = self.store.list_requests(&RequestFilter { open_only: true, limit: None }).await?;
        for r in open {
            if !gone(r.facts.source.as_ref(), r.facts.requester.actor.as_ref()) {
                continue;
            }
            let id = r.id;
            let result = if r.state.is_pending() {
                self.withdraw(id, now).await.map(drop)
            } else {
                self.revoke_unchecked(r, None, now).await.map(drop)
            };
            match result {
                Ok(()) => info!(request = %id, "requester suspended or client removed; closed"),
                Err(e) => warn!(request = %id, error = %e, "could not close a suspended requester's request"),
            }
        }

        let questions = self.store.list_questions(&RequestFilter { open_only: true, limit: None }).await?;
        for q in questions {
            let source = Source::Client(q.asker.client.clone());
            if gone(Some(&source), q.asker.actor.as_ref()) {
                let id = q.id;
                match self.withdraw_question(id, None, now).await {
                    Ok(_) => info!(question = %id, "asker suspended or removed; withdrawn"),
                    Err(e) => warn!(question = %id, error = %e, "could not withdraw a question"),
                }
            }
        }
        Ok(())
    }

    /// Check that `person` holds `role` now.
    fn require_role(roster: &Roster<'_>, person: &ActorId, role: Role) -> Result<(), EngineError> {
        if roster.has_role(person, role) {
            Ok(())
        } else {
            Err(EngineError::Forbidden(format!("{person} does not hold the {} role", role.as_str())))
        }
    }

    /// Record a person's decision (from the web UI or a channel), then apply
    /// it at the backend.
    pub async fn decide(&self, intent: ActionIntent, now: Timestamp) -> Result<Request, EngineError> {
        let ActionIntent { request_id, verdict, approver: person, assurance, via, comment } = intent;
        for _ in 0..CONFLICT_RETRIES {
            let (rules, standing) = self.standing().await?;
            let roster = rules.roster(&standing, now);
            Self::require_role(&roster, &person, Role::Member)?;
            let mut r = self.store.get_request(request_id).await?.ok_or(EngineError::UnknownRequest(request_id))?;
            let v = r.version;
            let events = r.decide(&roster, &person, verdict, assurance, via.clone(), comment.clone(), now)?;
            if !self.save(&r, v, &events).await? {
                continue;
            }
            info!(request = %r.id, %person, ?verdict, %assurance, via = %via, state = r.state.name(), "decision recorded");
            match r.state {
                RequestState::Approved => return self.apply_grant(r, now).await,
                RequestState::Denied => self.deny_subject(&r).await,
                _ => {}
            }
            return Ok(r);
        }
        Err(EngineError::Busy)
    }

    /// The requester has picked up an approval. A single-use approval ends
    /// here; a window stays open until its time is up.
    pub async fn collect(&self, request_id: RequestId, now: Timestamp) -> Result<Request, EngineError> {
        for _ in 0..CONFLICT_RETRIES {
            let mut r = self.store.get_request(request_id).await?.ok_or(EngineError::UnknownRequest(request_id))?;
            if r.requirements.grant != GrantMode::Once || !matches!(r.state, RequestState::Active { .. }) {
                return Ok(r);
            }
            let v = r.version;
            let events = r.collect(now)?;
            if self.save(&r, v, &events).await? {
                info!(request = %r.id, "single-use approval collected");
                return Ok(r);
            }
        }
        Err(EngineError::Busy)
    }

    /// The requester gave up waiting.
    pub async fn withdraw(&self, request_id: RequestId, now: Timestamp) -> Result<Request, EngineError> {
        for _ in 0..CONFLICT_RETRIES {
            let mut r = self.store.get_request(request_id).await?.ok_or(EngineError::UnknownRequest(request_id))?;
            let v = r.version;
            let events = r.withdraw(now)?;
            if self.save(&r, v, &events).await? {
                info!(request = %r.id, "withdrawn");
                return Ok(r);
            }
        }
        Err(EngineError::Busy)
    }

    /// End an active grant early. `person` must be an admin, or a member
    /// who could decide the request now.
    pub async fn revoke(
        &self,
        request_id: RequestId,
        person: &ActorId,
        now: Timestamp,
    ) -> Result<Request, EngineError> {
        let (rules, standing) = self.standing().await?;
        let roster = rules.roster(&standing, now);
        let r = self.store.get_request(request_id).await?.ok_or(EngineError::UnknownRequest(request_id))?;
        if !roster.has_role(person, Role::Admin) {
            Self::require_role(&roster, person, Role::Member)?;
            r.eligible(&roster, person)?;
        }
        self.revoke_unchecked(r, Some(person.clone()), now).await
    }

    async fn revoke_unchecked(
        &self,
        mut r: Request,
        by: Option<ActorId>,
        now: Timestamp,
    ) -> Result<Request, EngineError> {
        let v = r.version;
        let events = r.revoke(by.clone(), now)?;
        let backend = self.backend(&r.subject.backend)?;
        if let Some(g) = &r.grant {
            if backend.capabilities().revoke {
                backend.revoke(g).await?;
            } else {
                return Err(BackendError::Unsupported.into());
            }
        }
        if !self.save(&r, v, &events).await? {
            return Err(EngineError::Busy);
        }
        info!(request = %r.id, by = ?by, "grant revoked");
        Ok(r)
    }

    /// Re-verify the subject and grant access. Transient backend failures
    /// leave the request approved so the next tick retries.
    async fn apply_grant(&self, mut r: Request, now: Timestamp) -> Result<Request, EngineError> {
        let backend = self.backend(&r.subject.backend)?;
        let v = r.version;

        let failure = match backend.verify(&r.subject).await {
            Ok(facts) if facts.requester.id != r.facts.requester.id => {
                Some(format!("requester changed from {} to {}", r.facts.requester.id, facts.requester.id))
            }
            Ok(_) => None,
            Err(e) if e.is_retryable() => {
                warn!(request = %r.id, error = %e, "backend unavailable; will retry the grant");
                return Ok(r);
            }
            Err(e) => Some(format!("verification failed: {e}")),
        };

        let events = match failure {
            Some(reason) => r.grant_failed(reason, now)?,
            None => match backend.grant(&r.subject, r.requirements.ttl).await {
                Ok(handle) => r.grant_succeeded(handle, now)?,
                Err(e) if e.is_retryable() => {
                    warn!(request = %r.id, error = %e, "backend unavailable; will retry the grant");
                    return Ok(r);
                }
                Err(e) => r.grant_failed(e.to_string(), now)?,
            },
        };
        if self.save(&r, v, &events).await? {
            match &r.state {
                RequestState::Active { until } => info!(request = %r.id, %until, "access granted"),
                RequestState::Failed { error } => {
                    warn!(request = %r.id, %error, "grant failed");
                    self.deny_subject(&r).await;
                }
                _ => {}
            }
        }
        Ok(r)
    }

    /// Best-effort rejection at the backend after a negative outcome.
    async fn deny_subject(&self, r: &Request) {
        let Ok(backend) = self.backend(&r.subject.backend) else { return };
        match backend.deny(&r.subject).await {
            Ok(()) | Err(BackendError::NotFound | BackendError::Conflict(_)) => {}
            // The next sync finds the subject still pending and retries.
            Err(e) => warn!(request = %r.id, error = %e, "could not reject at the backend; will retry"),
        }
    }

    async fn deny_at_backend(&self, backend: &dyn AccessBackend, p: &PendingSubject) -> bool {
        self.deny_ref(backend, &p.subject).await
    }

    async fn deny_ref(&self, backend: &dyn AccessBackend, subject: &countersign_core::SubjectRef) -> bool {
        match backend.deny(subject).await {
            Ok(()) => true,
            Err(BackendError::NotFound | BackendError::Conflict(_)) => false,
            Err(e) => {
                warn!(subject = %subject.id, error = %e, "could not reject at the backend");
                false
            }
        }
    }

    /// Persist a transition. Returns `false` if another writer got there first.
    async fn save(&self, r: &Request, expected: u64, events: &[DomainEvent]) -> Result<bool, EngineError> {
        match self.store.update_request(r, expected, events).await {
            Ok(()) => {
                self.changed();
                Ok(true)
            }
            Err(StoreError::Conflict(_)) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    // ---- Questions ------------------------------------------------------

    /// Ask a question on behalf of an authenticated client.
    pub async fn ask(&self, ask: Ask, now: Timestamp) -> Result<Question, EngineError> {
        use countersign_core::question::{MAX_CONTEXT, MAX_CONTEXT_KEY, MAX_CONTEXT_VALUE, MAX_MESSAGE};
        let Ask { asker, message, schema, context, mut confidentiality } = ask;
        let (rules, standing) = self.standing().await?;
        let roster = rules.roster(&standing, now);
        if asker.actor.as_ref().is_some_and(|a| !roster.is_active(a)) {
            return Err(EngineError::Forbidden("the actor this client asks for is suspended".into()));
        }
        let Some(policy) = rules.question_policies.find(&asker) else {
            return Err(EngineError::Refused("no question policy allows this asker".into()));
        };

        let message = message.trim();
        if message.is_empty() {
            return Err(EngineError::Invalid("message is empty".into()));
        }
        let message = clean_text(message, MAX_MESSAGE, "message")?;
        if context.len() > MAX_CONTEXT {
            return Err(EngineError::Invalid(format!("context has more than {MAX_CONTEXT} entries")));
        }
        let context = context
            .iter()
            .map(|(k, v)| {
                Ok((
                    clean_text(k, MAX_CONTEXT_KEY, "a context key")?,
                    clean_text(v, MAX_CONTEXT_VALUE, "a context value")?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, EngineError>>()?;
        FormSchema::parse(&schema).map_err(|e| EngineError::Invalid(e.to_string()))?;

        match policy.confidential {
            ConfidentialMode::Deny if confidentiality.question => {
                return Err(EngineError::Refused(format!(
                    "question policy {} does not allow confidential questions",
                    policy.name
                )));
            }
            ConfidentialMode::Require => confidentiality.question = true,
            _ => {}
        }

        let open = self.store.list_questions(&RequestFilter { open_only: true, limit: None }).await?;
        let waiting =
            open.iter().filter(|q| q.asker.client == asker.client && q.requirements.policy == policy.name).count();
        if waiting >= policy.max_pending {
            return Err(EngineError::Refused("too many questions are waiting for an answer".into()));
        }

        let (q, events) = Question::ask(asker, message, schema, context, policy, confidentiality, now);
        let potential = roster
            .directory
            .persons()
            .filter(|p| {
                roster.active_person(&p.id).is_some() && roster.could_be_selected(&q.requirements.responders, &p.id)
            })
            .filter(|p| q.requirements.allow_self_answer || q.asker.actor.as_ref() != Some(&p.id))
            .count();
        if potential == 0 {
            return Err(EngineError::Refused("nobody could answer this question".into()));
        }
        self.store.insert_question(&q, &events).await?;
        self.changed();
        info!(question = %q.id, asker = %q.asker.client, policy = %q.requirements.policy, "question asked");
        Ok(q)
    }

    /// Record an answer or a decline.
    pub async fn answer(&self, intent: AnswerIntent, now: Timestamp) -> Result<Question, EngineError> {
        let AnswerIntent { question_id, responder, response, assurance, via } = intent;
        for _ in 0..CONFLICT_RETRIES {
            let (rules, standing) = self.standing().await?;
            let roster = rules.roster(&standing, now);
            Self::require_role(&roster, &responder, Role::Member)?;
            let mut q = self.store.get_question(question_id).await?.ok_or(EngineError::UnknownQuestion(question_id))?;
            let v = q.version;
            let events = q.respond(&roster, &responder, response.clone(), assurance, via.clone(), now)?;
            if self.save_question(&q, v, &events).await? {
                info!(question = %q.id, %responder, %assurance, via = %via, state = q.state(), "question answered");
                return Ok(q);
            }
        }
        Err(EngineError::Busy)
    }

    /// The asking client reads a question. The first read of a finished
    /// question marks the answer read, which removes a confidential answer
    /// from the store; the content is returned this once.
    pub async fn read_question(
        &self,
        id: RequestId,
        client: &ClientId,
        now: Timestamp,
    ) -> Result<Question, EngineError> {
        for _ in 0..CONFLICT_RETRIES {
            let mut q = self.store.get_question(id).await?.ok_or(EngineError::UnknownQuestion(id))?;
            if &q.asker.client != client {
                return Err(EngineError::UnknownQuestion(id));
            }
            let before = q.clone();
            let v = q.version;
            if !q.mark_read(now) {
                return Ok(q);
            }
            if self.save_question(&q, v, &[]).await? {
                debug!(question = %q.id, "answer read by the asker");
                return Ok(before);
            }
        }
        Err(EngineError::Busy)
    }

    /// The asker gave up. With `client`, only that client's question.
    pub async fn withdraw_question(
        &self,
        id: RequestId,
        client: Option<&ClientId>,
        now: Timestamp,
    ) -> Result<Question, EngineError> {
        for _ in 0..CONFLICT_RETRIES {
            let mut q = self.store.get_question(id).await?.ok_or(EngineError::UnknownQuestion(id))?;
            if client.is_some_and(|c| c != &q.asker.client) {
                return Err(EngineError::UnknownQuestion(id));
            }
            let v = q.version;
            let events = q.withdraw(now)?;
            if self.save_question(&q, v, &events).await? {
                info!(question = %q.id, "question withdrawn");
                return Ok(q);
            }
        }
        Err(EngineError::Busy)
    }

    /// Expire unanswered questions and remove confidential content whose
    /// time is up.
    pub async fn advance_questions(&self, now: Timestamp) -> Result<(), EngineError> {
        let open = self.store.list_questions(&RequestFilter { open_only: true, limit: None }).await?;
        for mut q in open {
            let v = q.version;
            let events = q.expire_if_due(now);
            if !events.is_empty() && self.save_question(&q, v, &events).await? {
                info!(question = %q.id, "expired without an answer");
            }
        }
        for mut q in self.store.questions_holding_content().await? {
            let v = q.version;
            if q.sweep(now) && self.save_question(&q, v, &[]).await? {
                info!(question = %q.id, "confidential content removed");
            }
        }
        Ok(())
    }

    async fn save_question(&self, q: &Question, expected: u64, events: &[DomainEvent]) -> Result<bool, EngineError> {
        match self.store.update_question(q, expected, events).await {
            Ok(()) => {
                self.changed();
                Ok(true)
            }
            Err(StoreError::Conflict(_)) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    // ---- Admin ----------------------------------------------------------

    async fn audit(
        &self,
        by: &ActorId,
        action: &str,
        target: &str,
        detail: Option<String>,
        now: Timestamp,
    ) -> AdminAction {
        let a = AdminAction { at: now, by: by.clone(), action: action.to_owned(), target: target.to_owned(), detail };
        if let Err(e) = self.store.record_admin_action(&a).await {
            warn!(error = %e, action, target, "could not record an admin action");
        }
        a
    }

    async fn announce_admin(&self, action: AdminAction) {
        let notifier = self.admin_notifier.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        if let Some(notify) = notifier {
            notify(action).await;
        }
    }

    async fn require_admin(&self, by: &ActorId, now: Timestamp) -> Result<(), EngineError> {
        let (rules, standing) = self.standing().await?;
        Self::require_role(&rules.roster(&standing, now), by, Role::Admin)
    }

    /// Suspend an actor at once: they can no longer decide, answer, request
    /// or ask, their approvals stop counting, and what they (or workloads
    /// left without an active owner) have open is withdrawn or revoked.
    pub async fn suspend(
        &self,
        actor: &ActorId,
        by: &ActorId,
        reason: Option<String>,
        now: Timestamp,
    ) -> Result<(), EngineError> {
        self.require_admin(by, now).await?;
        if self.rules().directory.actor(actor).is_none() {
            return Err(EngineError::Invalid(format!("unknown actor {actor}")));
        }
        if actor == by {
            return Err(EngineError::Invalid("admins cannot suspend themselves".into()));
        }
        let reason = reason.map(|r| r.trim().chars().take(500).collect::<String>()).filter(|r| !r.is_empty());
        self.store.suspend(actor, &Suspension { since: now, by: by.clone(), reason: reason.clone() }).await?;
        let action = self.audit(by, "suspend", actor.as_str(), reason, now).await;
        info!(%actor, %by, "actor suspended");
        self.enforce_standing(now).await?;
        self.announce_admin(action).await;
        self.changed();
        Ok(())
    }

    /// Lift a suspension. Returns whether there was one.
    pub async fn reinstate(&self, actor: &ActorId, by: &ActorId, now: Timestamp) -> Result<bool, EngineError> {
        self.require_admin(by, now).await?;
        let lifted = self.store.reinstate(actor).await?;
        if lifted {
            self.audit(by, "reinstate", actor.as_str(), None, now).await;
            info!(%actor, %by, "suspension lifted");
            self.changed();
        }
        Ok(lifted)
    }

    /// Revoke every active grant `person` approved, e.g. after their
    /// account was misused. Returns the revoked requests.
    pub async fn revoke_approved_by(
        &self,
        person: &ActorId,
        by: &ActorId,
        now: Timestamp,
    ) -> Result<Vec<RequestId>, EngineError> {
        self.require_admin(by, now).await?;
        let open = self.store.list_requests(&RequestFilter { open_only: true, limit: None }).await?;
        let mut revoked = Vec::new();
        for r in open {
            if !matches!(r.state, RequestState::Active { .. }) || !r.approvals().contains(person) {
                continue;
            }
            let id = r.id;
            match self.revoke_unchecked(r, Some(by.clone()), now).await {
                Ok(_) => revoked.push(id),
                Err(e) => warn!(request = %id, error = %e, "could not revoke"),
            }
        }
        let action = self
            .audit(by, "revoke-approved-by", person.as_str(), Some(format!("{} revoked", revoked.len())), now)
            .await;
        self.announce_admin(action).await;
        Ok(revoked)
    }

    /// Remove a chat link, as an admin.
    pub async fn unlink(
        &self,
        channel: &countersign_core::ChannelName,
        external_id: &str,
        by: &ActorId,
        now: Timestamp,
    ) -> Result<bool, EngineError> {
        self.require_admin(by, now).await?;
        let removed = self.store.unlink_account(channel, external_id).await?;
        if removed {
            self.audit(by, "unlink", &format!("{channel}:{external_id}"), None, now).await;
        }
        Ok(removed)
    }
}
