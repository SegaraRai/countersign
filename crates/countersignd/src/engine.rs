//! Applies the core state machine against backends and the store.
//!
//! The engine is driven by two kinds of calls:
//! - [`Engine::tick`], run periodically, discovers pending subjects, sweeps
//!   timeouts, and retries grants that could not be applied yet.
//! - [`Engine::decide`] / [`Engine::revoke`], run when an approver acts.
//! - [`Engine::submit`], run when a subject is pushed to countersign (e.g. a
//!   `sudo` invocation waiting for approval).
//!
//! Every method takes `now` so tests control time.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};

use countersign_core::{
    AccessBackend, ActionIntent, Approver, ApproverId, BackendError, BackendName, DomainEvent, GrantMode,
    PendingSubject, PolicySet, Request, RequestFilter, RequestId, RequestState, Store, StoreError, TransitionError,
};
use jiff::Timestamp;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::config::Unmatched;

/// How many times to retry a decision that lost an optimistic-concurrency race.
const CONFLICT_RETRIES: usize = 3;

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("unknown approver {0}")]
    UnknownApprover(ApproverId),
    #[error("request {0} not found")]
    UnknownRequest(RequestId),
    #[error("backend {0} is not configured")]
    UnknownBackend(BackendName),
    #[error(transparent)]
    Transition(#[from] TransitionError),
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
    pub policies: PolicySet,
    pub approvers: BTreeMap<ApproverId, Approver>,
    pub unmatched: Unmatched,
}

pub struct Engine {
    store: Arc<dyn Store>,
    backends: BTreeMap<BackendName, Arc<dyn AccessBackend>>,
    rules: RwLock<Arc<Rules>>,
    /// Unmatched subjects already logged, to avoid repeating the warning.
    unmatched_seen: std::sync::Mutex<BTreeSet<String>>,
    /// Bumped whenever a request is stored, so waiters can re-check.
    changes: watch::Sender<u64>,
}

/// Outcome of [`Engine::submit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Submitted {
    /// A new request waits for approval.
    Opened(Request),
    /// An active window approved the subject; this is the window request,
    /// with the use recorded.
    Covered(Request),
    /// No policy matches; nothing was stored.
    Unmatched,
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

impl Engine {
    pub fn new(store: Arc<dyn Store>, backends: Vec<Arc<dyn AccessBackend>>, rules: Rules) -> Self {
        Self {
            store,
            backends: backends.into_iter().map(|b| (b.name().clone(), b)).collect(),
            rules: RwLock::new(Arc::new(rules)),
            unmatched_seen: std::sync::Mutex::default(),
            changes: watch::Sender::new(0),
        }
    }

    /// A receiver that changes whenever any request is stored.
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

    /// Replace policies and approvers. Requests already open keep the
    /// requirements they were opened with.
    pub fn set_rules(&self, rules: Rules) {
        *self.rules.write().unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(rules);
    }

    fn backend(&self, name: &BackendName) -> Result<&Arc<dyn AccessBackend>, EngineError> {
        self.backends.get(name).ok_or_else(|| EngineError::UnknownBackend(name.clone()))
    }

    /// One periodic pass: discover, then advance every open request.
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
        if let Err(e) = self.advance_open(now).await {
            warn!(error = %e, "advancing open requests failed");
        }
    }

    /// Reconcile one backend's pending subjects with stored requests.
    pub async fn sync_backend(&self, name: &BackendName, now: Timestamp) -> Result<SyncReport, EngineError> {
        let backend = self.backend(name)?;
        let pending = backend.discover_pending().await?;
        let rules = self.rules();
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
                None => match rules.policies.evaluate(&p) {
                    Some(reqs) => {
                        let (request, events) = Request::open(p, reqs, now);
                        match self.store.insert_request(&request, &events).await {
                            Ok(()) => {
                                self.changed();
                                info!(request = %request.id, subject = %request.subject.id, policy = %request.requirements.policy, "opened request");
                                report.opened += 1;
                            }
                            Err(StoreError::Duplicate) => {}
                            Err(e) => return Err(e.into()),
                        }
                    }
                    None => match rules.unmatched {
                        Unmatched::Deny => {
                            info!(subject = %p.subject.id, requester = %p.facts.requester.id, "no policy matches; rejecting");
                            if self.deny_at_backend(backend.as_ref(), &p).await {
                                report.denied_unmatched += 1;
                            }
                        }
                        Unmatched::Ignore => {
                            let key = format!("{}/{}", p.subject.backend, p.subject.id);
                            if self.unmatched_seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(key)
                            {
                                warn!(subject = %p.subject.id, requester = %p.facts.requester.id, "no policy matches; ignoring");
                            }
                        }
                    },
                },
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

    /// Record an approver's decision (from the web UI or a channel), then
    /// apply it at the backend.
    pub async fn decide(&self, intent: ActionIntent, now: Timestamp) -> Result<Request, EngineError> {
        let ActionIntent { request_id, verdict, approver: approver_id, assurance, via, comment } = intent;
        let approver =
            self.rules().approvers.get(&approver_id).cloned().ok_or(EngineError::UnknownApprover(approver_id))?;

        for _ in 0..CONFLICT_RETRIES {
            let mut r = self.store.get_request(request_id).await?.ok_or(EngineError::UnknownRequest(request_id))?;
            let v = r.version;
            let events = r.decide(&approver, verdict, assurance, via.clone(), comment.clone(), now)?;
            if !self.save(&r, v, &events).await? {
                continue;
            }
            info!(request = %r.id, approver = %approver.id, ?verdict, %assurance, via = %via, state = r.state.name(), "decision recorded");
            match r.state {
                RequestState::Approved => return self.apply_grant(r, now).await,
                RequestState::Denied => self.deny_subject(&r).await,
                _ => {}
            }
            return Ok(r);
        }
        Err(EngineError::Busy)
    }

    /// Take a subject pushed by its backend: approve it under an active
    /// window of the same policy, or open a request for it.
    pub async fn submit(&self, p: PendingSubject, now: Timestamp) -> Result<Submitted, EngineError> {
        self.backend(&p.subject.backend)?;
        let rules = self.rules();
        let Some(policy) = rules.policies.find(&p) else {
            info!(subject = %p.subject.id, requester = %p.facts.requester.id, "no policy matches; refusing");
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
        let (request, events) = Request::open(p, reqs, now);
        self.store.insert_request(&request, &events).await?;
        self.changed();
        info!(request = %request.id, subject = %request.subject.id, policy = %request.requirements.policy, "opened request");
        Ok(Submitted::Opened(request))
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
            let events = r.end(now)?;
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
                info!(request = %r.id, "withdrawn by the requester");
                return Ok(r);
            }
        }
        Err(EngineError::Busy)
    }

    /// End an active grant early. The approver must be eligible for the request.
    pub async fn revoke(
        &self,
        request_id: RequestId,
        approver_id: &ApproverId,
        now: Timestamp,
    ) -> Result<Request, EngineError> {
        let approver = self
            .rules()
            .approvers
            .get(approver_id)
            .cloned()
            .ok_or_else(|| EngineError::UnknownApprover(approver_id.clone()))?;
        let mut r = self.store.get_request(request_id).await?.ok_or(EngineError::UnknownRequest(request_id))?;
        if !r.requirements.is_eligible(&approver) {
            return Err(TransitionError::NotEligible.into());
        }
        let v = r.version;
        let events = r.revoke(Some(approver.id.clone()), now)?;
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
        info!(request = %r.id, approver = %approver.id, "grant revoked");
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
        match backend.deny(&p.subject).await {
            Ok(()) => true,
            Err(BackendError::NotFound | BackendError::Conflict(_)) => false,
            Err(e) => {
                warn!(subject = %p.subject.id, error = %e, "could not reject at the backend");
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
}
