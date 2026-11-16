//! The approval state machine.
//!
//! ```text
//!            decide(approve) until quorum
//!            ┌───────┐
//!            ▼       │
//! open ──▶ Pending ──┴─▶ Approved ──grant_succeeded──▶ Active ──end_if_elapsed──▶ Ended
//!            │  │  │         └──────grant_failed─────▶ Failed        └──revoke──▶ Revoked
//!            │  │  └─decide(deny)──▶ Denied
//!            │  └─expire_pending──▶ Expired
//!            └─withdraw──▶ Withdrawn
//! ```
//!
//! Every successful transition bumps [`Request::version`] (for optimistic
//! concurrency in the store) and returns the events to put in the outbox.
//!
//! Who may decide is checked against a [`Roster`] at decision time: the
//! selectors are frozen with the request, while status and group membership
//! are taken as they are now. A request can only get harder to approve after
//! it is created.

use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::actor::Roster;
use crate::assurance::Assurance;
use crate::backend::GrantHandle;
use crate::event::DomainEvent;
use crate::id::{ActorId, ChannelName, RequestId};
use crate::policy::{Exclusion, GrantMode, Requirements};
use crate::subject::{PendingSubject, Requester, SubjectFacts, SubjectRef};
use crate::time;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Approve,
    Deny,
}

/// One person's decision, as recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub approver: ActorId,
    pub verdict: Verdict,
    pub assurance: Assurance,
    pub via: ChannelName,
    pub at: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum RequestState {
    Pending,
    /// Quorum reached; waiting for the backend to apply the grant.
    Approved,
    Active {
        until: Timestamp,
    },
    Denied,
    Expired,
    Withdrawn,
    Failed {
        error: String,
    },
    Revoked,
    Ended,
}

impl RequestState {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Active { .. } => "active",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Withdrawn => "withdrawn",
            Self::Failed { .. } => "failed",
            Self::Revoked => "revoked",
            Self::Ended => "ended",
        }
    }

    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }

    /// No further transitions are possible.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Denied | Self::Expired | Self::Withdrawn | Self::Failed { .. } | Self::Revoked | Self::Ended
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransitionError {
    #[error("cannot {action} a request that is {state}")]
    InvalidState { state: &'static str, action: &'static str },
    #[error("the request is no longer accepting decisions")]
    PendingExpired,
    #[error("you are not eligible for this request")]
    NotEligible,
    #[error("only active persons can decide")]
    Inactive,
    #[error("the policy excludes the {} from deciding this request", exclusion_name(*.0))]
    Excluded(Exclusion),
    #[error("approval requires assurance {required}, got {presented}")]
    InsufficientAssurance { required: Assurance, presented: Assurance },
    #[error("you have already decided")]
    AlreadyDecided,
    #[error("the approval does not cover other subjects")]
    NotAWindow,
}

fn exclusion_name(e: Exclusion) -> &'static str {
    match e {
        Exclusion::Requester => "requester",
        Exclusion::Owners => "owners of the requester",
        Exclusion::Initiator => "initiator",
    }
}

/// A subject approved under an active [`GrantMode::Window`] request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Use {
    pub subject: SubjectRef,
    pub at: Timestamp,
    /// The new subject's attributes (e.g. the command that was run).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
}

/// A request for approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub id: RequestId,
    pub subject: SubjectRef,
    pub facts: SubjectFacts,
    pub requirements: Requirements,
    pub state: RequestState,
    pub decisions: Vec<Decision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<GrantHandle>,
    /// Subjects approved under this request while it was an active window.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uses: Vec<Use>,
    /// When the requester picked up a single-use approval (see
    /// [`Request::collect`]). A single-use approval that ended without being
    /// collected was never used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collected_at: Option<Timestamp>,
    /// Keep the details out of chat channels (the requester asked, or the
    /// policy says so). Approvers in the web UI still see everything, and
    /// the record keeps everything.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sensitive: bool,
    pub created_at: Timestamp,
    /// Decisions are refused after this instant.
    pub pending_until: Timestamp,
    pub updated_at: Timestamp,
    pub version: u64,
}

impl Request {
    /// Open a request for a pending subject under resolved requirements.
    /// `sensitive` is the resolved display flag (see
    /// [`crate::SensitiveMode::resolve`]).
    pub fn open(
        pending: PendingSubject,
        requirements: Requirements,
        sensitive: bool,
        now: Timestamp,
    ) -> (Self, Vec<DomainEvent>) {
        let id = RequestId::new();
        let pending_until = time::add(now, requirements.pending_timeout);
        let req = Self {
            id,
            subject: pending.subject,
            facts: pending.facts,
            requirements,
            state: RequestState::Pending,
            decisions: Vec::new(),
            grant: None,
            uses: Vec::new(),
            collected_at: None,
            sensitive,
            created_at: now,
            pending_until,
            updated_at: now,
            version: 0,
        };
        (req, vec![DomainEvent::Requested { request_id: id, at: now }])
    }

    /// The request as chat and webhook channels may show it. A sensitive
    /// request keeps only where it came from, its policy and how it stands:
    /// no requester, target, reason, attributes or comments.
    #[must_use]
    pub fn for_chat(&self) -> Self {
        let mut r = self.clone();
        if r.sensitive {
            let source = r.facts.source.take();
            r.facts = SubjectFacts { source, sensitive: true, ..SubjectFacts::new(Requester::default()) };
            for u in &mut r.uses {
                u.attributes.clear();
            }
            for d in &mut r.decisions {
                d.comment = None;
            }
        }
        r
    }

    /// Every person who has approved so far.
    pub fn approvals(&self) -> BTreeSet<&ActorId> {
        self.decisions.iter().filter(|d| d.verdict == Verdict::Approve).map(|d| &d.approver).collect()
    }

    /// Approvals that still count: those of persons who are active now. A
    /// suspended or removed person's approval of a pending request stops
    /// counting towards the quorum.
    pub fn counted_approvals(&self, roster: &Roster<'_>) -> BTreeSet<&ActorId> {
        self.approvals().into_iter().filter(|a| roster.active_person(a).is_some()).collect()
    }

    /// The relation that excludes `person` from deciding, if any.
    pub fn exclusion(&self, roster: &Roster<'_>, person: &ActorId) -> Option<Exclusion> {
        let requester = self.facts.requester.actor.as_ref();
        let initiator = self.facts.initiator.as_ref().and_then(|i| i.actor.as_ref());
        self.requirements.exclude.iter().copied().find(|e| match e {
            Exclusion::Requester => requester == Some(person),
            Exclusion::Owners => requester.is_some_and(|r| roster.owners(r).contains(person)),
            Exclusion::Initiator => initiator == Some(person),
        })
    }

    /// Whether `person` could decide this request now, assurance aside:
    /// active, selected by the frozen selectors with their current groups,
    /// and not excluded.
    pub fn eligible(&self, roster: &Roster<'_>, person: &ActorId) -> Result<(), TransitionError> {
        if roster.active_person(person).is_none() {
            return Err(TransitionError::Inactive);
        }
        if !roster.selected(&self.requirements.approvers, person) {
            return Err(TransitionError::NotEligible);
        }
        if let Some(e) = self.exclusion(roster, person) {
            return Err(TransitionError::Excluded(e));
        }
        Ok(())
    }

    /// How many persons could take part in the quorum, counting those whose
    /// group membership needs renewing by signing in again.
    pub fn potential_deciders(&self, roster: &Roster<'_>) -> usize {
        roster
            .directory
            .persons()
            .filter(|p| {
                roster.active_person(&p.id).is_some()
                    && roster.could_be_selected(&self.requirements.approvers, &p.id)
                    && self.exclusion(roster, &p.id).is_none()
            })
            .count()
    }

    /// Check whether `person` may record `verdict` at `assurance`, without
    /// changing anything. Useful to decide which actions to offer.
    pub fn check_decision(
        &self,
        roster: &Roster<'_>,
        person: &ActorId,
        verdict: Verdict,
        assurance: Assurance,
        now: Timestamp,
    ) -> Result<(), TransitionError> {
        self.require(RequestState::is_pending, "decide")?;
        if now >= self.pending_until {
            return Err(TransitionError::PendingExpired);
        }
        self.eligible(roster, person)?;
        let reqs = &self.requirements;
        if verdict == Verdict::Approve && assurance < reqs.min_assurance {
            return Err(TransitionError::InsufficientAssurance { required: reqs.min_assurance, presented: assurance });
        }
        if self.decisions.iter().any(|d| d.approver == *person) {
            return Err(TransitionError::AlreadyDecided);
        }
        Ok(())
    }

    /// Record a decision. A single denial ends the request; approvals
    /// accumulate until the quorum of active persons is reached.
    #[allow(clippy::too_many_arguments)]
    pub fn decide(
        &mut self,
        roster: &Roster<'_>,
        person: &ActorId,
        verdict: Verdict,
        assurance: Assurance,
        via: ChannelName,
        comment: Option<String>,
        now: Timestamp,
    ) -> Result<Vec<DomainEvent>, TransitionError> {
        self.check_decision(roster, person, verdict, assurance, now)?;
        let decision = Decision { approver: person.clone(), verdict, assurance, via, at: now, comment };
        self.decisions.push(decision.clone());
        let mut events = vec![DomainEvent::DecisionRecorded { request_id: self.id, decision }];
        match verdict {
            Verdict::Deny => {
                self.state = RequestState::Denied;
                events.push(DomainEvent::Denied { request_id: self.id, by: person.clone(), at: now });
            }
            Verdict::Approve if self.counted_approvals(roster).len() >= usize::from(self.requirements.quorum) => {
                self.state = RequestState::Approved;
                events.push(DomainEvent::Approved { request_id: self.id, at: now });
            }
            Verdict::Approve => {}
        }
        self.touch(now);
        Ok(events)
    }

    /// The backend applied the grant.
    pub fn grant_succeeded(&mut self, grant: GrantHandle, now: Timestamp) -> Result<Vec<DomainEvent>, TransitionError> {
        self.require(|s| matches!(s, RequestState::Approved), "activate")?;
        let ours = time::add(now, self.requirements.ttl);
        // Never extend beyond what we asked for, even if the backend reports more.
        let until = grant.expires_at.map_or(ours, |t| t.min(ours));
        self.grant = Some(grant);
        self.state = RequestState::Active { until };
        self.touch(now);
        Ok(vec![DomainEvent::Granted { request_id: self.id, until, at: now }])
    }

    /// The backend failed to apply the grant (after retries).
    pub fn grant_failed(&mut self, error: String, now: Timestamp) -> Result<Vec<DomainEvent>, TransitionError> {
        self.require(|s| matches!(s, RequestState::Approved), "fail")?;
        self.state = RequestState::Failed { error: error.clone() };
        self.touch(now);
        Ok(vec![DomainEvent::GrantFailed { request_id: self.id, error, at: now }])
    }

    /// The request cannot be decided at all (nobody is eligible, a required
    /// initiator is missing).
    pub fn fail_pending(&mut self, error: String, now: Timestamp) -> Result<Vec<DomainEvent>, TransitionError> {
        self.require(RequestState::is_pending, "fail")?;
        self.state = RequestState::Failed { error: error.clone() };
        self.touch(now);
        Ok(vec![DomainEvent::GrantFailed { request_id: self.id, error, at: now }])
    }

    /// Expire an undecided request whose pending timeout has passed.
    /// Returns no events if it is not due yet.
    pub fn expire_pending(&mut self, now: Timestamp) -> Result<Vec<DomainEvent>, TransitionError> {
        self.require(RequestState::is_pending, "expire")?;
        if now < self.pending_until {
            return Ok(Vec::new());
        }
        self.state = RequestState::Expired;
        self.touch(now);
        Ok(vec![DomainEvent::Expired { request_id: self.id, at: now }])
    }

    /// The requester or backend dropped the request.
    pub fn withdraw(&mut self, now: Timestamp) -> Result<Vec<DomainEvent>, TransitionError> {
        self.require(RequestState::is_pending, "withdraw")?;
        self.state = RequestState::Withdrawn;
        self.touch(now);
        Ok(vec![DomainEvent::Withdrawn { request_id: self.id, at: now }])
    }

    /// Take back an active grant early.
    pub fn revoke(&mut self, by: Option<ActorId>, now: Timestamp) -> Result<Vec<DomainEvent>, TransitionError> {
        self.require(|s| matches!(s, RequestState::Active { .. }), "revoke")?;
        self.state = RequestState::Revoked;
        self.touch(now);
        Ok(vec![DomainEvent::Revoked { request_id: self.id, by, at: now }])
    }

    /// Whether this request, as an active window, covers `pending`: same
    /// source, backend, kind, requester and target. The caller checks that
    /// the same policy matches.
    pub fn window_covers(&self, pending: &PendingSubject, now: Timestamp) -> bool {
        let RequestState::Active { until } = self.state else { return false };
        self.requirements.grant == GrantMode::Window
            && now < until
            && self.subject.backend == pending.subject.backend
            && self.subject.kind == pending.subject.kind
            && self.facts.source == pending.facts.source
            && !self.facts.requester.identity.is_empty()
            && self.facts.requester.identity == pending.facts.requester.identity
            && self.facts.target.is_some()
            && self.facts.target == pending.facts.target
    }

    /// Record a subject approved under this active window. Emits no events.
    pub fn record_use(&mut self, pending: &PendingSubject, now: Timestamp) -> Result<(), TransitionError> {
        self.require(|s| matches!(s, RequestState::Active { .. }), "use")?;
        if !self.window_covers(pending, now) {
            return Err(TransitionError::NotAWindow);
        }
        self.uses.push(Use { subject: pending.subject.clone(), at: now, attributes: pending.facts.attributes.clone() });
        self.touch(now);
        Ok(())
    }

    /// The requester picked up an active single-use approval: it is used,
    /// and ends now.
    pub fn collect(&mut self, now: Timestamp) -> Result<Vec<DomainEvent>, TransitionError> {
        self.require(|s| matches!(s, RequestState::Active { .. }), "collect")?;
        if self.requirements.grant != GrantMode::Once {
            return Err(TransitionError::InvalidState { state: "a window", action: "collect" });
        }
        self.collected_at = Some(now);
        self.state = RequestState::Ended;
        self.touch(now);
        Ok(vec![DomainEvent::Ended { request_id: self.id, at: now }])
    }

    /// End an active grant whose time is up. Returns no events if not due.
    pub fn end_if_elapsed(&mut self, now: Timestamp) -> Result<Vec<DomainEvent>, TransitionError> {
        let RequestState::Active { until } = self.state else {
            return Err(TransitionError::InvalidState { state: self.state.name(), action: "end" });
        };
        if now < until {
            return Ok(Vec::new());
        }
        self.state = RequestState::Ended;
        self.touch(now);
        Ok(vec![DomainEvent::Ended { request_id: self.id, at: now }])
    }

    fn require(&self, ok: impl FnOnce(&RequestState) -> bool, action: &'static str) -> Result<(), TransitionError> {
        if ok(&self.state) { Ok(()) } else { Err(TransitionError::InvalidState { state: self.state.name(), action }) }
    }

    fn touch(&mut self, now: Timestamp) {
        self.updated_at = now;
        self.version += 1;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::time::Duration;

    use super::*;
    use crate::actor::{Directory, GroupConfig, PersonConfig, Roles, Selector, Standing, Suspension, WorkloadConfig};
    use crate::subject::{Initiator, Requester, Source};

    fn t(secs: i64) -> Timestamp {
        Timestamp::from_second(1_800_000_000 + secs).unwrap()
    }

    fn person(id: &str) -> PersonConfig {
        PersonConfig { id: id.into(), display_name: None, identities: vec![] }
    }

    /// alice owns the requesting workload; bob, carol and dave are in ops;
    /// mallory is not.
    fn directory() -> Directory {
        Directory::new(
            vec![person("alice"), person("bob"), person("carol"), person("dave"), person("mallory")],
            vec![WorkloadConfig {
                id: "alice-agent".into(),
                display_name: None,
                owners: vec!["alice".into()],
                identities: vec!["unix:web-1#agent".into()],
            }],
            vec![GroupConfig {
                name: "ops".into(),
                members: vec!["alice".into(), "bob".into(), "carol".into(), "dave".into()],
                from_idp: vec![],
            }],
            Roles::default(),
        )
        .unwrap()
    }

    struct World {
        dir: Directory,
        standing: Standing,
    }

    impl World {
        fn new() -> Self {
            Self { dir: directory(), standing: Standing::default() }
        }
        fn roster(&self) -> Roster<'_> {
            Roster { directory: &self.dir, standing: &self.standing, now: t(0), idp_max_age: Duration::from_secs(60) }
        }
    }

    fn open(quorum: u8, min: Assurance) -> Request {
        let mut facts = SubjectFacts::new(Requester {
            id: "agent".into(),
            identity: "unix:web-1#agent".into(),
            actor: Some("alice-agent".into()),
            ..Requester::default()
        });
        facts.source = Some(Source::Client("web-1".into()));
        facts.target = Some("host-1".into());
        let pending = PendingSubject {
            subject: SubjectRef { backend: "oct".into(), kind: "session".into(), id: "s1".into() },
            facts,
            observed_at: t(0),
        };
        let reqs = Requirements {
            policy: "p".into(),
            approvers: vec![Selector::Group("ops".into())],
            exclude: BTreeSet::from([Exclusion::Requester, Exclusion::Owners]),
            quorum,
            min_assurance: min,
            ttl: Duration::from_secs(600),
            pending_timeout: Duration::from_secs(300),
            grant: GrantMode::Once,
            require_initiator: false,
        };
        let (r, ev) = Request::open(pending, reqs, false, t(0));
        assert_eq!(ev.len(), 1);
        r
    }

    fn web() -> ChannelName {
        "web".into()
    }

    fn id(s: &str) -> ActorId {
        s.into()
    }

    #[test]
    fn single_approval_then_grant_then_end() {
        let w = World::new();
        let mut r = open(1, Assurance::FreshAuth);
        let ev = r.decide(&w.roster(), &id("bob"), Verdict::Approve, Assurance::FreshAuth, web(), None, t(10)).unwrap();
        assert_eq!(ev.iter().map(DomainEvent::kind).collect::<Vec<_>>(), ["decision-recorded", "approved"]);
        assert_eq!(r.state, RequestState::Approved);

        let handle = GrantHandle { subject: r.subject.clone(), backend_ref: None, expires_at: None };
        r.grant_succeeded(handle, t(11)).unwrap();
        assert_eq!(r.state, RequestState::Active { until: t(611) });

        assert_eq!(r.end_if_elapsed(t(600)).unwrap(), []);
        assert_eq!(r.end_if_elapsed(t(611)).unwrap().len(), 1);
        assert_eq!(r.state, RequestState::Ended);
        assert!(r.state.is_terminal());
        assert_eq!(r.version, 3);
    }

    #[test]
    fn backend_expiry_cannot_extend_ttl() {
        let w = World::new();
        let mut r = open(1, Assurance::Linked);
        r.decide(&w.roster(), &id("bob"), Verdict::Approve, Assurance::Linked, web(), None, t(0)).unwrap();
        let handle = GrantHandle { subject: r.subject.clone(), backend_ref: None, expires_at: Some(t(99_999)) };
        r.grant_succeeded(handle, t(0)).unwrap();
        assert_eq!(r.state, RequestState::Active { until: t(600) });
    }

    #[test]
    fn quorum_counts_distinct_persons() {
        let w = World::new();
        let mut r = open(2, Assurance::Web);
        let roster = w.roster();
        assert_eq!(
            r.decide(&roster, &id("bob"), Verdict::Approve, Assurance::Web, web(), None, t(1)).unwrap().len(),
            1
        );
        assert!(r.state.is_pending());
        assert_eq!(
            r.decide(&roster, &id("bob"), Verdict::Approve, Assurance::Web, web(), None, t(2)),
            Err(TransitionError::AlreadyDecided)
        );
        r.decide(&roster, &id("carol"), Verdict::Approve, Assurance::Web, web(), None, t(3)).unwrap();
        assert_eq!(r.state, RequestState::Approved);
    }

    #[test]
    fn a_suspended_persons_approval_stops_counting() {
        let mut w = World::new();
        let mut r = open(2, Assurance::Web);
        r.decide(&w.roster(), &id("bob"), Verdict::Approve, Assurance::Web, web(), None, t(1)).unwrap();
        w.standing.suspended.insert(id("bob"), Suspension { since: t(2), by: id("dave"), reason: None });
        r.decide(&w.roster(), &id("carol"), Verdict::Approve, Assurance::Web, web(), None, t(3)).unwrap();
        assert!(r.state.is_pending(), "bob's approval no longer counts");
        assert_eq!(
            r.decide(&w.roster(), &id("bob"), Verdict::Deny, Assurance::Web, web(), None, t(4)),
            Err(TransitionError::Inactive)
        );
        r.decide(&w.roster(), &id("dave"), Verdict::Approve, Assurance::Web, web(), None, t(5)).unwrap();
        assert_eq!(r.state, RequestState::Approved);
    }

    #[test]
    fn deny_wins_and_accepts_weak_assurance() {
        let w = World::new();
        let mut r = open(2, Assurance::FreshAuth);
        r.decide(&w.roster(), &id("bob"), Verdict::Approve, Assurance::FreshAuth, web(), None, t(1)).unwrap();
        let ev =
            r.decide(&w.roster(), &id("carol"), Verdict::Deny, Assurance::Linked, "chat".into(), None, t(2)).unwrap();
        assert_eq!(ev.last().unwrap().kind(), "denied");
        assert_eq!(r.state, RequestState::Denied);
    }

    #[test]
    fn refuses_weak_approval() {
        let w = World::new();
        let mut r = open(1, Assurance::FreshAuth);
        let before = r.clone();
        let err = r
            .decide(&w.roster(), &id("bob"), Verdict::Approve, Assurance::Linked, "chat".into(), None, t(1))
            .unwrap_err();
        assert_eq!(
            err,
            TransitionError::InsufficientAssurance { required: Assurance::FreshAuth, presented: Assurance::Linked }
        );
        assert_eq!(r, before, "failed transitions leave the request untouched");
    }

    #[test]
    fn exclusions_and_eligibility() {
        let w = World::new();
        let mut r = open(1, Assurance::Linked);
        r.facts.initiator =
            Some(Initiator { identity: "github:4".into(), display_name: None, actor: Some(id("dave")) });
        let roster = w.roster();
        assert_eq!(
            r.decide(&roster, &id("alice"), Verdict::Approve, Assurance::FreshAuth, web(), None, t(1)),
            Err(TransitionError::Excluded(Exclusion::Owners)),
            "the owner of the requesting agent"
        );
        assert_eq!(
            r.decide(&roster, &id("mallory"), Verdict::Deny, Assurance::FreshAuth, web(), None, t(1)),
            Err(TransitionError::NotEligible)
        );
        assert_eq!(
            r.decide(&roster, &id("ghost"), Verdict::Deny, Assurance::FreshAuth, web(), None, t(1)),
            Err(TransitionError::Inactive)
        );
        // Without the initiator exclusion, dave may decide; with it, not.
        r.requirements.exclude.insert(Exclusion::Initiator);
        assert_eq!(
            r.check_decision(&roster, &id("dave"), Verdict::Approve, Assurance::FreshAuth, t(1)),
            Err(TransitionError::Excluded(Exclusion::Initiator))
        );
        assert_eq!(r.potential_deciders(&roster), 2, "bob and carol");

        r.requirements.exclude.clear();
        r.decide(&roster, &id("alice"), Verdict::Approve, Assurance::FreshAuth, web(), None, t(1)).unwrap();
    }

    #[test]
    fn group_changes_apply_at_decision_time() {
        let mut w = World::new();
        let r = open(1, Assurance::Linked);
        assert!(r.eligible(&w.roster(), &id("bob")).is_ok());
        w.dir = Directory::new(
            vec![person("alice"), person("bob")],
            vec![],
            vec![GroupConfig { name: "ops".into(), members: vec!["alice".into()], from_idp: vec![] }],
            Roles::default(),
        )
        .unwrap();
        assert_eq!(r.eligible(&w.roster(), &id("bob")), Err(TransitionError::NotEligible));
    }

    #[test]
    fn pending_timeout() {
        let w = World::new();
        let mut r = open(1, Assurance::Linked);
        assert_eq!(r.expire_pending(t(299)).unwrap(), []);
        assert_eq!(
            r.decide(&w.roster(), &id("bob"), Verdict::Approve, Assurance::Linked, web(), None, t(300)),
            Err(TransitionError::PendingExpired)
        );
        r.expire_pending(t(300)).unwrap();
        assert_eq!(r.state, RequestState::Expired);
        assert!(matches!(
            r.decide(&w.roster(), &id("bob"), Verdict::Approve, Assurance::Linked, web(), None, t(301)),
            Err(TransitionError::InvalidState { state: "expired", .. })
        ));
    }

    #[test]
    fn revoke_and_failure_paths() {
        let w = World::new();
        let bob = id("bob");

        let mut r = open(1, Assurance::Linked);
        assert!(r.revoke(None, t(0)).is_err(), "nothing to revoke while pending");
        r.decide(&w.roster(), &bob, Verdict::Approve, Assurance::Linked, web(), None, t(1)).unwrap();
        r.grant_failed("boom".into(), t(2)).unwrap();
        assert!(matches!(r.state, RequestState::Failed { .. }));

        let mut r = open(1, Assurance::Linked);
        r.decide(&w.roster(), &bob, Verdict::Approve, Assurance::Linked, web(), None, t(1)).unwrap();
        r.grant_succeeded(GrantHandle { subject: r.subject.clone(), backend_ref: None, expires_at: None }, t(2))
            .unwrap();
        r.revoke(Some(bob), t(3)).unwrap();
        assert_eq!(r.state, RequestState::Revoked);

        let mut r = open(1, Assurance::Linked);
        r.withdraw(t(1)).unwrap();
        assert_eq!(r.state, RequestState::Withdrawn);

        let mut r = open(1, Assurance::Linked);
        r.fail_pending("no eligible approvers".into(), t(1)).unwrap();
        assert!(matches!(r.state, RequestState::Failed { .. }));
    }

    #[test]
    fn roundtrips_through_json() {
        let w = World::new();
        let mut r = open(1, Assurance::Web);
        r.decide(&w.roster(), &id("bob"), Verdict::Approve, Assurance::Web, web(), Some("ok".into()), t(1)).unwrap();
        let s = serde_json::to_string(&r).unwrap();
        let back: Request = serde_json::from_str(&s).unwrap();
        assert_eq!(back, r);
    }

    fn active(mode: GrantMode) -> Request {
        let w = World::new();
        let mut r = open(1, Assurance::Linked);
        r.requirements.grant = mode;
        r.decide(&w.roster(), &id("bob"), Verdict::Approve, Assurance::Linked, web(), None, t(1)).unwrap();
        r.grant_succeeded(GrantHandle { subject: r.subject.clone(), backend_ref: None, expires_at: None }, t(2))
            .unwrap();
        r
    }

    fn another(id: &str, identity: &str, target: &str) -> PendingSubject {
        let mut p = PendingSubject {
            subject: SubjectRef { backend: "oct".into(), kind: "session".into(), id: id.into() },
            facts: open(1, Assurance::Linked).facts,
            observed_at: t(0),
        };
        p.facts.requester.identity = identity.into();
        p.facts.target = Some(target.into());
        p.facts.attributes.insert("command".into(), "apt upgrade".into());
        p
    }

    #[test]
    fn window_covers_same_requester_and_target_until_it_ends() {
        let mut r = active(GrantMode::Window);
        let same = another("s2", "unix:web-1#agent", "host-1");
        assert!(r.window_covers(&same, t(100)));
        assert!(!r.window_covers(&another("s3", "unix:web-1#bob", "host-1"), t(100)));
        assert!(!r.window_covers(&another("s4", "unix:web-1#agent", "host-2"), t(100)));
        let mut other_source = same.clone();
        other_source.facts.source = Some(Source::Client("web-2".into()));
        assert!(!r.window_covers(&other_source, t(100)));
        assert!(!r.window_covers(&same, t(602)), "not after the window ends");

        r.record_use(&same, t(100)).unwrap();
        assert_eq!(r.uses.len(), 1);
        assert_eq!(r.uses[0].attributes["command"], "apt upgrade");
        let back: Request = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back, r);

        r.revoke(None, t(200)).unwrap();
        assert!(!r.window_covers(&same, t(201)));
        assert!(r.record_use(&same, t(201)).is_err());
    }

    #[test]
    fn single_use_approvals_cover_nothing_else_and_end_on_collection() {
        let mut r = active(GrantMode::Once);
        let same = another("s2", "unix:web-1#agent", "host-1");
        assert!(!r.window_covers(&same, t(100)));
        assert_eq!(r.record_use(&same, t(100)), Err(TransitionError::NotAWindow));
        assert_eq!(r.collected_at, None);
        assert_eq!(r.collect(t(3)).unwrap().len(), 1);
        assert_eq!(r.state, RequestState::Ended);
        assert_eq!(r.collected_at, Some(t(3)));
        assert!(r.collect(t(4)).is_err());

        // Running out before collection leaves it uncollected.
        let mut r = active(GrantMode::Once);
        let RequestState::Active { until } = r.state else { panic!() };
        r.end_if_elapsed(until).unwrap();
        assert_eq!((r.state.clone(), r.collected_at), (RequestState::Ended, None));
        // A window is never collected.
        assert!(active(GrantMode::Window).collect(t(3)).is_err());
    }
}
