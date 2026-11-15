//! The request state machine.
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

use std::collections::BTreeSet;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::assurance::Assurance;
use crate::backend::GrantHandle;
use crate::event::DomainEvent;
use crate::id::{ApproverId, ChannelName, RequestId};
use crate::policy::Requirements;
use crate::principal::Approver;
use crate::subject::{PendingSubject, SubjectFacts, SubjectRef};
use crate::time;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Approve,
    Deny,
}

/// One approver's decision, as recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub approver: ApproverId,
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
    #[error("approver is not eligible for this request")]
    NotEligible,
    #[error("approvers cannot decide their own requests")]
    SelfApproval,
    #[error("approval requires assurance {required}, got {presented}")]
    InsufficientAssurance { required: Assurance, presented: Assurance },
    #[error("approver has already decided")]
    AlreadyDecided,
}

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
    pub created_at: Timestamp,
    /// Decisions are refused after this instant.
    pub pending_until: Timestamp,
    pub updated_at: Timestamp,
    pub version: u64,
}

impl Request {
    /// Open a request for a pending subject under resolved requirements.
    pub fn open(pending: PendingSubject, requirements: Requirements, now: Timestamp) -> (Self, Vec<DomainEvent>) {
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
            created_at: now,
            pending_until,
            updated_at: now,
            version: 0,
        };
        (req, vec![DomainEvent::Requested { request_id: id, at: now }])
    }

    /// Approvers who have approved so far.
    pub fn approvals(&self) -> BTreeSet<&ApproverId> {
        self.decisions.iter().filter(|d| d.verdict == Verdict::Approve).map(|d| &d.approver).collect()
    }

    /// Check whether `approver` may record `verdict` at `assurance`, without
    /// changing anything. Useful to decide which actions to offer.
    pub fn check_decision(
        &self,
        approver: &Approver,
        verdict: Verdict,
        assurance: Assurance,
        now: Timestamp,
    ) -> Result<(), TransitionError> {
        self.require(RequestState::is_pending, "decide")?;
        if now >= self.pending_until {
            return Err(TransitionError::PendingExpired);
        }
        let reqs = &self.requirements;
        if !reqs.is_eligible(approver) {
            return Err(TransitionError::NotEligible);
        }
        if !reqs.allow_self_approval && approver.is_same_person_as(&self.facts.requester) {
            return Err(TransitionError::SelfApproval);
        }
        if verdict == Verdict::Approve && assurance < reqs.min_assurance {
            return Err(TransitionError::InsufficientAssurance { required: reqs.min_assurance, presented: assurance });
        }
        if self.decisions.iter().any(|d| d.approver == approver.id) {
            return Err(TransitionError::AlreadyDecided);
        }
        Ok(())
    }

    /// Record a decision. A single denial ends the request; approvals
    /// accumulate until the quorum is reached.
    pub fn decide(
        &mut self,
        approver: &Approver,
        verdict: Verdict,
        assurance: Assurance,
        via: ChannelName,
        comment: Option<String>,
        now: Timestamp,
    ) -> Result<Vec<DomainEvent>, TransitionError> {
        self.check_decision(approver, verdict, assurance, now)?;
        let decision = Decision { approver: approver.id.clone(), verdict, assurance, via, at: now, comment };
        self.decisions.push(decision.clone());
        let mut events = vec![DomainEvent::DecisionRecorded { request_id: self.id, decision }];
        match verdict {
            Verdict::Deny => {
                self.state = RequestState::Denied;
                events.push(DomainEvent::Denied { request_id: self.id, by: approver.id.clone(), at: now });
            }
            Verdict::Approve if self.approvals().len() >= usize::from(self.requirements.quorum) => {
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
    pub fn revoke(&mut self, by: Option<ApproverId>, now: Timestamp) -> Result<Vec<DomainEvent>, TransitionError> {
        self.require(|s| matches!(s, RequestState::Active { .. }), "revoke")?;
        self.state = RequestState::Revoked;
        self.touch(now);
        Ok(vec![DomainEvent::Revoked { request_id: self.id, by, at: now }])
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
    use std::collections::BTreeMap;
    use std::time::Duration;

    use super::*;
    use crate::policy::ApproverSelector;
    use crate::principal::Requester;

    fn t(secs: i64) -> Timestamp {
        Timestamp::from_second(1_800_000_000 + secs).unwrap()
    }

    fn approver(id: &str, groups: &[&str], identities: &[&str]) -> Approver {
        Approver {
            id: id.into(),
            display_name: None,
            groups: groups.iter().map(|s| (*s).to_owned()).collect(),
            identities: identities.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn open(quorum: u8, min: Assurance) -> Request {
        let pending = PendingSubject {
            subject: SubjectRef { backend: "oct".into(), kind: "session".into(), id: "s1".into() },
            facts: SubjectFacts {
                requester: Requester {
                    id: "alice-agent".into(),
                    display_name: None,
                    groups: BTreeSet::new(),
                    identities: ["oidc:alice".to_owned()].into(),
                },
                target: Some("host-1".into()),
                requested_ttl: None,
                reason: None,
                attributes: BTreeMap::new(),
            },
            observed_at: t(0),
        };
        let reqs = Requirements {
            policy: "p".into(),
            approvers: vec![ApproverSelector::Group("ops".into())],
            quorum,
            min_assurance: min,
            ttl: Duration::from_secs(600),
            pending_timeout: Duration::from_secs(300),
            allow_self_approval: false,
        };
        let (r, ev) = Request::open(pending, reqs, t(0));
        assert_eq!(ev.len(), 1);
        r
    }

    fn web() -> ChannelName {
        "web".into()
    }

    #[test]
    fn single_approval_then_grant_then_end() {
        let mut r = open(1, Assurance::FreshAuth);
        let bob = approver("bob", &["ops"], &["oidc:bob"]);
        let ev = r.decide(&bob, Verdict::Approve, Assurance::FreshAuth, web(), None, t(10)).unwrap();
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
        let mut r = open(1, Assurance::Linked);
        r.decide(&approver("bob", &["ops"], &[]), Verdict::Approve, Assurance::Linked, web(), None, t(0)).unwrap();
        let handle = GrantHandle { subject: r.subject.clone(), backend_ref: None, expires_at: Some(t(99_999)) };
        r.grant_succeeded(handle, t(0)).unwrap();
        assert_eq!(r.state, RequestState::Active { until: t(600) });
    }

    #[test]
    fn quorum_counts_distinct_approvers() {
        let mut r = open(2, Assurance::Web);
        let bob = approver("bob", &["ops"], &[]);
        let carol = approver("carol", &["ops"], &[]);
        assert_eq!(r.decide(&bob, Verdict::Approve, Assurance::Web, web(), None, t(1)).unwrap().len(), 1);
        assert!(r.state.is_pending());
        assert_eq!(
            r.decide(&bob, Verdict::Approve, Assurance::Web, web(), None, t(2)),
            Err(TransitionError::AlreadyDecided)
        );
        r.decide(&carol, Verdict::Approve, Assurance::Web, web(), None, t(3)).unwrap();
        assert_eq!(r.state, RequestState::Approved);
    }

    #[test]
    fn deny_wins_and_accepts_weak_assurance() {
        let mut r = open(2, Assurance::FreshAuth);
        r.decide(&approver("bob", &["ops"], &[]), Verdict::Approve, Assurance::FreshAuth, web(), None, t(1)).unwrap();
        let ev = r
            .decide(&approver("carol", &["ops"], &[]), Verdict::Deny, Assurance::Linked, "chat".into(), None, t(2))
            .unwrap();
        assert_eq!(ev.last().unwrap().kind(), "denied");
        assert_eq!(r.state, RequestState::Denied);
    }

    #[test]
    fn refuses_weak_approval() {
        let mut r = open(1, Assurance::FreshAuth);
        let before = r.clone();
        let err = r
            .decide(&approver("bob", &["ops"], &[]), Verdict::Approve, Assurance::Linked, "chat".into(), None, t(1))
            .unwrap_err();
        assert_eq!(
            err,
            TransitionError::InsufficientAssurance { required: Assurance::FreshAuth, presented: Assurance::Linked }
        );
        assert_eq!(r, before, "failed transitions leave the request untouched");
    }

    #[test]
    fn refuses_self_and_ineligible() {
        let mut r = open(1, Assurance::Linked);
        let alice = approver("alice", &["ops"], &["oidc:alice"]);
        assert_eq!(
            r.decide(&alice, Verdict::Approve, Assurance::FreshAuth, web(), None, t(1)),
            Err(TransitionError::SelfApproval)
        );
        let mallory = approver("mallory", &["dev"], &[]);
        assert_eq!(
            r.decide(&mallory, Verdict::Deny, Assurance::FreshAuth, web(), None, t(1)),
            Err(TransitionError::NotEligible)
        );

        r.requirements.allow_self_approval = true;
        r.decide(&alice, Verdict::Approve, Assurance::FreshAuth, web(), None, t(1)).unwrap();
    }

    #[test]
    fn pending_timeout() {
        let mut r = open(1, Assurance::Linked);
        let bob = approver("bob", &["ops"], &[]);
        assert_eq!(r.expire_pending(t(299)).unwrap(), []);
        assert_eq!(
            r.decide(&bob, Verdict::Approve, Assurance::Linked, web(), None, t(300)),
            Err(TransitionError::PendingExpired)
        );
        r.expire_pending(t(300)).unwrap();
        assert_eq!(r.state, RequestState::Expired);
        assert!(matches!(
            r.decide(&bob, Verdict::Approve, Assurance::Linked, web(), None, t(301)),
            Err(TransitionError::InvalidState { state: "expired", .. })
        ));
    }

    #[test]
    fn revoke_and_failure_paths() {
        let bob = approver("bob", &["ops"], &[]);

        let mut r = open(1, Assurance::Linked);
        assert!(r.revoke(None, t(0)).is_err(), "nothing to revoke while pending");
        r.decide(&bob, Verdict::Approve, Assurance::Linked, web(), None, t(1)).unwrap();
        r.grant_failed("boom".into(), t(2)).unwrap();
        assert!(matches!(r.state, RequestState::Failed { .. }));

        let mut r = open(1, Assurance::Linked);
        r.decide(&bob, Verdict::Approve, Assurance::Linked, web(), None, t(1)).unwrap();
        r.grant_succeeded(GrantHandle { subject: r.subject.clone(), backend_ref: None, expires_at: None }, t(2))
            .unwrap();
        r.revoke(Some("bob".into()), t(3)).unwrap();
        assert_eq!(r.state, RequestState::Revoked);

        let mut r = open(1, Assurance::Linked);
        r.withdraw(t(1)).unwrap();
        assert_eq!(r.state, RequestState::Withdrawn);
    }

    #[test]
    fn roundtrips_through_json() {
        let mut r = open(1, Assurance::Web);
        r.decide(&approver("bob", &["ops"], &[]), Verdict::Approve, Assurance::Web, web(), Some("ok".into()), t(1))
            .unwrap();
        let s = serde_json::to_string(&r).unwrap();
        let back: Request = serde_json::from_str(&s).unwrap();
        assert_eq!(back, r);
    }
}
