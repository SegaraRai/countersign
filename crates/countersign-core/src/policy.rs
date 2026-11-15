//! Which requests need whose approval, at what assurance, for how long.
//!
//! Policies are evaluated in order; the first match wins. A subject that
//! matches no policy cannot be approved at all (deny by default).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::assurance::Assurance;
use crate::glob;
use crate::id::{ApproverId, BackendName, PolicyName};
use crate::principal::Approver;
use crate::subject::PendingSubject;

const DEFAULT_PENDING_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// A set of ordered policy rules, typically read from `[[policy]]` tables.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySet {
    #[serde(default, rename = "policy")]
    pub policies: Vec<Policy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub name: PolicyName,
    #[serde(default, rename = "match")]
    pub matcher: Matcher,
    /// Who may decide. At least one entry is required.
    pub approvers: Vec<ApproverSelector>,
    /// Number of distinct approvals required. A single denial always wins.
    #[serde(default = "one")]
    pub quorum: u8,
    /// Upper bound on the grant duration.
    #[serde(with = "humantime_serde")]
    pub max_ttl: Duration,
    /// Used when the requester does not ask for a duration. Defaults to `max_ttl`.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "humantime_serde")]
    pub default_ttl: Option<Duration>,
    /// Minimum assurance for an approval. Defaults to the strongest level.
    #[serde(default = "strongest")]
    pub min_assurance: Assurance,
    /// How long a request may stay undecided.
    #[serde(default = "default_pending_timeout", with = "humantime_serde")]
    pub pending_timeout: Duration,
    /// Let the requester approve their own request. Off by default.
    #[serde(default)]
    pub allow_self_approval: bool,
    /// What an approval covers. Only meaningful for backends whose subjects
    /// are submitted to countersign (such as `sudo` invocations).
    #[serde(default)]
    pub grant: GrantMode,
}

/// What an approval covers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GrantMode {
    /// The one subject that was approved.
    #[default]
    Once,
    /// While active, later submissions from the same requester and target
    /// that match the same policy are approved without asking again.
    Window,
}

impl GrantMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Once => "once",
            Self::Window => "window",
        }
    }
}

fn one() -> u8 {
    1
}
fn strongest() -> Assurance {
    Assurance::FreshAuth
}
fn default_pending_timeout() -> Duration {
    DEFAULT_PENDING_TIMEOUT
}

/// Conditions on a pending subject. Omitted fields match anything; string
/// values support `*` and `?` globs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matcher {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<BackendName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Glob on [`crate::Requester::id`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester: Option<String>,
    /// The requester must be in this group (exact match).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_group: Option<String>,
    /// Glob on [`crate::SubjectFacts::target`]; an absent target never matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Globs on backend attributes; an absent attribute never matches.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
}

impl Matcher {
    pub fn matches(&self, p: &PendingSubject) -> bool {
        let facts = &p.facts;
        self.backend.as_ref().is_none_or(|b| *b == p.subject.backend)
            && self.kind.as_deref().is_none_or(|k| glob::matches(k, &p.subject.kind))
            && self.requester.as_deref().is_none_or(|r| glob::matches(r, &facts.requester.id))
            && self.requester_group.as_ref().is_none_or(|g| facts.requester.groups.contains(g))
            && self.target.as_deref().is_none_or(|t| facts.target.as_deref().is_some_and(|v| glob::matches(t, v)))
            && self.attributes.iter().all(|(k, pat)| facts.attributes.get(k).is_some_and(|v| glob::matches(pat, v)))
    }
}

/// `approver:<id>` or `group:<name>`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum ApproverSelector {
    Approver(ApproverId),
    Group(String),
}

impl ApproverSelector {
    pub fn selects(&self, approver: &Approver) -> bool {
        match self {
            Self::Approver(id) => *id == approver.id,
            Self::Group(g) => approver.groups.contains(g),
        }
    }
}

impl FromStr for ApproverSelector {
    type Err = PolicyError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once(':') {
            Some(("approver", id)) if !id.is_empty() => Ok(Self::Approver(ApproverId::new(id))),
            Some(("group", g)) if !g.is_empty() => Ok(Self::Group(g.to_owned())),
            _ => Err(PolicyError::BadSelector(s.to_owned())),
        }
    }
}

impl TryFrom<String> for ApproverSelector {
    type Error = PolicyError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<ApproverSelector> for String {
    fn from(s: ApproverSelector) -> Self {
        s.to_string()
    }
}

impl fmt::Display for ApproverSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approver(id) => write!(f, "approver:{id}"),
            Self::Group(g) => write!(f, "group:{g}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid approver selector {0:?} (expected \"approver:<id>\" or \"group:<name>\")")]
    BadSelector(String),
    #[error("policy {0}: duplicate name")]
    DuplicateName(PolicyName),
    #[error("policy {0}: no approvers")]
    NoApprovers(PolicyName),
    #[error("policy {0}: quorum must be at least 1")]
    ZeroQuorum(PolicyName),
    #[error("policy {0}: quorum exceeds the number of approver entries that could satisfy it")]
    UnreachableQuorum(PolicyName),
    #[error("policy {0}: max_ttl must be greater than zero")]
    ZeroTtl(PolicyName),
    #[error("policy {0}: default_ttl exceeds max_ttl")]
    DefaultExceedsMax(PolicyName),
}

/// Requirements resolved for one request, snapshotted when it is opened so
/// later policy edits do not change decisions already in flight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Requirements {
    pub policy: PolicyName,
    pub approvers: Vec<ApproverSelector>,
    pub quorum: u8,
    pub min_assurance: Assurance,
    #[serde(with = "humantime_serde")]
    pub ttl: Duration,
    #[serde(with = "humantime_serde")]
    pub pending_timeout: Duration,
    pub allow_self_approval: bool,
    #[serde(default)]
    pub grant: GrantMode,
}

impl Requirements {
    pub fn is_eligible(&self, approver: &Approver) -> bool {
        self.approvers.iter().any(|s| s.selects(approver))
    }
}

impl Policy {
    /// Effective grant duration for a requested one.
    pub fn resolve_ttl(&self, requested: Option<Duration>) -> Duration {
        match requested {
            Some(d) if !d.is_zero() => d.min(self.max_ttl),
            _ => self.default_ttl.unwrap_or(self.max_ttl).min(self.max_ttl),
        }
    }

    pub fn requirements_for(&self, p: &PendingSubject) -> Requirements {
        Requirements {
            policy: self.name.clone(),
            approvers: self.approvers.clone(),
            quorum: self.quorum,
            min_assurance: self.min_assurance,
            ttl: self.resolve_ttl(p.facts.requested_ttl),
            pending_timeout: self.pending_timeout,
            allow_self_approval: self.allow_self_approval,
            grant: self.grant,
        }
    }

    fn validate(&self) -> Result<(), PolicyError> {
        let name = || self.name.clone();
        if self.approvers.is_empty() {
            return Err(PolicyError::NoApprovers(name()));
        }
        if self.quorum == 0 {
            return Err(PolicyError::ZeroQuorum(name()));
        }
        // Each `approver:` entry contributes at most one approval; a group may
        // contribute many, so only an all-individuals list can be checked.
        let only_individuals = self.approvers.iter().all(|s| matches!(s, ApproverSelector::Approver(_)));
        if only_individuals {
            let distinct: BTreeSet<_> = self.approvers.iter().collect();
            if usize::from(self.quorum) > distinct.len() {
                return Err(PolicyError::UnreachableQuorum(name()));
            }
        }
        if self.max_ttl.is_zero() {
            return Err(PolicyError::ZeroTtl(name()));
        }
        if self.default_ttl.is_some_and(|d| d > self.max_ttl) {
            return Err(PolicyError::DefaultExceedsMax(name()));
        }
        Ok(())
    }
}

impl PolicySet {
    /// Check every policy, returning all problems found.
    pub fn validate(&self) -> Result<(), Vec<PolicyError>> {
        let mut errors = Vec::new();
        let mut seen = BTreeSet::new();
        for p in &self.policies {
            if !seen.insert(&p.name) {
                errors.push(PolicyError::DuplicateName(p.name.clone()));
            }
            if let Err(e) = p.validate() {
                errors.push(e);
            }
        }
        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }

    /// The first policy matching `p`, if any.
    pub fn find(&self, p: &PendingSubject) -> Option<&Policy> {
        self.policies.iter().find(|pol| pol.matcher.matches(p))
    }

    /// Requirements for `p`, or `None` if no policy matches (deny by default).
    pub fn evaluate(&self, p: &PendingSubject) -> Option<Requirements> {
        self.find(p).map(|pol| pol.requirements_for(p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::principal::Requester;
    use crate::subject::{SubjectFacts, SubjectRef};

    const EXAMPLE: &str = r#"
        [[policy]]
        name = "elevated-agents"
        match = { backend = "oct", requester_group = "agents-elevated" }
        approvers = ["group:approvers"]
        max_ttl = "30m"
        default_ttl = "10m"

        [[policy]]
        name = "staging"
        match = { backend = "exec-sudo", target = "staging-*" }
        approvers = ["approver:alice", "approver:bob"]
        quorum = 2
        max_ttl = "2h"
        min_assurance = "linked"
    "#;

    fn set() -> PolicySet {
        toml::from_str(EXAMPLE).unwrap()
    }

    fn pending(backend: &str, groups: &[&str], target: Option<&str>, ttl: Option<Duration>) -> PendingSubject {
        PendingSubject {
            subject: SubjectRef { backend: backend.into(), kind: "session".into(), id: "s1".into() },
            facts: SubjectFacts {
                requester: Requester {
                    id: "agent-1".into(),
                    display_name: None,
                    groups: groups.iter().map(|g| (*g).to_owned()).collect(),
                    identities: BTreeSet::new(),
                },
                target: target.map(str::to_owned),
                requested_ttl: ttl,
                reason: None,
                attributes: BTreeMap::new(),
            },
            observed_at: jiff::Timestamp::UNIX_EPOCH,
        }
    }

    #[test]
    fn parses_and_validates_example() {
        let s = set();
        assert_eq!(s.policies.len(), 2);
        assert_eq!(s.policies[0].min_assurance, Assurance::FreshAuth, "secure default");
        assert_eq!(s.policies[0].quorum, 1);
        assert_eq!(s.policies[0].pending_timeout, DEFAULT_PENDING_TIMEOUT);
        assert_eq!(s.policies[1].approvers[0], ApproverSelector::Approver("alice".into()));
        s.validate().unwrap();
    }

    #[test]
    fn first_match_wins_and_unmatched_is_none() {
        let s = set();
        let r = s.evaluate(&pending("oct", &["agents-elevated"], None, None)).unwrap();
        assert_eq!(r.policy.as_str(), "elevated-agents");
        assert_eq!(r.ttl, Duration::from_secs(600));

        let r = s.evaluate(&pending("exec-sudo", &[], Some("staging-web"), None)).unwrap();
        assert_eq!(r.policy.as_str(), "staging");
        assert_eq!(r.quorum, 2);

        assert!(s.evaluate(&pending("oct", &["agents"], None, None)).is_none());
        assert!(s.evaluate(&pending("exec-sudo", &[], Some("prod-web"), None)).is_none());
        assert!(s.evaluate(&pending("exec-sudo", &[], None, None)).is_none(), "absent target never matches");
    }

    #[test]
    fn ttl_is_clamped() {
        let s = set();
        let pol = &s.policies[0];
        assert_eq!(pol.resolve_ttl(Some(Duration::from_secs(3600 * 5))), Duration::from_secs(1800));
        assert_eq!(pol.resolve_ttl(Some(Duration::from_secs(60))), Duration::from_secs(60));
        assert_eq!(pol.resolve_ttl(Some(Duration::ZERO)), Duration::from_secs(600));
        assert_eq!(pol.resolve_ttl(None), Duration::from_secs(600));
    }

    #[test]
    fn rejects_bad_policies() {
        let bad = r#"
            [[policy]]
            name = "a"
            approvers = []
            max_ttl = "1m"

            [[policy]]
            name = "a"
            approvers = ["approver:x"]
            quorum = 2
            max_ttl = "1m"
            default_ttl = "5m"
        "#;
        let errs = toml::from_str::<PolicySet>(bad).unwrap().validate().unwrap_err();
        assert!(errs.contains(&PolicyError::NoApprovers("a".into())));
        assert!(errs.contains(&PolicyError::DuplicateName("a".into())));
        assert!(errs.contains(&PolicyError::UnreachableQuorum("a".into())));
    }

    #[test]
    fn rejects_bad_selector_and_unknown_fields() {
        let e = toml::from_str::<PolicySet>("[[policy]]\nname='x'\napprovers=['alice']\nmax_ttl='1m'\n");
        assert!(e.is_err());
        let e = toml::from_str::<PolicySet>(
            "[[policy]]\nname='x'\napprovers=['group:g']\nmax_ttl='1m'\nmin_assurence='web'\n",
        );
        assert!(e.is_err(), "typos must not silently fall back to defaults");
    }
}
