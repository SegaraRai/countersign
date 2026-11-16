//! Which requests need whose approval, at what assurance, for how long.
//!
//! Policies are evaluated in order; the first match wins. A subject that
//! matches no policy cannot be approved at all (deny by default).

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::actor::Selector;
use crate::assurance::Assurance;
use crate::glob;
use crate::id::{BackendName, PolicyName};
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
    /// Who may decide (`person:<id>`, `group:<name>`). At least one entry.
    pub approvers: Vec<Selector>,
    /// Who may not decide although selected. Defaults to the requester.
    #[serde(default = "default_exclude")]
    pub exclude: BTreeSet<Exclusion>,
    /// Refuse requests whose source does not name the person who caused them.
    #[serde(default)]
    pub require_initiator: bool,
    /// Number of distinct persons who must approve. A single denial always wins.
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
    /// What an approval covers. Only meaningful for backends whose subjects
    /// are submitted to countersign (such as `sudo` invocations).
    #[serde(default)]
    pub grant: GrantMode,
    /// Whether requests may be kept out of chat channels.
    #[serde(default)]
    pub sensitive: SensitiveMode,
}

/// Relations to the request that disqualify a decider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Exclusion {
    /// The requester themself (or a person sharing an identity with it).
    Requester,
    /// The owners of the requesting workload.
    Owners,
    /// The person who caused the request.
    Initiator,
}

fn default_exclude() -> BTreeSet<Exclusion> {
    BTreeSet::from([Exclusion::Requester])
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

/// Whether a request's details are shown in chat channels.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SensitiveMode {
    /// Follow the requester's flag.
    #[default]
    Honor,
    /// Always show the details in chat.
    Ignore,
    /// Never show this policy's details in chat.
    Always,
}

impl SensitiveMode {
    pub fn resolve(self, requested: bool) -> bool {
        match self {
            Self::Honor => requested,
            Self::Ignore => false,
            Self::Always => true,
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
    /// The client or backend that delivered the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<BackendName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Glob on the requester's actor id; an unresolved requester never matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester: Option<String>,
    /// Glob on the requester's identity (`unix:web-1#agent`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_identity: Option<String>,
    /// The requester must be in this countersign group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_group: Option<String>,
    /// The source must report the requester in this group (exact match).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_group: Option<String>,
    /// Glob on [`crate::SubjectFacts::target`]; an absent target never matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Globs on backend attributes; an absent attribute never matches.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
}

impl Matcher {
    /// `requester_groups` are the countersign groups of the resolved requester.
    pub fn matches(&self, p: &PendingSubject, requester_groups: &BTreeSet<String>) -> bool {
        let facts = &p.facts;
        let requester = &facts.requester;
        self.source.as_deref().is_none_or(|s| facts.source.as_ref().is_some_and(|src| glob::matches(s, src.name())))
            && self.backend.as_ref().is_none_or(|b| *b == p.subject.backend)
            && self.kind.as_deref().is_none_or(|k| glob::matches(k, &p.subject.kind))
            && self
                .requester
                .as_deref()
                .is_none_or(|r| requester.actor.as_ref().is_some_and(|a| glob::matches(r, a.as_str())))
            && self.requester_identity.as_deref().is_none_or(|r| glob::matches(r, &requester.identity))
            && self.requester_group.as_ref().is_none_or(|g| requester_groups.contains(g))
            && self.backend_group.as_ref().is_none_or(|g| requester.groups.contains(g))
            && self.target.as_deref().is_none_or(|t| facts.target.as_deref().is_some_and(|v| glob::matches(t, v)))
            && self.attributes.iter().all(|(k, pat)| facts.attributes.get(k).is_some_and(|v| glob::matches(pat, v)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
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

/// Requirements resolved for one request, frozen when it is opened so later
/// policy edits cannot make it easier to approve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Requirements {
    pub policy: PolicyName,
    pub approvers: Vec<Selector>,
    #[serde(default = "default_exclude")]
    pub exclude: BTreeSet<Exclusion>,
    pub quorum: u8,
    pub min_assurance: Assurance,
    #[serde(with = "humantime_serde")]
    pub ttl: Duration,
    #[serde(with = "humantime_serde")]
    pub pending_timeout: Duration,
    #[serde(default)]
    pub grant: GrantMode,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub require_initiator: bool,
    /// The attribute globs the policy matched on (e.g. `command = "apt*"`):
    /// for a window, what later subjects must match to be covered.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub scope: BTreeMap<String, String>,
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
            exclude: self.exclude.clone(),
            quorum: self.quorum,
            min_assurance: self.min_assurance,
            ttl: self.resolve_ttl(p.facts.requested_ttl),
            pending_timeout: self.pending_timeout,
            grant: self.grant,
            require_initiator: self.require_initiator,
            scope: self.matcher.attributes.clone(),
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
        // Each `person:` entry contributes at most one approval; a group may
        // contribute many, so only an all-persons list can be checked.
        let only_persons = self.approvers.iter().all(|s| matches!(s, Selector::Person(_)));
        if only_persons {
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
    pub fn find(&self, p: &PendingSubject, requester_groups: &BTreeSet<String>) -> Option<&Policy> {
        self.policies.iter().find(|pol| pol.matcher.matches(p, requester_groups))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subject::{Requester, Source, SubjectFacts, SubjectRef};

    const EXAMPLE: &str = r#"
        [[policy]]
        name = "elevated-agents"
        match = { backend = "oct", backend_group = "agents-elevated" }
        approvers = ["group:approvers"]
        max_ttl = "30m"
        default_ttl = "10m"

        [[policy]]
        name = "staging"
        match = { source = "web-*", requester = "agent-*", target = "staging-*" }
        approvers = ["person:alice", "person:bob"]
        exclude = ["requester", "owners"]
        quorum = 2
        max_ttl = "2h"
        min_assurance = "linked"
    "#;

    fn set() -> PolicySet {
        toml::from_str(EXAMPLE).unwrap()
    }

    fn pending(backend: &str, groups: &[&str], target: Option<&str>, ttl: Option<Duration>) -> PendingSubject {
        let mut facts = SubjectFacts::new(Requester {
            id: "agent".into(),
            groups: groups.iter().map(|g| (*g).to_owned()).collect(),
            identity: "unix:web-1#agent".into(),
            actor: Some("agent-ops".into()),
            ..Requester::default()
        });
        facts.source = Some(Source::Client("web-1".into()));
        facts.target = target.map(str::to_owned);
        facts.requested_ttl = ttl;
        PendingSubject {
            subject: SubjectRef { backend: backend.into(), kind: "session".into(), id: "s1".into() },
            facts,
            observed_at: jiff::Timestamp::UNIX_EPOCH,
        }
    }

    fn eval(s: &PolicySet, p: &PendingSubject) -> Option<Requirements> {
        s.find(p, &BTreeSet::new()).map(|pol| pol.requirements_for(p))
    }

    #[test]
    fn parses_and_validates_example() {
        let s = set();
        assert_eq!(s.policies.len(), 2);
        assert_eq!(s.policies[0].min_assurance, Assurance::FreshAuth, "secure default");
        assert_eq!(s.policies[0].quorum, 1);
        assert_eq!(s.policies[0].exclude, BTreeSet::from([Exclusion::Requester]), "self-approval is off by default");
        assert_eq!(s.policies[0].pending_timeout, DEFAULT_PENDING_TIMEOUT);
        assert_eq!(s.policies[1].approvers[0], Selector::Person("alice".into()));
        s.validate().unwrap();
    }

    #[test]
    fn first_match_wins_and_unmatched_is_none() {
        let s = set();
        let r = eval(&s, &pending("oct", &["agents-elevated"], None, None)).unwrap();
        assert_eq!(r.policy.as_str(), "elevated-agents");
        assert_eq!(r.ttl, Duration::from_secs(600));

        let r = eval(&s, &pending("host", &[], Some("staging-web"), None)).unwrap();
        assert_eq!(r.policy.as_str(), "staging");
        assert_eq!(r.quorum, 2);

        assert!(eval(&s, &pending("oct", &["agents"], None, None)).is_none());
        assert!(eval(&s, &pending("host", &[], Some("prod-web"), None)).is_none());
        assert!(eval(&s, &pending("host", &[], None, None)).is_none(), "absent target never matches");

        let mut unresolved = pending("host", &[], Some("staging-web"), None);
        unresolved.facts.requester.actor = None;
        assert!(eval(&s, &unresolved).is_none(), "requester globs need a resolved requester");
    }

    #[test]
    fn requester_groups_come_from_countersign() {
        let s: PolicySet = toml::from_str(
            "[[policy]]\nname='p'\nmatch={requester_group='agents'}\napprovers=['group:g']\nmax_ttl='1m'\n",
        )
        .unwrap();
        let p = pending("host", &["agents"], None, None);
        assert!(s.find(&p, &BTreeSet::new()).is_none(), "source-reported groups are not countersign groups");
        assert!(s.find(&p, &BTreeSet::from(["agents".to_owned()])).is_some());
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
            approvers = ["person:x"]
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
        let e = toml::from_str::<PolicySet>("[[policy]]\nname='x'\napprovers=['approver:a']\nmax_ttl='1m'\n");
        assert!(e.is_err(), "the old selector form is gone");
        let e = toml::from_str::<PolicySet>(
            "[[policy]]\nname='x'\napprovers=['group:g']\nmax_ttl='1m'\nmin_assurence='web'\n",
        );
        assert!(e.is_err(), "typos must not silently fall back to defaults");
        let e = toml::from_str::<PolicySet>(
            "[[policy]]\nname='x'\napprovers=['group:g']\nmax_ttl='1m'\nallow_self_approval=true\n",
        );
        assert!(e.is_err(), "self-approval is configured through exclude now");
    }

    #[test]
    fn sensitive_modes() {
        assert!(SensitiveMode::Honor.resolve(true));
        assert!(!SensitiveMode::Honor.resolve(false));
        assert!(!SensitiveMode::Ignore.resolve(true));
        assert!(SensitiveMode::Always.resolve(false));
    }
}
