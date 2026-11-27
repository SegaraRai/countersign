//! People, workloads, groups and roles (see `docs/design/identity-model.md`).
//!
//! - An [`Actor`] is a person or a workload (an agent, a CI pipeline, a
//!   script). Only persons sign in and decide; workloads are owned by persons.
//! - Identities (`oidc:<issuer>#<sub>`, `unix:<host>#<user>`, ...) belong to
//!   exactly one actor. What an identity proves depends on its [`Purpose`].
//! - Groups come from the configuration, plus identity-provider groups that
//!   the configuration maps explicitly, taken from a snapshot made at sign-in.
//! - Roles say what a person may do in countersign; which requests they may
//!   decide is up to each policy.
//!
//! The configuration is the [`Directory`]; what changes at runtime
//! (suspensions, identity-provider group snapshots) is the [`Standing`],
//! read from the database. A [`Roster`] combines both at one instant.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::id::ActorId;
use crate::time;

/// What an identity proves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Purpose {
    /// Signs a person in to the web UI (`oidc:<issuer>#<sub>`). Persons only.
    SignIn,
    /// A chat account linked through the web UI. Persons only; lives in the
    /// database, never in the configuration.
    Chat,
    /// Recognises a requester or initiator in what sources report. Proves
    /// nothing about who is deciding.
    Recognition,
}

impl Purpose {
    /// The purpose of an identity written in the configuration.
    pub fn of(identity: &str) -> Self {
        if identity.starts_with("oidc:") { Self::SignIn } else { Self::Recognition }
    }
}

/// Whether `s` looks like `<provider>:<subject>`: a lowercase provider name and
/// a non-empty subject without whitespace or control characters.
pub fn is_identity(s: &str) -> bool {
    let Some((provider, subject)) = s.split_once(':') else { return false };
    !provider.is_empty()
        && provider.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !subject.is_empty()
        && s.len() <= 512
        && !s.chars().any(|c| c.is_whitespace() || c.is_control())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ActorKind {
    Person,
    /// Something automated. Its owners answer for it.
    Workload {
        owners: BTreeSet<ActorId>,
    },
}

/// A person or workload, as configured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    pub id: ActorId,
    pub kind: ActorKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub identities: BTreeSet<String>,
}

impl Actor {
    pub fn is_person(&self) -> bool {
        matches!(self.kind, ActorKind::Person)
    }

    pub fn name(&self) -> &str {
        self.display_name.as_deref().unwrap_or(self.id.as_str())
    }
}

/// `[[person]]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonConfig {
    pub id: ActorId,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub identities: Vec<String>,
}

/// `[[workload]]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadConfig {
    pub id: ActorId,
    #[serde(default)]
    pub display_name: Option<String>,
    /// Persons who answer for this workload. At least one.
    pub owners: Vec<ActorId>,
    /// Recognition identities, e.g. `unix:web-1#agent`.
    #[serde(default)]
    pub identities: Vec<String>,
}

/// An identity-provider group that counts as membership of a countersign group.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdpGroup {
    /// The provider, as in sign-in identities without the subject
    /// (`oidc:<issuer>`).
    pub provider: String,
    /// The group name in the provider's `groups` claim.
    pub group: String,
}

/// `[[group]]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupConfig {
    pub name: String,
    #[serde(default)]
    pub members: Vec<ActorId>,
    #[serde(default)]
    pub from_idp: Vec<IdpGroup>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    pub name: String,
    pub members: BTreeSet<ActorId>,
    pub from_idp: Vec<IdpGroup>,
}

/// What a person may do in countersign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// Sign in, see and decide the requests they are eligible for, link chat accounts.
    Member,
    /// Read every request (confidential content excepted).
    Auditor,
    /// Suspend and reinstate actors, revoke in bulk, unlink chat accounts.
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Auditor => "auditor",
            Self::Admin => "admin",
        }
    }
}

/// `[roles]`: who holds which role.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Roles {
    #[serde(default)]
    pub admin: Vec<Selector>,
    #[serde(default)]
    pub auditor: Vec<Selector>,
    #[serde(default)]
    pub member: Vec<Selector>,
}

impl Roles {
    fn selectors(&self, role: Role) -> &[Selector] {
        match role {
            Role::Member => &self.member,
            Role::Auditor => &self.auditor,
            Role::Admin => &self.admin,
        }
    }

    fn all(&self) -> impl Iterator<Item = &Selector> {
        self.admin.iter().chain(&self.auditor).chain(&self.member)
    }
}

/// `person:<id>` or `group:<name>`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Selector {
    Person(ActorId),
    Group(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid selector {0:?} (expected \"person:<id>\" or \"group:<name>\")")]
pub struct BadSelector(pub String);

impl FromStr for Selector {
    type Err = BadSelector;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once(':') {
            Some(("person", id)) if !id.is_empty() => Ok(Self::Person(ActorId::new(id))),
            Some(("group", g)) if !g.is_empty() => Ok(Self::Group(g.to_owned())),
            _ => Err(BadSelector(s.to_owned())),
        }
    }
}

impl TryFrom<String> for Selector {
    type Error = BadSelector;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<Selector> for String {
    fn from(s: Selector) -> Self {
        s.to_string()
    }
}

impl fmt::Display for Selector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Person(id) => write!(f, "person:{id}"),
            Self::Group(g) => write!(f, "group:{g}"),
        }
    }
}

/// Everyone countersign knows, from the configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Directory {
    actors: BTreeMap<ActorId, Actor>,
    groups: BTreeMap<String, Group>,
    roles: Roles,
    /// Identity → owner.
    identities: BTreeMap<String, ActorId>,
}

impl Directory {
    /// Build and check a directory. Returns every problem found.
    pub fn new(
        persons: Vec<PersonConfig>,
        workloads: Vec<WorkloadConfig>,
        groups: Vec<GroupConfig>,
        roles: Roles,
    ) -> Result<Self, Vec<String>> {
        let mut errors = Vec::new();
        let mut dir = Self { roles, ..Self::default() };

        let add = |dir: &mut Self, actor: Actor, errors: &mut Vec<String>| {
            if !is_name(actor.id.as_str()) {
                errors.push(format!("actor {:?}: ids are letters, digits, '-', '_' and '.'", actor.id.as_str()));
            }
            for identity in &actor.identities {
                if !is_identity(identity) {
                    errors.push(format!("{}: invalid identity {identity:?}", actor.id));
                } else if let Some(other) = dir.identities.insert(identity.clone(), actor.id.clone()) {
                    errors.push(format!("{}: identity {identity} already belongs to {other}", actor.id));
                }
            }
            if let Some(old) = dir.actors.insert(actor.id.clone(), actor) {
                errors.push(format!("{}: duplicate id (persons and workloads share one namespace)", old.id));
            }
        };

        for p in persons {
            let actor = Actor {
                id: p.id,
                kind: ActorKind::Person,
                display_name: p.display_name,
                identities: p.identities.into_iter().collect(),
            };
            add(&mut dir, actor, &mut errors);
        }
        let mut owners_of = Vec::new();
        for w in workloads {
            for identity in &w.identities {
                if Purpose::of(identity) != Purpose::Recognition {
                    errors
                        .push(format!("workload {}: {identity} is a sign-in identity; workloads never sign in", w.id));
                }
            }
            if w.owners.is_empty() {
                errors.push(format!("workload {}: needs at least one owner", w.id));
            }
            owners_of.push((w.id.clone(), w.owners.clone()));
            let actor = Actor {
                id: w.id,
                kind: ActorKind::Workload { owners: w.owners.into_iter().collect() },
                display_name: w.display_name,
                identities: w.identities.into_iter().collect(),
            };
            add(&mut dir, actor, &mut errors);
        }
        for (workload, owners) in owners_of {
            for o in owners {
                if !dir.actors.get(&o).is_some_and(Actor::is_person) {
                    errors.push(format!("workload {workload}: owner {o} is not a person"));
                }
            }
        }

        for g in groups {
            if !is_name(&g.name) {
                errors.push(format!("group {:?}: names are letters, digits, '-', '_' and '.'", g.name));
            }
            for m in &g.members {
                if !dir.actors.contains_key(m) {
                    errors.push(format!("group {}: unknown member {m}", g.name));
                }
            }
            for idp in &g.from_idp {
                if !idp.provider.starts_with("oidc:") || idp.group.is_empty() {
                    errors.push(format!("group {}: from_idp needs provider = \"oidc:<issuer>\" and a group", g.name));
                }
            }
            let group = Group { name: g.name.clone(), members: g.members.into_iter().collect(), from_idp: g.from_idp };
            if dir.groups.insert(g.name.clone(), group).is_some() {
                errors.push(format!("group {}: duplicate name", g.name));
            }
        }

        for sel in dir.roles.all() {
            if let Some(problem) = dir.selector_problem(sel) {
                errors.push(format!("roles: {problem}"));
            }
        }

        if errors.is_empty() { Ok(dir) } else { Err(errors) }
    }

    /// Why a selector cannot select anyone, if so.
    pub fn selector_problem(&self, sel: &Selector) -> Option<String> {
        match sel {
            Selector::Person(id) => match self.actors.get(id) {
                Some(a) if a.is_person() => None,
                Some(_) => Some(format!("{sel}: {id} is a workload; only persons decide")),
                None => Some(format!("{sel}: unknown person {id}")),
            },
            Selector::Group(g) => match self.groups.get(g) {
                None => Some(format!("{sel}: unknown group {g}")),
                Some(group)
                    if group.from_idp.is_empty()
                        && !group.members.iter().any(|m| self.actors.get(m).is_some_and(Actor::is_person)) =>
                {
                    Some(format!("{sel}: no person is in group {g}"))
                }
                Some(_) => None,
            },
        }
    }

    pub fn actor(&self, id: &ActorId) -> Option<&Actor> {
        self.actors.get(id)
    }

    pub fn actors(&self) -> impl Iterator<Item = &Actor> {
        self.actors.values()
    }

    pub fn persons(&self) -> impl Iterator<Item = &Actor> {
        self.actors.values().filter(|a| a.is_person())
    }

    pub fn group(&self, name: &str) -> Option<&Group> {
        self.groups.get(name)
    }

    pub fn groups(&self) -> impl Iterator<Item = &Group> {
        self.groups.values()
    }

    pub fn roles(&self) -> &Roles {
        &self.roles
    }

    /// The actor an identity belongs to, if the identity has `purpose`.
    pub fn by_identity(&self, identity: &str, purpose: Purpose) -> Option<&Actor> {
        if Purpose::of(identity) != purpose {
            return None;
        }
        let actor = self.actors.get(self.identities.get(identity)?)?;
        // Sign-in identities only ever authenticate persons.
        (purpose != Purpose::SignIn || actor.is_person()).then_some(actor)
    }

    /// Groups the configuration puts `id` in.
    pub fn config_groups(&self, id: &ActorId) -> BTreeSet<String> {
        self.groups.values().filter(|g| g.members.contains(id)).map(|g| g.name.clone()).collect()
    }

    /// countersign groups an identity-provider snapshot maps to.
    pub fn mapped_groups(&self, snapshot: &IdpSnapshot) -> BTreeSet<String> {
        self.groups
            .values()
            .filter(|g| {
                g.from_idp.iter().any(|m| m.provider == snapshot.provider && snapshot.groups.contains(&m.group))
            })
            .map(|g| g.name.clone())
            .collect()
    }
}

/// Actor ids, group names and client ids: ASCII letters, digits, `-`, `_` and `.`.
pub fn is_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with(['-', '.'])
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// An admin's suspension of an actor. Overrides the configuration until
/// lifted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suspension {
    pub since: Timestamp,
    pub by: ActorId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Identity-provider groups reported at a person's latest sign-in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdpSnapshot {
    /// `oidc:<issuer>`.
    pub provider: String,
    pub groups: BTreeSet<String>,
    pub at: Timestamp,
}

/// What changes at runtime, from the database.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Standing {
    pub suspended: BTreeMap<ActorId, Suspension>,
    pub idp: BTreeMap<ActorId, IdpSnapshot>,
}

/// Directory and standing at one instant: who is active, in which groups,
/// with which roles.
#[derive(Debug, Clone, Copy)]
pub struct Roster<'a> {
    pub directory: &'a Directory,
    pub standing: &'a Standing,
    pub now: Timestamp,
    /// How long an identity-provider group snapshot counts.
    pub idp_max_age: Duration,
}

impl<'a> Roster<'a> {
    /// Configured and not suspended. A workload also needs an active owner.
    pub fn is_active(&self, id: &ActorId) -> bool {
        let Some(actor) = self.directory.actor(id) else { return false };
        if self.standing.suspended.contains_key(id) {
            return false;
        }
        match &actor.kind {
            ActorKind::Person => true,
            ActorKind::Workload { owners } => owners.iter().any(|o| {
                self.directory.actor(o).is_some_and(Actor::is_person) && !self.standing.suspended.contains_key(o)
            }),
        }
    }

    /// The actor, if it is an active person.
    pub fn active_person(&self, id: &ActorId) -> Option<&'a Actor> {
        self.directory.actor(id).filter(|a| a.is_person() && self.is_active(id))
    }

    /// Current groups: from the configuration, plus mapped identity-provider
    /// groups while the snapshot is recent enough.
    pub fn groups(&self, id: &ActorId) -> BTreeSet<String> {
        let mut groups = self.directory.config_groups(id);
        if let Some(snap) = self.standing.idp.get(id)
            && self.now < time::add(snap.at, self.idp_max_age)
        {
            groups.extend(self.directory.mapped_groups(snap));
        }
        groups
    }

    /// Whether `id` could be in `group` after signing in again: configured,
    /// or mapped from any snapshot however old.
    fn could_be_in(&self, id: &ActorId, group: &str) -> bool {
        self.directory.group(group).is_some_and(|g| g.members.contains(id))
            || self.standing.idp.get(id).is_some_and(|s| self.directory.mapped_groups(s).contains(group))
    }

    pub fn selects(&self, sel: &Selector, id: &ActorId) -> bool {
        match sel {
            Selector::Person(p) => p == id,
            Selector::Group(g) => self.groups(id).contains(g),
        }
    }

    /// Whether any selector selects `id` now.
    pub fn selected(&self, selectors: &[Selector], id: &ActorId) -> bool {
        let groups = self.groups(id);
        selectors.iter().any(|s| match s {
            Selector::Person(p) => p == id,
            Selector::Group(g) => groups.contains(g),
        })
    }

    /// Whether any selector could select `id` (see [`Self::could_be_in`]).
    pub fn could_be_selected(&self, selectors: &[Selector], id: &ActorId) -> bool {
        selectors.iter().any(|s| match s {
            Selector::Person(p) => p == id,
            Selector::Group(g) => self.could_be_in(id, g),
        })
    }

    /// Whether an active person holds `role`.
    pub fn has_role(&self, id: &ActorId, role: Role) -> bool {
        self.active_person(id).is_some() && self.selected(self.directory.roles.selectors(role), id)
    }

    /// Roles an active person holds.
    pub fn roles(&self, id: &ActorId) -> BTreeSet<Role> {
        [Role::Member, Role::Auditor, Role::Admin].into_iter().filter(|r| self.has_role(id, *r)).collect()
    }

    /// Owners of a workload (none for persons and unknown actors).
    pub fn owners(&self, id: &ActorId) -> BTreeSet<ActorId> {
        match self.directory.actor(id).map(|a| &a.kind) {
            Some(ActorKind::Workload { owners }) => owners.clone(),
            _ => BTreeSet::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> Directory {
        Directory::new(
            vec![
                PersonConfig {
                    id: "alice".into(),
                    display_name: Some("Alice".into()),
                    identities: vec!["oidc:https://id.example.com#a".into(), "github:1".into()],
                },
                PersonConfig { id: "bob".into(), display_name: None, identities: vec![] },
            ],
            vec![WorkloadConfig {
                id: "agent".into(),
                display_name: None,
                owners: vec!["alice".into()],
                identities: vec!["unix:web-1#agent".into()],
            }],
            vec![
                GroupConfig { name: "ops".into(), members: vec!["bob".into()], from_idp: vec![] },
                GroupConfig {
                    name: "sec".into(),
                    members: vec![],
                    from_idp: vec![IdpGroup {
                        provider: "oidc:https://id.example.com".into(),
                        group: "security".into(),
                    }],
                },
            ],
            Roles {
                admin: vec![Selector::Person("alice".into())],
                auditor: vec![Selector::Group("sec".into())],
                member: vec![Selector::Group("ops".into()), Selector::Person("alice".into())],
            },
        )
        .unwrap()
    }

    fn at(s: i64) -> Timestamp {
        Timestamp::from_second(1_800_000_000 + s).unwrap()
    }

    #[test]
    fn identities_resolve_only_for_their_purpose() {
        let d = dir();
        assert_eq!(d.by_identity("oidc:https://id.example.com#a", Purpose::SignIn).unwrap().id.as_str(), "alice");
        assert!(d.by_identity("oidc:https://id.example.com#a", Purpose::Recognition).is_none());
        assert_eq!(d.by_identity("unix:web-1#agent", Purpose::Recognition).unwrap().id.as_str(), "agent");
        assert!(d.by_identity("unix:web-1#agent", Purpose::SignIn).is_none());
        assert!(d.by_identity("unix:web-1#root", Purpose::Recognition).is_none());
    }

    #[test]
    fn idp_groups_count_only_while_fresh_and_mapped() {
        let d = dir();
        let mut standing = Standing::default();
        standing.idp.insert(
            "bob".into(),
            IdpSnapshot {
                provider: "oidc:https://id.example.com".into(),
                groups: ["security".to_owned(), "unmapped".to_owned()].into(),
                at: at(0),
            },
        );
        let r = |now| Roster { directory: &d, standing: &standing, now, idp_max_age: Duration::from_secs(3600) };
        assert_eq!(r(at(10)).groups(&"bob".into()), ["ops".to_owned(), "sec".to_owned()].into());
        assert!(r(at(10)).has_role(&"bob".into(), Role::Auditor));
        assert_eq!(r(at(3600)).groups(&"bob".into()), ["ops".to_owned()].into(), "stale snapshot");
        assert!(r(at(3600)).could_be_selected(&[Selector::Group("sec".into())], &"bob".into()));
    }

    #[test]
    fn suspension_and_owners() {
        let d = dir();
        let mut standing = Standing::default();
        let r = Roster { directory: &d, standing: &standing, now: at(0), idp_max_age: Duration::from_secs(60) };
        assert!(r.is_active(&"agent".into()));
        assert_eq!(r.owners(&"agent".into()), ["alice".into()].into());
        assert!(r.roles(&"alice".into()).contains(&Role::Admin));

        standing.suspended.insert("alice".into(), Suspension { since: at(0), by: "alice".into(), reason: None });
        let r = Roster { directory: &d, standing: &standing, now: at(0), idp_max_age: Duration::from_secs(60) };
        assert!(!r.is_active(&"alice".into()));
        assert!(!r.is_active(&"agent".into()), "a workload without an active owner is suspended too");
        assert!(r.roles(&"alice".into()).is_empty());
        assert!(!r.is_active(&"ghost".into()));
    }

    #[test]
    fn rejects_bad_directories() {
        let errs = Directory::new(
            vec![PersonConfig { id: "a".into(), display_name: None, identities: vec!["x:1".into()] }],
            vec![
                WorkloadConfig {
                    id: "a".into(),
                    display_name: None,
                    owners: vec![],
                    identities: vec!["x:1".into(), "oidc:https://i#s".into()],
                },
                WorkloadConfig {
                    id: "w".into(),
                    display_name: None,
                    owners: vec!["nobody".into()],
                    identities: vec![],
                },
            ],
            vec![GroupConfig { name: "g".into(), members: vec!["ghost".into()], from_idp: vec![] }],
            Roles { admin: vec![Selector::Group("missing".into())], ..Roles::default() },
        )
        .unwrap_err()
        .join("\n");
        for needle in [
            "already belongs",
            "duplicate id",
            "sign-in identity",
            "at least one owner",
            "owner nobody is not a person",
            "unknown member ghost",
            "unknown group missing",
        ] {
            assert!(errs.contains(needle), "missing {needle:?} in:\n{errs}");
        }
    }

    #[test]
    fn selectors_parse() {
        assert_eq!("person:a".parse::<Selector>().unwrap(), Selector::Person("a".into()));
        assert_eq!("group:g".parse::<Selector>().unwrap(), Selector::Group("g".into()));
        assert!("approver:a".parse::<Selector>().is_err());
        assert!("group:".parse::<Selector>().is_err());
    }
}
