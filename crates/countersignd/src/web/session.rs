//! Sessions, sign-in destinations and who may see what.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use axum_extra::extract::PrivateCookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};
use tracing::warn;

use countersign_core::question::REMOVED;
use countersign_core::{ActorId, Assurance, Purpose, Question, QuestionOutcome, Request, Role, Roster, Standing};

use super::AppState;
use crate::engine::Rules;

pub(super) const SESSION_COOKIE: &str = "cs_session";
pub(super) const LOGIN_COOKIE: &str = "cs_login";
pub(super) const LOGIN_TTL: Duration = Duration::from_mins(10);

/// What the session cookie holds, encrypted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct SessionData {
    pub(super) person: String,
    pub(super) identity: String,
    pub(super) auth_time: Option<i64>,
    pub(super) issued: i64,
    /// For the forms Rust handles itself (sign-out) and the JSON API.
    pub(super) csrf: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct LoginData {
    pub(super) state: String,
    pub(super) next: String,
    pub(super) issued: i64,
}

/// A signed-in, active person holding at least one role, with the rules and
/// standing their access was checked against.
#[derive(Debug, Clone)]
pub(super) struct Session {
    pub(super) person: ActorId,
    pub(super) name: String,
    pub(super) roles: BTreeSet<Role>,
    pub(super) data: SessionData,
    pub(super) rules: Arc<Rules>,
    pub(super) standing: Arc<Standing>,
}

impl Session {
    pub(super) fn assurance(&self, now: Timestamp, window: Duration) -> Assurance {
        match self.fresh_until(window) {
            Some(until) if now <= until => Assurance::FreshAuth,
            _ => Assurance::Web,
        }
    }

    pub(super) fn fresh_until(&self, window: Duration) -> Option<Timestamp> {
        let t = Timestamp::from_second(self.data.auth_time?).ok()?;
        t.checked_add(SignedDuration::try_from(window).ok()?).ok()
    }

    pub(super) fn roster(&self, now: Timestamp) -> Roster<'_> {
        self.rules.roster(&self.standing, now)
    }

    pub(super) fn has(&self, role: Role) -> bool {
        self.roles.contains(&role)
    }

    /// Auditors and admins see everything.
    pub(super) fn oversees(&self) -> bool {
        self.has(Role::Auditor) || self.has(Role::Admin)
    }
}

pub(super) fn random_token() -> String {
    format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple())
}

/// Constant-time string comparison.
pub(super) fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub(super) fn cookie(name: &'static str, value: String, secure: bool) -> Cookie<'static> {
    Cookie::build((name, value)).http_only(true).secure(secure).same_site(SameSite::Lax).path("/").build()
}

pub(super) fn removal(name: &'static str) -> Cookie<'static> {
    Cookie::build((name, "")).path("/").build()
}

/// The session cookie's content, decrypted; not yet checked.
pub(super) fn session_data(jar: &PrivateCookieJar) -> Option<SessionData> {
    serde_json::from_str(jar.get(SESSION_COOKIE)?.value()).ok()
}

pub(super) async fn current_session(state: &AppState, jar: &PrivateCookieJar, now: Timestamp) -> Option<Session> {
    check_session(state, session_data(jar)?, now).await
}

/// The session `data` describes, if it is still good: not expired, its
/// sign-in identity still belongs to the person, and the person is active
/// and holds a role.
pub(super) async fn check_session(state: &AppState, data: SessionData, now: Timestamp) -> Option<Session> {
    let ttl = i64::try_from(state.settings.session_ttl.as_secs()).unwrap_or(i64::MAX);
    if now.as_second() >= data.issued.saturating_add(ttl) {
        return None;
    }
    let (rules, standing) = match state.engine.standing().await {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "loading standing failed");
            return None;
        }
    };
    let person = ActorId::new(data.person.clone());
    let roster = rules.roster(&standing, now);
    let actor = rules.directory.by_identity(&data.identity, Purpose::SignIn).filter(|a| a.id == person)?;
    roster.active_person(&person)?;
    let held = roster.roles(&person);
    if held.is_empty() {
        return None;
    }
    let name = actor.display_name.clone().unwrap_or_else(|| person.to_string());
    Some(Session { person, name, roles: held, data, standing: Arc::new(standing), rules })
}

/// Only same-site absolute paths are accepted as post-login destinations.
pub(super) fn safe_next(next: Option<&str>) -> String {
    match next {
        Some(n) if n.starts_with('/') && !n.starts_with("//") && !n.starts_with("/\\") && !n.contains(['\r', '\n']) => {
            n.to_owned()
        }
        _ => "/".to_owned(),
    }
}

pub(super) fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

pub(super) fn login_url(next: &str, fresh: bool) -> String {
    format!("/login?next={}{}", percent_encode(next), if fresh { "&fresh=1" } else { "" })
}

// ------------------------------------------------------------------ visibility

/// Whether `s` relates to an actor: is it, or owns it.
fn relates_to(roster: &Roster<'_>, s: &Session, actor: Option<&ActorId>) -> bool {
    actor.is_some_and(|a| a == &s.person || roster.owners(a).contains(&s.person))
}

pub(super) fn sees_approval(roster: &Roster<'_>, s: &Session, r: &Request) -> bool {
    s.oversees()
        || roster.could_be_selected(&r.requirements.approvers, &s.person)
        || r.decisions.iter().any(|d| d.approver == s.person)
        || r.facts.initiator.as_ref().and_then(|i| i.actor.as_ref()) == Some(&s.person)
        || relates_to(roster, s, r.facts.requester.actor.as_ref())
}

/// A responder of the question: selected now, or the one who answered.
pub(super) fn responds_to(roster: &Roster<'_>, s: &Session, q: &Question) -> bool {
    roster.selected(&q.requirements.responders, &s.person) || answered_by(q) == Some(&s.person)
}

fn answered_by(q: &Question) -> Option<&ActorId> {
    match &q.outcome {
        Some(QuestionOutcome::Accepted { by, .. } | QuestionOutcome::Declined { by, .. }) => Some(by),
        _ => None,
    }
}

pub(super) fn sees_question(roster: &Roster<'_>, s: &Session, q: &Question) -> bool {
    s.oversees()
        || roster.could_be_selected(&q.requirements.responders, &s.person)
        || answered_by(q) == Some(&s.person)
        || relates_to(roster, s, q.asker.actor.as_ref())
}

/// What of a question's content `s` may see now: (question text, answer).
pub(super) fn question_access(roster: &Roster<'_>, s: &Session, q: &Question, assurance: Assurance) -> (bool, bool) {
    let responder = responds_to(roster, s, q);
    let text = !q.confidentiality.question || (responder && assurance >= q.required_assurance());
    let answer = !q.answer_confidential() || (responder && text);
    (text, answer)
}

/// A copy with what `s` may not see taken out.
pub(super) fn redacted(q: &Question, (text, answer): (bool, bool)) -> Question {
    let mut q = q.clone();
    if !text && !q.content_removed {
        REMOVED.clone_into(&mut q.message);
        q.schema = serde_json::json!({ "type": "object", "properties": {} });
        q.context.clear();
    }
    if !answer && let Some(QuestionOutcome::Accepted { content, .. }) = &mut q.outcome {
        *content = None;
    }
    q
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_must_be_a_local_path() {
        assert_eq!(safe_next(Some("/requests/1")), "/requests/1");
        for bad in ["//evil.example", "/\\evil.example", "https://evil.example", "evil", "/a\r\nSet-Cookie: x"] {
            assert_eq!(safe_next(Some(bad)), "/", "{bad:?}");
        }
        assert_eq!(safe_next(None), "/");
    }

    #[test]
    fn encodes_login_urls() {
        assert_eq!(login_url("/requests/a b?x=1&y", true), "/login?next=/requests/a%20b%3Fx%3D1%26y&fresh=1");
    }

    #[test]
    fn freshness_window() {
        let s = Session {
            person: "a".into(),
            name: "a".into(),
            roles: BTreeSet::from([Role::Member]),
            data: SessionData {
                person: "a".into(),
                identity: "i".into(),
                auth_time: Some(1000),
                issued: 1000,
                csrf: "c".into(),
            },
            rules: Arc::default(),
            standing: Arc::default(),
        };
        let w = Duration::from_secs(300);
        let at = |s| Timestamp::from_second(s).unwrap();
        assert_eq!(s.assurance(at(1300), w), Assurance::FreshAuth);
        assert_eq!(s.assurance(at(1301), w), Assurance::Web);
        let none = Session { data: SessionData { auth_time: None, ..s.data.clone() }, ..s };
        assert_eq!(none.assurance(at(1000), w), Assurance::Web);
    }
}
