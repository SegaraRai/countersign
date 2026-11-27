//! Questions: "what should happen?", answered with structured data (see
//! `docs/design/questions.md`).
//!
//! A question shares ids, channels, identity, assurance and the audit log
//! with approvals, but it is a separate type with its own policy and API. It
//! has no grant, window or revoke, so no answer can authorize anything.
//!
//! ```text
//! ask ──▶ pending ──answer──▶ answered
//!            │ └───decline──▶ declined
//!            │ └───expire───▶ expired     (no answer; never a default)
//!            └─────withdraw─▶ withdrawn   (the asker gave up)
//! ```
//!
//! Confidential content is kept only as long as the exchange needs it: the
//! question text while the question is pending, the answer until the asker
//! has read it or the retention runs out. Then it is overwritten
//! ([`Question::remove_content`]); the record of who asked and who answered
//! stays.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::actor::{Roster, Selector};
use crate::assurance::Assurance;
use crate::event::DomainEvent;
use crate::form::{FormError, FormSchema};
use crate::glob;
use crate::id::{ActorId, ChannelName, ClientId, PolicyName, RequestId};
use crate::time;

/// Longest question message.
pub const MAX_MESSAGE: usize = 2000;
/// Most context entries, and the longest key and value.
pub const MAX_CONTEXT: usize = 20;
pub const MAX_CONTEXT_KEY: usize = 64;
pub const MAX_CONTEXT_VALUE: usize = 500;
/// Longest decline note.
pub const MAX_NOTE: usize = 500;

/// Who asked: the authenticated client, and the actor it acts for, if any.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asker {
    pub client: ClientId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<ActorId>,
}

/// What the asker marked confidential when asking.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Confidentiality {
    /// The message, schema and context are confidential.
    #[serde(default)]
    pub question: bool,
    /// The answer may be confidential (pre-fills the responder's choice).
    #[serde(default)]
    pub answer_may_be: bool,
}

/// `confidential` in a question policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfidentialMode {
    /// Refuse confidential questions.
    #[default]
    Deny,
    /// Accept them.
    Allow,
    /// Treat every question under this policy as confidential.
    Require,
}

/// `[[question_policy]]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestionPolicy {
    pub name: PolicyName,
    #[serde(default, rename = "match")]
    pub matcher: QuestionMatcher,
    /// Who may answer. At least one entry.
    pub responders: Vec<Selector>,
    #[serde(default = "strongest")]
    pub min_assurance: Assurance,
    /// When an unanswered question expires.
    #[serde(default = "default_answer_timeout", with = "humantime_serde")]
    pub answer_timeout: Duration,
    /// Pending questions one asker may have under this policy.
    #[serde(default = "default_max_pending")]
    pub max_pending: usize,
    /// Let the person a client acts for answer its questions.
    #[serde(default)]
    pub allow_self_answer: bool,
    #[serde(default)]
    pub confidential: ConfidentialMode,
    /// Minimum assurance to read and answer a confidential question.
    #[serde(default = "strongest")]
    pub confidential_min_assurance: Assurance,
    /// How long a confidential answer stays readable by the asker.
    #[serde(default = "default_retention", with = "humantime_serde")]
    pub answer_retention: Duration,
    /// Channels that receive notifications for this policy. Empty means all configured channels.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub channels: Vec<ChannelName>,
}

/// Which askers a question policy covers. Omitted fields match anything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestionMatcher {
    /// Glob on the asking client's id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asker: Option<String>,
    /// Glob on the actor the client acts for; a client acting for nobody
    /// never matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asker_actor: Option<String>,
}

fn strongest() -> Assurance {
    Assurance::FreshAuth
}
fn default_answer_timeout() -> Duration {
    Duration::from_mins(30)
}
fn default_max_pending() -> usize {
    5
}
fn default_retention() -> Duration {
    Duration::from_hours(24)
}

impl QuestionPolicy {
    pub fn matches(&self, asker: &Asker) -> bool {
        self.matcher.asker.as_deref().is_none_or(|g| glob::matches(g, asker.client.as_str()))
            && self
                .matcher
                .asker_actor
                .as_deref()
                .is_none_or(|g| asker.actor.as_ref().is_some_and(|a| glob::matches(g, a.as_str())))
    }

    /// Problems with this policy, for the configuration check.
    pub fn problems(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.responders.is_empty() {
            errors.push(format!("question_policy {}: no responders", self.name));
        }
        if self.answer_timeout.is_zero() {
            errors.push(format!("question_policy {}: answer_timeout must be greater than zero", self.name));
        }
        if self.max_pending == 0 {
            errors.push(format!("question_policy {}: max_pending must be at least 1", self.name));
        }
        if self.answer_retention.is_zero() {
            errors.push(format!("question_policy {}: answer_retention must be greater than zero", self.name));
        }
        errors
    }
}

/// The ordered `[[question_policy]]` tables.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuestionPolicySet {
    pub policies: Vec<QuestionPolicy>,
}

impl QuestionPolicySet {
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors: Vec<String> = self.policies.iter().flat_map(QuestionPolicy::problems).collect();
        let mut seen = BTreeSet::new();
        for p in &self.policies {
            if !seen.insert(&p.name) {
                errors.push(format!("question_policy {}: duplicate name", p.name));
            }
        }
        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }

    /// The first policy covering `asker`.
    pub fn find(&self, asker: &Asker) -> Option<&QuestionPolicy> {
        self.policies.iter().find(|p| p.matches(asker))
    }
}

/// The policy's rules, frozen when the question is asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuestionRequirements {
    pub policy: PolicyName,
    pub responders: Vec<Selector>,
    pub min_assurance: Assurance,
    #[serde(with = "humantime_serde")]
    pub answer_timeout: Duration,
    pub allow_self_answer: bool,
    pub confidential_min_assurance: Assurance,
    #[serde(with = "humantime_serde")]
    pub answer_retention: Duration,
    /// Channels routed for this question; empty means all configured channels.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub channels: Vec<ChannelName>,
}

/// How a question ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case")]
pub enum QuestionOutcome {
    /// Answered. `content` is gone once confidential content was removed.
    Accepted {
        by: ActorId,
        at: Timestamp,
        assurance: Assurance,
        via: ChannelName,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        content: Option<Map<String, Value>>,
        /// Field names of the answer, kept when only the answer was
        /// confidential (they come from the schema).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        fields: Vec<String>,
        /// Set by the responder.
        confidential: bool,
    },
    Declined {
        by: ActorId,
        at: Timestamp,
        assurance: Assurance,
        via: ChannelName,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    /// No one answered in time. countersign never fills in a default.
    Expired { at: Timestamp },
    /// The asker gave up.
    Withdrawn { at: Timestamp },
}

/// What a responder sends back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case")]
pub enum Response {
    Accept {
        content: Map<String, Value>,
        #[serde(default)]
        confidential: bool,
    },
    Decline {
        #[serde(default)]
        note: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AnswerError {
    #[error("the question is {0}")]
    NotPending(&'static str),
    #[error("the question is no longer accepting answers")]
    Expired,
    #[error("you are not a responder for this question")]
    NotEligible,
    #[error("only active persons can answer")]
    Inactive,
    #[error("you cannot answer a question asked on your own behalf")]
    SelfAnswer,
    #[error("answering requires assurance {required}, got {presented}")]
    InsufficientAssurance { required: Assurance, presented: Assurance },
    #[error("the answer does not fit the form: {0}")]
    Invalid(#[from] FormError),
    #[error("the answer to a confidential question is confidential")]
    MustStayConfidential,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Question {
    pub id: RequestId,
    pub asker: Asker,
    /// Shown to responders; untrusted. Empty once confidential content was
    /// removed.
    pub message: String,
    /// The `requestedSchema` as accepted (checked by [`FormSchema::parse`]).
    pub schema: Value,
    /// Extra facts from the asker, shown to responders; untrusted.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub context: BTreeMap<String, String>,
    pub requirements: QuestionRequirements,
    #[serde(default)]
    pub confidentiality: Confidentiality,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<QuestionOutcome>,
    /// When the asker first read the answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer_read_at: Option<Timestamp>,
    /// The confidential question text was overwritten.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub content_removed: bool,
    pub created_at: Timestamp,
    /// Answers are refused after this instant.
    pub pending_until: Timestamp,
    pub updated_at: Timestamp,
    pub version: u64,
}

/// Placeholder for removed confidential text.
pub const REMOVED: &str = "content removed (confidential)";

impl Question {
    /// Ask a question. The caller has checked the message, schema and
    /// context against the limits and the confidentiality against the policy.
    pub fn ask(
        asker: Asker,
        message: String,
        schema: Value,
        context: BTreeMap<String, String>,
        policy: &QuestionPolicy,
        confidentiality: Confidentiality,
        now: Timestamp,
    ) -> (Self, Vec<DomainEvent>) {
        let id = RequestId::new();
        let requirements = QuestionRequirements {
            policy: policy.name.clone(),
            responders: policy.responders.clone(),
            min_assurance: policy.min_assurance,
            answer_timeout: policy.answer_timeout,
            allow_self_answer: policy.allow_self_answer,
            confidential_min_assurance: policy.confidential_min_assurance,
            answer_retention: policy.answer_retention,
            channels: policy.channels.clone(),
        };
        let q = Self {
            id,
            asker,
            message,
            schema,
            context,
            pending_until: time::add(now, requirements.answer_timeout),
            requirements,
            confidentiality,
            outcome: None,
            answer_read_at: None,
            content_removed: false,
            created_at: now,
            updated_at: now,
            version: 0,
        };
        (q, vec![DomainEvent::Requested { request_id: id, at: now }])
    }

    pub fn state(&self) -> &'static str {
        match &self.outcome {
            None => "pending",
            Some(QuestionOutcome::Accepted { .. }) => "answered",
            Some(QuestionOutcome::Declined { .. }) => "declined",
            Some(QuestionOutcome::Expired { .. }) => "expired",
            Some(QuestionOutcome::Withdrawn { .. }) => "withdrawn",
        }
    }

    pub fn is_pending(&self) -> bool {
        self.outcome.is_none()
    }

    /// The MCP view of the outcome: `accept`, `decline` or `cancel`.
    pub fn mcp_action(&self) -> Option<&'static str> {
        match &self.outcome {
            None => None,
            Some(QuestionOutcome::Accepted { .. }) => Some("accept"),
            Some(QuestionOutcome::Declined { .. }) => Some("decline"),
            Some(QuestionOutcome::Expired { .. } | QuestionOutcome::Withdrawn { .. }) => Some("cancel"),
        }
    }

    /// Whether the question text must stay out of chat and audit.
    pub fn question_confidential(&self) -> bool {
        self.confidentiality.question
    }

    /// Whether anything about this question is or was confidential.
    pub fn answer_confidential(&self) -> bool {
        matches!(&self.outcome, Some(QuestionOutcome::Accepted { confidential: true, .. }))
    }

    /// The parsed form (empty once confidential content was removed).
    pub fn form(&self) -> Result<FormSchema, FormError> {
        FormSchema::parse(&self.schema)
    }

    /// The assurance needed to answer (and, when confidential, to read).
    pub fn required_assurance(&self) -> Assurance {
        if self.confidentiality.question {
            self.requirements.min_assurance.max(self.requirements.confidential_min_assurance)
        } else {
            self.requirements.min_assurance
        }
    }

    /// Whether `person` is a responder now: active, selected, and not
    /// answering their own question unless allowed.
    pub fn eligible(&self, roster: &Roster<'_>, person: &ActorId) -> Result<(), AnswerError> {
        if roster.active_person(person).is_none() {
            return Err(AnswerError::Inactive);
        }
        if !roster.selected(&self.requirements.responders, person) {
            return Err(AnswerError::NotEligible);
        }
        if !self.requirements.allow_self_answer && self.asker.actor.as_ref() == Some(person) {
            return Err(AnswerError::SelfAnswer);
        }
        Ok(())
    }

    /// Check an answer without recording it.
    pub fn check_response(
        &self,
        roster: &Roster<'_>,
        person: &ActorId,
        response: &Response,
        assurance: Assurance,
        now: Timestamp,
    ) -> Result<(), AnswerError> {
        if !self.is_pending() {
            return Err(AnswerError::NotPending(self.state()));
        }
        if now >= self.pending_until {
            return Err(AnswerError::Expired);
        }
        self.eligible(roster, person)?;
        let required = self.required_assurance();
        // Like denials, declining never widens anything; a weaker channel
        // may decline, but only for questions whose text it could show.
        let needed = match response {
            Response::Accept { .. } => required,
            Response::Decline { .. } if self.confidentiality.question => required,
            Response::Decline { .. } => Assurance::Linked,
        };
        if assurance < needed {
            return Err(AnswerError::InsufficientAssurance { required: needed, presented: assurance });
        }
        if let Response::Accept { content, confidential } = response {
            self.form()?.validate(content)?;
            if self.confidentiality.question && !confidential {
                return Err(AnswerError::MustStayConfidential);
            }
        }
        Ok(())
    }

    /// Record an answer or a decline. The first valid one closes the
    /// question for everyone.
    pub fn respond(
        &mut self,
        roster: &Roster<'_>,
        person: &ActorId,
        response: Response,
        assurance: Assurance,
        via: ChannelName,
        now: Timestamp,
    ) -> Result<Vec<DomainEvent>, AnswerError> {
        self.check_response(roster, person, &response, assurance, now)?;
        let event = match response {
            Response::Accept { content, confidential } => {
                let content = self.form()?.validate(&content)?;
                self.outcome = Some(QuestionOutcome::Accepted {
                    by: person.clone(),
                    at: now,
                    assurance,
                    via,
                    content: Some(content),
                    fields: Vec::new(),
                    confidential,
                });
                DomainEvent::Answered { request_id: self.id, by: person.clone(), at: now }
            }
            Response::Decline { note } => {
                let note = note.map(|n| n.trim().chars().take(MAX_NOTE).collect::<String>()).filter(|n| !n.is_empty());
                self.outcome = Some(QuestionOutcome::Declined { by: person.clone(), at: now, assurance, via, note });
                DomainEvent::Declined { request_id: self.id, by: person.clone(), at: now }
            }
        };
        self.touch(now);
        self.remove_content_if_due(now);
        Ok(vec![event])
    }

    /// Expire an unanswered question whose time is up. No events if not due.
    pub fn expire_if_due(&mut self, now: Timestamp) -> Vec<DomainEvent> {
        if !self.is_pending() || now < self.pending_until {
            return Vec::new();
        }
        self.outcome = Some(QuestionOutcome::Expired { at: now });
        self.touch(now);
        self.remove_content_if_due(now);
        vec![DomainEvent::Expired { request_id: self.id, at: now }]
    }

    /// The asker gave up.
    pub fn withdraw(&mut self, now: Timestamp) -> Result<Vec<DomainEvent>, AnswerError> {
        if !self.is_pending() {
            return Err(AnswerError::NotPending(self.state()));
        }
        self.outcome = Some(QuestionOutcome::Withdrawn { at: now });
        self.touch(now);
        self.remove_content_if_due(now);
        Ok(vec![DomainEvent::Withdrawn { request_id: self.id, at: now }])
    }

    /// The asker has read the outcome. Returns whether anything changed.
    pub fn mark_read(&mut self, now: Timestamp) -> bool {
        if self.is_pending() || self.answer_read_at.is_some() {
            return false;
        }
        self.answer_read_at = Some(now);
        self.remove_content_if_due(now);
        self.touch(now);
        true
    }

    /// Whether the confidential answer must still be held for the asker.
    fn answer_still_needed(&self, now: Timestamp) -> bool {
        match &self.outcome {
            Some(QuestionOutcome::Accepted { at, content: Some(_), confidential: true, .. }) => {
                self.answer_read_at.is_none() && now < time::add(*at, self.requirements.answer_retention)
            }
            _ => false,
        }
    }

    /// Whether the record may still hold confidential content.
    pub fn holds_content(&self) -> bool {
        (self.confidentiality.question && !self.content_removed)
            || matches!(&self.outcome, Some(QuestionOutcome::Accepted { content: Some(_), confidential: true, .. }))
    }

    /// Whether confidential content is held that is no longer needed: the
    /// question text once the question is closed, a confidential answer once
    /// the asker has read it or the retention ran out.
    pub fn content_due_for_removal(&self, now: Timestamp) -> bool {
        if self.is_pending() {
            return false;
        }
        let text = self.confidentiality.question && !self.content_removed;
        let answer =
            matches!(&self.outcome, Some(QuestionOutcome::Accepted { content: Some(_), confidential: true, .. }))
                && !self.answer_still_needed(now);
        text || answer
    }

    fn remove_content_if_due(&mut self, now: Timestamp) {
        if self.content_due_for_removal(now) {
            self.remove_content(now);
        }
    }

    /// Overwrite confidential content that is no longer needed, keeping the
    /// record of who asked, who answered and how it ended. No hash or other
    /// trace of the content is kept.
    pub fn remove_content(&mut self, now: Timestamp) {
        if self.confidentiality.question && !self.is_pending() {
            self.message = String::new();
            self.schema = serde_json::json!({ "type": "object", "properties": {} });
            self.context.clear();
            self.content_removed = true;
        }
        let keep_answer = self.answer_still_needed(now);
        let question_confidential = self.confidentiality.question;
        if let Some(QuestionOutcome::Accepted { content, fields, confidential: true, .. }) = &mut self.outcome
            && !keep_answer
            && let Some(c) = content.take()
        {
            // Field names come from the schema; keep them unless the
            // schema itself was confidential.
            if !question_confidential {
                *fields = c.keys().cloned().collect();
            }
        }
    }

    /// The question as chat and webhook channels may show it: never the
    /// text of a confidential question, never a confidential answer.
    #[must_use]
    pub fn for_chat(&self) -> Self {
        let mut q = self.clone();
        let question_confidential = q.confidentiality.question;
        if question_confidential {
            q.message = String::new();
            q.schema = serde_json::json!({ "type": "object", "properties": {} });
            q.context.clear();
            if let Some(QuestionOutcome::Declined { note, .. }) = &mut q.outcome {
                *note = None;
            }
        }
        if let Some(QuestionOutcome::Accepted { content, fields, confidential, .. }) = &mut q.outcome
            && (*confidential || question_confidential)
        {
            if let Some(c) = content.take()
                && !question_confidential
            {
                *fields = c.keys().cloned().collect();
            }
            if question_confidential {
                fields.clear();
            }
        }
        q
    }

    /// Whether the content was (partly) removed as confidential.
    pub fn shows_removed(&self) -> bool {
        self.content_removed
            || matches!(&self.outcome, Some(QuestionOutcome::Accepted { content: None, confidential: true, .. }))
    }

    /// Remove confidential content whose time is up. Returns whether
    /// anything changed.
    pub fn sweep(&mut self, now: Timestamp) -> bool {
        if !self.content_due_for_removal(now) {
            return false;
        }
        self.remove_content(now);
        self.touch(now);
        true
    }

    fn touch(&mut self, now: Timestamp) {
        self.updated_at = now;
        self.version += 1;
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::actor::{Directory, GroupConfig, PersonConfig, Roles, Standing};

    fn t(secs: i64) -> Timestamp {
        Timestamp::from_second(1_800_000_000 + secs).unwrap()
    }

    fn dir() -> Directory {
        let p = |id: &str| PersonConfig { id: id.into(), display_name: None, identities: vec![] };
        Directory::new(
            vec![p("alice"), p("bob"), p("mallory")],
            vec![],
            vec![GroupConfig { name: "ops".into(), members: vec!["alice".into(), "bob".into()], from_idp: vec![] }],
            Roles::default(),
        )
        .unwrap()
    }

    fn policy() -> QuestionPolicy {
        toml::from_str(
            r#"
            name = "agents"
            match = { asker = "agent-*" }
            responders = ["group:ops"]
            min_assurance = "linked"
            confidential = "allow"
            confidential_min_assurance = "fresh-auth"
            answer_retention = "1h"
            "#,
        )
        .unwrap()
    }

    fn ask(conf: Confidentiality) -> Question {
        let asker = Asker { client: "agent-1".into(), actor: Some("alice".into()) };
        let schema = json!({ "type": "object", "properties": { "branch": { "type": "string", "enum": ["main", "release"] } }, "required": ["branch"] });
        let ctx = BTreeMap::from([("repo".to_owned(), "app".to_owned())]);
        Question::ask(asker, "Which branch?".into(), schema, ctx, &policy(), conf, t(0)).0
    }

    fn accept(branch: &str, confidential: bool) -> Response {
        Response::Accept { content: json!({ "branch": branch }).as_object().unwrap().clone(), confidential }
    }

    #[test]
    fn first_valid_answer_wins() {
        let (d, s) = (dir(), Standing::default());
        let roster = Roster { directory: &d, standing: &s, now: t(1), idp_max_age: Duration::from_secs(60) };
        let mut q = ask(Confidentiality::default());
        assert_eq!(q.state(), "pending");
        assert_eq!(
            q.respond(&roster, &"alice".into(), accept("main", false), Assurance::Linked, "web".into(), t(1)),
            Err(AnswerError::SelfAnswer)
        );
        assert_eq!(
            q.respond(&roster, &"mallory".into(), accept("main", false), Assurance::Linked, "web".into(), t(1)),
            Err(AnswerError::NotEligible)
        );
        assert!(matches!(
            q.respond(&roster, &"bob".into(), accept("dev", false), Assurance::Linked, "web".into(), t(1)),
            Err(AnswerError::Invalid(_))
        ));
        let ev =
            q.respond(&roster, &"bob".into(), accept("main", false), Assurance::Linked, "web".into(), t(1)).unwrap();
        assert_eq!(ev[0].kind(), "answered");
        assert_eq!((q.state(), q.mcp_action()), ("answered", Some("accept")));
        assert!(
            q.respond(&roster, &"bob".into(), accept("release", false), Assurance::Linked, "web".into(), t(2)).is_err()
        );
        q.mark_read(t(3));
        assert!(
            matches!(&q.outcome, Some(QuestionOutcome::Accepted { content: Some(_), .. })),
            "not confidential: kept"
        );
        assert_eq!(q.message, "Which branch?");
    }

    #[test]
    fn expiry_is_recorded_as_no_answer() {
        let mut q = ask(Confidentiality::default());
        assert_eq!(q.expire_if_due(t(1799)), vec![]);
        assert_eq!(q.expire_if_due(t(1800))[0].kind(), "expired");
        assert_eq!((q.state(), q.mcp_action()), ("expired", Some("cancel")));
        assert!(q.withdraw(t(1801)).is_err());
    }

    #[test]
    fn confidential_question_text_goes_when_closed_and_answer_after_reading() {
        let (d, s) = (dir(), Standing::default());
        let roster = Roster { directory: &d, standing: &s, now: t(1), idp_max_age: Duration::from_secs(60) };
        let mut q = ask(Confidentiality { question: true, answer_may_be: false });
        assert_eq!(q.required_assurance(), Assurance::FreshAuth);
        assert!(matches!(
            q.respond(&roster, &"bob".into(), accept("main", true), Assurance::Linked, "chat".into(), t(1)),
            Err(AnswerError::InsufficientAssurance { .. })
        ));
        assert_eq!(
            q.respond(&roster, &"bob".into(), accept("main", false), Assurance::FreshAuth, "web".into(), t(1)),
            Err(AnswerError::MustStayConfidential)
        );
        q.respond(&roster, &"bob".into(), accept("main", true), Assurance::FreshAuth, "web".into(), t(1)).unwrap();
        assert_eq!(q.message, "", "the question text is gone once answered");
        assert!(q.context.is_empty());
        assert!(matches!(&q.outcome, Some(QuestionOutcome::Accepted { content: Some(_), .. })), "kept for the asker");
        assert!(q.mark_read(t(2)));
        let Some(QuestionOutcome::Accepted { content, fields, by, .. }) = &q.outcome else { panic!() };
        assert_eq!((content, fields.len(), by.as_str()), (&None, 0, "bob"), "no field names for a confidential schema");
        assert!(q.shows_removed());
        assert!(!serde_json::to_string(&q).unwrap().contains("main"), "nothing of the answer is stored");
    }

    #[test]
    fn confidential_answer_expires_with_retention_and_keeps_field_names() {
        let (d, s) = (dir(), Standing::default());
        let roster = Roster { directory: &d, standing: &s, now: t(1), idp_max_age: Duration::from_secs(60) };
        let mut q = ask(Confidentiality { question: false, answer_may_be: true });
        q.respond(&roster, &"bob".into(), accept("release", true), Assurance::Linked, "web".into(), t(10)).unwrap();
        assert!(!q.sweep(t(3609)));
        assert!(q.sweep(t(3610)));
        let Some(QuestionOutcome::Accepted { content, fields, .. }) = &q.outcome else { panic!() };
        assert_eq!((content, fields.as_slice()), (&None, ["branch".to_owned()].as_slice()));
        assert_eq!(q.message, "Which branch?", "the question itself was not confidential");
        assert!(!serde_json::to_string(&q.outcome).unwrap().contains("release"));
    }

    #[test]
    fn declines_and_withdrawals_remove_confidential_text() {
        let (d, s) = (dir(), Standing::default());
        let roster = Roster { directory: &d, standing: &s, now: t(1), idp_max_age: Duration::from_secs(60) };
        let mut q = ask(Confidentiality::default());
        q.respond(
            &roster,
            &"bob".into(),
            Response::Decline { note: Some(" not now ".into()) },
            Assurance::Linked,
            "chat".into(),
            t(1),
        )
        .unwrap();
        assert!(matches!(&q.outcome, Some(QuestionOutcome::Declined { note: Some(n), .. }) if n == "not now"));

        let mut q = ask(Confidentiality { question: true, answer_may_be: false });
        assert!(
            matches!(
                q.respond(
                    &roster,
                    &"bob".into(),
                    Response::Decline { note: None },
                    Assurance::Linked,
                    "chat".into(),
                    t(1)
                ),
                Err(AnswerError::InsufficientAssurance { .. })
            ),
            "a chat that cannot show the question cannot decline it either"
        );
        q.withdraw(t(2)).unwrap();
        assert_eq!(q.message, "");
        assert!(q.shows_removed());
    }

    #[test]
    fn policies_match_askers() {
        let set = QuestionPolicySet { policies: vec![policy()] };
        set.validate().unwrap();
        assert!(set.find(&Asker { client: "agent-1".into(), actor: None }).is_some());
        assert!(set.find(&Asker { client: "web-1".into(), actor: None }).is_none());
        assert!(toml::from_str::<QuestionPolicy>("name='x'\nresponders=['group:g']\nquorum=2\n").is_err());
    }
}
