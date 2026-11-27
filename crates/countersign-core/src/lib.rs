//! Domain core of countersign.
//!
//! This crate holds the approval state machine, questions and their form
//! schemas, the identity model (persons, workloads, groups, roles), policy
//! evaluation, domain events, and the traits that pluggable components
//! implement:
//!
//! - [`AccessBackend`]: the system that actually holds access (e.g. Octelium
//!   sessions, an external command speaking JSON).
//! - [`Channel`]: where requests are announced and, if interactive, decided
//!   (ntfy, webhooks, Discord, Slack, ...).
//! - [`Store`]: durable state plus the event outbox.
//! - [`Authenticator`]: signs persons in to the web UI.
//!
//! It deliberately has no network, database, or web-framework dependencies so
//! that the rules can be tested in isolation.

pub mod actor;
pub mod approval_signing;
pub mod assurance;
pub mod auth;
pub mod backend;
pub mod channel;
pub mod event;
pub mod form;
pub mod glob;
pub mod host_key;
pub mod id;
pub mod policy;
pub mod present;
pub mod question;
pub mod request;
pub mod store;
pub mod subject;
pub mod sudo;
pub mod text;
mod time;
pub mod url;

pub use actor::{
    Actor, ActorKind, Directory, GroupConfig, IdpGroup, IdpSnapshot, PersonConfig, Purpose, Role, Roles, Roster,
    Selector, Standing, Suspension, WorkloadConfig,
};
pub use assurance::Assurance;
pub use auth::{AuthError, Authenticator, LoginStart, VerifiedLogin};
pub use backend::{AccessBackend, BackendCaps, BackendError, GrantHandle};
pub use channel::{
    ActionIntent, ActionSink, AdminNotice, AnswerIntent, ApproveMode, Channel, ChannelCaps, ChannelError, Item,
    MessageRef, Notification,
};
pub use event::DomainEvent;
pub use form::{Choice, Field, FieldKind, FormError, FormSchema, TextFormat};
pub use id::{ActorId, BackendName, ChannelName, ClientId, EventId, PolicyName, RequestId};
pub use policy::{Exclusion, GrantMode, Matcher, Policy, PolicyError, PolicySet, Requirements, SensitiveMode};
pub use question::{
    AnswerError, Asker, ConfidentialMode, Confidentiality, Question, QuestionOutcome, QuestionPolicy,
    QuestionPolicySet, QuestionRequirements, Response,
};
pub use request::{Decision, Request, RequestState, TransitionError, Use, Verdict};
pub use store::{AccountLink, AdminAction, OutboxItem, PushSubscription, RequestFilter, Store, StoreError};
pub use subject::{Action, Detail, Initiator, PendingSubject, Requester, Source, SubjectFacts, SubjectRef};
