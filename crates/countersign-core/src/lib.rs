//! Domain core of countersign.
//!
//! Organized by domain area:
//!
//! - [`identity`]: persons, workloads, identities, groups, roles, and assurance levels.
//! - [`approval`]: access subjects, policies, the approval state machine, and `sudo` parsing.
//! - [`question`]: structured questions and MCP elicitation form schemas.
//! - [`ports`]: pluggable traits ([`AccessBackend`], [`Channel`], [`Store`], [`Authenticator`]) and [`DomainEvent`].
//! - [`crypto`]: checksummed host keys and Ed25519 approval signing.
//! - [`present`]: unified human-facing presentation shared by every surface.
//! - [`support`]: pure helpers (glob matching, text escaping, URL validation).
//!
//! It deliberately has no network, database, or web-framework dependencies so
//! that the rules can be tested in isolation and compiled to `wasm32`.

pub mod approval;
pub mod crypto;
pub mod identity;
pub mod ports;
pub mod present;
pub mod question;
pub mod support;

// Flat module re-exports for concise access (`countersign_core::host_key`, etc.).
pub use approval::{policy, request, subject, sudo};
pub use crypto::{approval_signing, host_key};
pub use identity::{actor, assurance, id};
pub use ports::{auth, backend, channel, event, store};
pub use question::form;
use support::time;
pub use support::{glob, text, url};

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
