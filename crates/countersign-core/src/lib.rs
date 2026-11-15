//! Domain core of countersign.
//!
//! This crate holds the request/decision state machine, policy evaluation,
//! domain events, and the traits that pluggable components implement:
//!
//! - [`AccessBackend`]: the system that actually holds access (e.g. Octelium
//!   sessions, an external command speaking JSON).
//! - [`Channel`]: where requests are announced and, if interactive, decided
//!   (ntfy, webhooks, Discord, Slack, ...).
//! - [`Store`]: durable state plus the event outbox.
//! - [`Authenticator`]: logs approvers in to the web UI.
//!
//! It deliberately has no network, database, or web-framework dependencies so
//! that the rules can be tested in isolation.

pub mod assurance;
pub mod auth;
pub mod backend;
pub mod channel;
pub mod event;
mod glob;
pub mod id;
pub mod policy;
pub mod principal;
pub mod request;
pub mod store;
pub mod subject;
mod time;

pub use assurance::Assurance;
pub use auth::{AuthError, Authenticator, LoginStart, VerifiedLogin};
pub use backend::{AccessBackend, BackendCaps, BackendError, GrantHandle};
pub use channel::{ActionIntent, ApproveMode, Channel, ChannelCaps, ChannelError, MessageRef, Notification};
pub use event::DomainEvent;
pub use id::{ApproverId, BackendName, ChannelName, EventId, PolicyName, RequestId};
pub use policy::{ApproverSelector, Matcher, Policy, PolicyError, PolicySet, Requirements};
pub use principal::{Approver, Requester};
pub use request::{Decision, Request, RequestState, TransitionError, Verdict};
pub use store::{OutboxItem, RequestFilter, Store, StoreError};
pub use subject::{PendingSubject, SubjectFacts, SubjectRef};
