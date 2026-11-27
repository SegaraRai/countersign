//! Authenticating approvers in the web UI.
//!
//! An [`Authenticator`] runs a redirect-based login (e.g. `OpenID Connect`).
//! The web layer keeps the opaque [`LoginStart::state`] somewhere the browser
//! cannot read or alter (an encrypted cookie) and hands it back on callback.

use async_trait::async_trait;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// The first half of a login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginStart {
    /// Where to send the browser.
    pub redirect_url: String,
    /// Opaque data needed to finish the login. Must be kept confidential and
    /// tamper-proof, and used at most once.
    pub state: String,
}

/// A completed, verified login.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedLogin {
    /// Globally namespaced identity, matched against
    /// sign-in identities of persons (e.g. `oidc:<issuer>#<sub>`).
    pub identity: String,
    /// When the user actually authenticated at the identity provider, if it
    /// says so. Used to decide whether a decision is [`crate::Assurance::FreshAuth`].
    pub auth_time: Option<Timestamp>,
    pub display_name: Option<String>,
    /// The provider (`oidc:<issuer>`) and the groups it reported, when it
    /// sends a `groups` claim. Count only through mappings in the config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<(String, std::collections::BTreeSet<String>)>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// The callback does not belong to the login in progress.
    #[error("login state mismatch")]
    StateMismatch,
    /// The identity provider reported an error or returned something invalid.
    #[error("identity provider: {0}")]
    Provider(String),
    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

#[async_trait]
pub trait Authenticator: Send + Sync {
    /// Start a login. With `fresh`, ask the provider to make the user
    /// authenticate again even if they have a session there.
    async fn begin(&self, fresh: bool) -> Result<LoginStart, AuthError>;

    /// Finish a login from the callback's `state` and `code` parameters.
    async fn complete(&self, saved_state: &str, returned_state: &str, code: &str) -> Result<VerifiedLogin, AuthError>;
}
