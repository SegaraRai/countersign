//! Push-style `host` backend for `sudo` invocations submitted via the intake API.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;

use countersign_core::{
    AccessBackend, BackendCaps, BackendError, BackendName, GrantHandle, PendingSubject, Store, SubjectFacts, SubjectRef,
};

/// `[backend.<name>] type = "host"`: `sudo` invocations from clients. Which
/// OS users may ask is decided by workload identities (`unix:<client>#<user>`)
/// and policies.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostBackendConfig {}

/// A backend for subjects that clients submit. It holds no state of its
/// own: the stored request is the record, and clients read the outcome
/// through the intake API.
pub struct HostBackend {
    name: BackendName,
    store: Arc<dyn Store>,
}

impl std::fmt::Debug for HostBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostBackend").field("name", &self.name).finish_non_exhaustive()
    }
}

impl HostBackend {
    pub fn new(name: BackendName, store: Arc<dyn Store>) -> Self {
        Self { name, store }
    }
}

#[async_trait]
impl AccessBackend for HostBackend {
    fn name(&self) -> &BackendName {
        &self.name
    }

    /// Unused: intake names requesters `unix:<client>#<user>` itself.
    fn identity_scheme(&self) -> &'static str {
        "unix"
    }

    fn capabilities(&self) -> BackendCaps {
        BackendCaps { discover: false, revoke: true, native_expiry: true }
    }

    async fn discover_pending(&self) -> Result<Vec<PendingSubject>, BackendError> {
        Ok(Vec::new())
    }

    /// The facts recorded when the authenticated client submitted the subject.
    async fn verify(&self, subject: &SubjectRef) -> Result<SubjectFacts, BackendError> {
        if subject.backend != self.name {
            return Err(BackendError::NotFound);
        }
        match self.store.find_latest_by_subject(subject).await {
            Ok(Some(r)) => Ok(r.facts),
            Ok(None) => Err(BackendError::NotFound),
            Err(e) => Err(BackendError::Unavailable(e.to_string())),
        }
    }

    async fn grant(&self, subject: &SubjectRef, _: Duration) -> Result<GrantHandle, BackendError> {
        Ok(GrantHandle { subject: subject.clone(), backend_ref: None, expires_at: None })
    }

    async fn deny(&self, _: &SubjectRef) -> Result<(), BackendError> {
        Ok(())
    }

    async fn revoke(&self, _: &GrantHandle) -> Result<(), BackendError> {
        Ok(())
    }
}
