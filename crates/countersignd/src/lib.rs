//! The countersign daemon, as a library so it can be embedded and tested.

pub mod config;
pub mod dispatch;
pub mod engine;

use std::sync::Arc;

use countersign_core::{AccessBackend, Channel, Store, StoreError};
use countersign_store_sqlite::SqliteStore;

use crate::config::{BackendConfig, ChannelConfig, Config};
use crate::dispatch::{Dispatcher, LogChannel};
use crate::engine::{Engine, Rules};

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("backend {name}: {source}")]
    Backend { name: String, source: countersign_core::BackendError },
}

/// Policies and approvers from a configuration, as engine rules.
pub fn rules_from(config: &Config) -> Rules {
    Rules { policies: config.policies.clone(), approvers: config.approver_map(), unmatched: config.engine.unmatched }
}

/// Instantiate the configured backends.
pub fn build_backends(config: &Config) -> Result<Vec<Arc<dyn AccessBackend>>, BuildError> {
    config
        .backends
        .iter()
        .map(|(name, bc)| -> Result<Arc<dyn AccessBackend>, BuildError> {
            match bc {
                #[cfg(feature = "backend-octelium")]
                BackendConfig::Octelium(c) => {
                    countersign_backend_octelium::OcteliumBackend::new(name.clone(), c.clone())
                        .map(|b| Arc::new(b) as Arc<dyn AccessBackend>)
                        .map_err(|source| BuildError::Backend { name: name.to_string(), source })
                }
                #[allow(unreachable_patterns)]
                _ => unreachable!("backend type {name} not compiled in"),
            }
        })
        .collect()
}

/// Instantiate the configured channels.
pub fn build_channels(config: &Config) -> Vec<Arc<dyn Channel>> {
    config
        .channels
        .iter()
        .map(|(name, cc)| match cc {
            ChannelConfig::Log {} => Arc::new(LogChannel::new(name.clone())) as Arc<dyn Channel>,
        })
        .collect()
}

/// Everything the daemon runs.
#[derive(Debug)]
pub struct Daemon {
    pub engine: Arc<Engine>,
    pub dispatcher: Arc<Dispatcher>,
}

impl Daemon {
    pub async fn build(config: &Config) -> Result<Self, BuildError> {
        let url = format!("sqlite://{}", config.store.path.display());
        let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&url).await?);
        Self::with_parts(config, store, build_backends(config)?, build_channels(config))
    }

    pub fn with_parts(
        config: &Config,
        store: Arc<dyn Store>,
        backends: Vec<Arc<dyn AccessBackend>>,
        channels: Vec<Arc<dyn Channel>>,
    ) -> Result<Self, BuildError> {
        let engine = Arc::new(Engine::new(Arc::clone(&store), backends, rules_from(config)));
        let dispatcher = Arc::new(Dispatcher::new(store, channels, &config.server.public_url));
        Ok(Self { engine, dispatcher })
    }
}
