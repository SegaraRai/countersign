//! The countersign daemon, as a library so it can be embedded and tested.

pub mod config;
pub mod dispatch;
pub mod engine;
pub mod link;
pub mod web;

use std::sync::Arc;

use countersign_core::{AccessBackend, Channel, Store, StoreError};
use countersign_store_sqlite::SqliteStore;

#[cfg_attr(not(feature = "backend-octelium"), allow(unused_imports))]
use crate::config::{BackendConfig, ChannelConfig, Config};
use crate::dispatch::{Dispatcher, LogChannel};
use crate::engine::{Engine, Rules};

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("backend {name}: {source}")]
    Backend { name: String, source: countersign_core::BackendError },
    #[error("auth: {0}")]
    Auth(#[from] countersign_core::AuthError),
    #[error("session key: {0}")]
    SessionKey(String),
    #[error("channel {name}: {source}")]
    Channel { name: String, source: countersign_core::ChannelError },
}

/// Instantiate the configured authenticator, if any.
pub fn build_authenticator(config: &Config) -> Result<Option<Arc<dyn countersign_core::Authenticator>>, BuildError> {
    #[cfg(feature = "auth-oidc")]
    if let Some(oidc) = &config.auth.oidc {
        let callback = format!("{}/auth/callback", config.server.public_url.trim_end_matches('/'));
        let a = countersign_auth_oidc::OidcAuthenticator::new(oidc.clone(), &callback)?;
        return Ok(Some(Arc::new(a)));
    }
    let _ = config;
    Ok(None)
}

/// The cookie key: from `session_key_file`, or random (sessions end on restart).
pub fn session_key(config: &Config) -> Result<axum_extra::extract::cookie::Key, BuildError> {
    use axum_extra::extract::cookie::Key;
    let Some(path) = &config.server.session_key_file else {
        tracing::warn!("server.session_key_file is not set; using a random key (web sessions end on restart)");
        return Ok(Key::generate());
    };
    let bytes = std::fs::read(path).map_err(|e| BuildError::SessionKey(format!("{}: {e}", path.display())))?;
    if bytes.len() < 32 {
        return Err(BuildError::SessionKey(format!("{} must hold at least 32 bytes", path.display())));
    }
    Ok(Key::derive_from(&bytes))
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

/// Instantiate the configured channels. Reads secrets; does not connect.
pub fn build_channels(config: &Config) -> Result<Vec<Arc<dyn Channel>>, BuildError> {
    config
        .channels
        .iter()
        .map(|(name, cc)| -> Result<Arc<dyn Channel>, BuildError> {
            Ok(match cc {
                ChannelConfig::Log {} => Arc::new(LogChannel::new(name.clone())),
                #[cfg(feature = "channel-discord")]
                ChannelConfig::Discord(c) => Arc::new(
                    countersign_channel_discord::DiscordChannel::new(name.clone(), c.clone())
                        .map_err(|source| BuildError::Channel { name: name.to_string(), source })?,
                ),
                #[cfg(feature = "channel-ntfy")]
                ChannelConfig::Ntfy(c) => Arc::new(
                    countersign_channel_ntfy::NtfyChannel::new(name.clone(), c.clone())
                        .map_err(|source| BuildError::Channel { name: name.to_string(), source })?,
                ),
            })
        })
        .collect()
}

/// Everything the daemon runs.
pub struct Daemon {
    pub engine: Arc<Engine>,
    pub dispatcher: Arc<Dispatcher>,
    pub web: web::AppState,
    /// Channels whose [`Channel::run`] should be kept running.
    pub interactive: Vec<Arc<dyn Channel>>,
    pub sink: Arc<link::DaemonSink>,
}

impl std::fmt::Debug for Daemon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let interactive: Vec<_> = self.interactive.iter().map(|c| c.name().to_string()).collect();
        f.debug_struct("Daemon").field("web", &self.web).field("interactive", &interactive).finish_non_exhaustive()
    }
}

impl Daemon {
    pub async fn build(config: &Config) -> Result<Self, BuildError> {
        let url = format!("sqlite://{}", config.store.path.display());
        let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&url).await?);
        let mut daemon = Self::with_parts(config, store, build_backends(config)?, build_channels(config)?)?;
        daemon.web.auth = build_authenticator(config)?;
        daemon.web.key = session_key(config)?;
        Ok(daemon)
    }

    pub fn with_parts(
        config: &Config,
        store: Arc<dyn Store>,
        backends: Vec<Arc<dyn AccessBackend>>,
        channels: Vec<Arc<dyn Channel>>,
    ) -> Result<Self, BuildError> {
        let engine = Arc::new(Engine::new(Arc::clone(&store), backends, rules_from(config)));
        let interactive = channels.iter().filter(|c| c.capabilities().interactive).cloned().collect();
        let dispatcher = Arc::new(Dispatcher::new(store, channels, &config.server.public_url));
        let codes = Arc::new(link::LinkCodes::default());
        let sink = Arc::new(link::DaemonSink { engine: Arc::clone(&engine), codes: Arc::clone(&codes) });
        let web = web::AppState {
            engine: Arc::clone(&engine),
            auth: None,
            links: codes,
            key: axum_extra::extract::cookie::Key::generate(),
            settings: Arc::new(web::WebSettings {
                secure_cookies: config.server.public_url.starts_with("https://"),
                session_ttl: config.server.session_ttl,
                fresh_auth_window: config.server.fresh_auth_window,
            }),
        };
        Ok(Self { engine, dispatcher, web, interactive, sink })
    }
}
