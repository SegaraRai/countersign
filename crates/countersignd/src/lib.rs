//! The countersign daemon, as a library so it can be embedded and tested.

pub mod config;
pub mod dispatch;
pub mod engine;
pub mod intake;
pub mod link;
pub mod metrics;
pub mod tls;
pub mod web;

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
    #[error("auth: {0}")]
    Auth(#[from] countersign_core::AuthError),
    #[error("session key: {0}")]
    SessionKey(String),
    #[error("intake signing key: {0}")]
    SigningKey(String),
    #[error("channel {name}: {source}")]
    Channel { name: String, source: countersign_core::ChannelError },
    #[error(transparent)]
    Pages(#[from] web::PagesError),
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

/// Refuse secret files that are accessible to "others" (`o+rwx`). Group read
/// (`0640`) is permitted so files owned by root can be read by the daemon's group.
#[cfg_attr(not(unix), allow(clippy::unnecessary_wraps))]
fn check_secret_permissions(path: &std::path::Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?.permissions().mode();
        if mode & 0o007 != 0 {
            return Err(format!("{} must not be accessible by others (mode {:04o})", path.display(), mode & 0o777));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// The cookie key: from `session_key_file`, or random (sessions end on restart).
pub fn session_key(config: &Config) -> Result<axum_extra::extract::cookie::Key, BuildError> {
    use axum_extra::extract::cookie::Key;
    let Some(path) = &config.server.session_key_file else {
        tracing::warn!("server.session_key_file is not set; using a random key (web sessions end on restart)");
        return Ok(Key::generate());
    };
    check_secret_permissions(path).map_err(BuildError::SessionKey)?;
    let bytes = std::fs::read(path).map_err(|e| BuildError::SessionKey(format!("{}: {e}", path.display())))?;
    if bytes.len() < 32 {
        return Err(BuildError::SessionKey(format!("{} must hold at least 32 bytes", path.display())));
    }
    Ok(Key::derive_from(&bytes))
}

/// Read countersign's approval signing key (`intake.signing_key_file`).
pub fn signing_key(path: &std::path::Path) -> Result<countersign_core::approval_signing::ServerKey, BuildError> {
    check_secret_permissions(path).map_err(BuildError::SigningKey)?;
    let text = std::fs::read_to_string(path).map_err(|e| BuildError::SigningKey(format!("{}: {e}", path.display())))?;
    countersign_core::approval_signing::ServerKey::parse(&text).ok_or_else(|| {
        BuildError::SigningKey(format!(
            "{} does not hold a signing key (create one with `countersign signing-key`)",
            path.display()
        ))
    })
}

/// The directory, policies and clients from a configuration, as engine rules.
pub fn rules_from(config: &Config) -> Rules {
    let clients = config
        .clients
        .iter()
        .map(|c| {
            let mut c = c.clone();
            if c.has_scope(config::Scope::Approval) {
                c.backend = config.client_backend(&c);
            }
            (c.id.clone(), c)
        })
        .collect();
    Rules {
        directory: config.directory().clone(),
        policies: config.policies.clone(),
        question_policies: config.question_policies.clone(),
        clients,
        unmatched: config.engine.unmatched,
        idp_max_age: config.server.idp_max_age(),
        retention: config.store.retention,
    }
}

/// Instantiate the configured backends. `host` backends keep their record
/// in `store`.
pub fn build_backends(config: &Config, store: &Arc<dyn Store>) -> Result<Vec<Arc<dyn AccessBackend>>, BuildError> {
    config
        .backends
        .iter()
        .map(|(name, bc)| -> Result<Arc<dyn AccessBackend>, BuildError> {
            match bc {
                BackendConfig::Host(_) => Ok(Arc::new(intake::HostBackend::new(name.clone(), Arc::clone(store)))),
                #[cfg(feature = "backend-octelium")]
                BackendConfig::Octelium(c) => {
                    countersign_backend_octelium::OcteliumBackend::new(name.clone(), c.clone())
                        .map(|b| Arc::new(b) as Arc<dyn AccessBackend>)
                        .map_err(|source| BuildError::Backend { name: name.to_string(), source })
                }
                #[cfg(feature = "backend-exec")]
                BackendConfig::Exec(c) => countersign_backend_exec::ExecBackend::new(name.clone(), c)
                    .map(|b| Arc::new(b) as Arc<dyn AccessBackend>)
                    .map_err(|source| BuildError::Backend { name: name.to_string(), source }),
                #[allow(unreachable_patterns)]
                _ => unreachable!("backend type {name} not compiled in"),
            }
        })
        .collect()
}

/// Channels built from configuration, plus the VAPID public key if Web Push is enabled.
pub struct BuiltChannels {
    pub channels: Vec<Arc<dyn Channel>>,
    pub vapid_public_key: Option<String>,
}

impl std::fmt::Debug for BuiltChannels {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<_> = self.channels.iter().map(|c| c.name().to_string()).collect();
        f.debug_struct("BuiltChannels")
            .field("channels", &names)
            .field("webpush", &self.vapid_public_key.is_some())
            .finish()
    }
}

/// Instantiate the configured channels. Reads secrets; does not connect.
pub fn build_channels(
    config: &Config,
    store: Option<&Arc<dyn Store>>,
    engine: Option<&Arc<Engine>>,
) -> Result<BuiltChannels, BuildError> {
    let mut vapid_public_key = None;
    let mut out = Vec::with_capacity(config.channels.len());
    for (name, cc) in &config.channels {
        let ch: Arc<dyn Channel> = match cc {
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
            #[cfg(feature = "channel-slack")]
            ChannelConfig::Slack(c) => Arc::new(
                countersign_channel_slack::SlackChannel::new(name.clone(), c.clone())
                    .map_err(|source| BuildError::Channel { name: name.to_string(), source })?,
            ),
            #[cfg(feature = "channel-webhook")]
            ChannelConfig::Webhook(c) => Arc::new(
                countersign_channel_webhook::WebhookChannel::new(name.clone(), c)
                    .map_err(|source| BuildError::Channel { name: name.to_string(), source })?,
            ),
            #[cfg(feature = "channel-webpush")]
            ChannelConfig::Webpush(c) => {
                check_secret_permissions(&c.vapid_key_file).map_err(|msg| BuildError::Channel {
                    name: name.to_string(),
                    source: countersign_core::ChannelError::Other(msg.into()),
                })?;
                let text = std::fs::read_to_string(&c.vapid_key_file).map_err(|e| BuildError::Channel {
                    name: name.to_string(),
                    source: countersign_core::ChannelError::Other(
                        format!("vapid_key_file {}: {e}", c.vapid_key_file.display()).into(),
                    ),
                })?;
                let vapid = countersign_channel_webpush::VapidKey::parse(&text).ok_or_else(|| BuildError::Channel {
                    name: name.to_string(),
                    source: countersign_core::ChannelError::Other(
                        format!(
                            "{} does not hold a VAPID key (create one with `countersign vapid-key`)",
                            c.vapid_key_file.display()
                        )
                        .into(),
                    ),
                })?;
                vapid_public_key = Some(vapid.public_key_base64url().to_owned());
                let store = store.cloned().ok_or_else(|| BuildError::Channel {
                    name: name.to_string(),
                    source: countersign_core::ChannelError::Other("webpush requires a store".into()),
                })?;
                let engine = engine.cloned().ok_or_else(|| BuildError::Channel {
                    name: name.to_string(),
                    source: countersign_core::ChannelError::Other("webpush requires an engine".into()),
                })?;
                let resolver: countersign_channel_webpush::RecipientResolver = Arc::new(move |item, now| {
                    let engine = Arc::clone(&engine);
                    let approval = match item {
                        countersign_core::Item::Approval(r) => Some(r.clone()),
                        countersign_core::Item::Question(_) => None,
                    };
                    let question = match item {
                        countersign_core::Item::Question(q) => Some(q.clone()),
                        countersign_core::Item::Approval(_) => None,
                    };
                    Box::pin(async move {
                        let Ok((rules, standing)) = engine.standing().await else {
                            return std::collections::BTreeSet::new();
                        };
                        let roster = rules.roster(&standing, now);
                        let mut eligible = std::collections::BTreeSet::new();
                        for actor in roster.directory.actors().filter(|a| a.is_person()) {
                            let ok = match (&approval, &question) {
                                (Some(r), _) => r.eligible(&roster, &actor.id).is_ok(),
                                (_, Some(q)) => q.eligible(&roster, &actor.id).is_ok(),
                                _ => false,
                            };
                            if ok {
                                eligible.insert(actor.id.clone());
                            }
                        }
                        eligible
                    })
                });
                let ch = countersign_channel_webpush::WebPushChannel::new(
                    name.clone(),
                    c.clone(),
                    vapid,
                    &config.server.public_url,
                    store,
                    resolver,
                )
                .map_err(|source| BuildError::Channel { name: name.to_string(), source })?;
                Arc::new(ch)
            }
        };
        out.push(ch);
    }
    Ok(BuiltChannels { channels: out, vapid_public_key })
}

/// Everything the daemon runs.
pub struct Daemon {
    pub engine: Arc<Engine>,
    pub dispatcher: Arc<Dispatcher>,
    pub metrics: Arc<metrics::Metrics>,
    pub web: web::AppState,
    /// Channels whose [`Channel::run`] should be kept running.
    pub interactive: Vec<Arc<dyn Channel>>,
    pub sink: Arc<link::DaemonSink>,
    /// The API for hosts, if `[intake]` is configured.
    pub intake: Option<intake::IntakeState>,
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
        let backends = build_backends(config, &store)?;
        let metrics = Arc::new(metrics::Metrics::default());
        let engine =
            Arc::new(Engine::with_metrics(Arc::clone(&store), backends, rules_from(config), Arc::clone(&metrics)));
        let BuiltChannels { channels, vapid_public_key } = build_channels(config, Some(&store), Some(&engine))?;
        let mut daemon = Self::with_engine(config, store, engine, channels, vapid_public_key, metrics)?;
        daemon.web.auth = build_authenticator(config)?;
        daemon.web.key = session_key(config)?;
        daemon.web.pages = web::Pages::start(&daemon.web).await?;
        if daemon.web.pages.is_none() {
            tracing::warn!("this countersignd was built without the web UI: only sign-in and the JSON API answer");
        }
        Ok(daemon)
    }

    pub fn with_parts(
        config: &Config,
        store: Arc<dyn Store>,
        backends: Vec<Arc<dyn AccessBackend>>,
        channels: Vec<Arc<dyn Channel>>,
    ) -> Result<Self, BuildError> {
        let metrics = Arc::new(metrics::Metrics::default());
        let engine =
            Arc::new(Engine::with_metrics(Arc::clone(&store), backends, rules_from(config), Arc::clone(&metrics)));
        Self::with_engine(config, store, engine, channels, None, metrics)
    }

    fn with_engine(
        config: &Config,
        store: Arc<dyn Store>,
        engine: Arc<Engine>,
        channels: Vec<Arc<dyn Channel>>,
        vapid_public_key: Option<String>,
        metrics: Arc<metrics::Metrics>,
    ) -> Result<Self, BuildError> {
        let interactive = channels.iter().filter(|c| c.capabilities().interactive).cloned().collect();
        let dispatcher =
            Arc::new(Dispatcher::with_metrics(store, channels, &config.server.public_url, Arc::clone(&metrics)));
        let disp = Arc::clone(&dispatcher);
        engine.set_admin_notifier(Arc::new(move |action| {
            let disp = Arc::clone(&disp);
            Box::pin(async move {
                disp.announce_admin(&action).await;
            })
        }));
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
                public_origin: web::origin_of(&config.server.public_url),
            }),
            pages: None,
            vapid_public_key,
        };
        let intake = match &config.intake {
            Some(i) => {
                let key = Arc::new(signing_key(&i.signing_key_file)?);
                tracing::info!(public_key = %key.public(), "intake approvals are signed; clients pin this key");
                Some(intake::IntakeState::new(Arc::clone(&engine), i, &config.server.public_url, key))
            }
            None => None,
        };
        Ok(Self { engine, dispatcher, metrics, web, interactive, sink, intake })
    }
}
