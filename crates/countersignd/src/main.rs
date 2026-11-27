use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use jiff::Timestamp;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use countersign_core::{ActionSink, Channel};
use countersignd::config::Config;
use countersignd::tls::{CertReloader, TlsConfig, TlsListener, reloadable_server_config};
use countersignd::{Daemon, rules_from};

#[derive(Debug, Parser)]
#[command(version, about = "Human approval for just-in-time access")]
struct Cli {
    /// Configuration file.
    #[arg(long, short, env = "COUNTERSIGN_CONFIG", default_value = "/etc/countersign/config.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the daemon (default).
    Run,
    /// Validate the configuration and exit.
    Check,
}

const DISPATCH_INTERVAL: Duration = Duration::from_secs(1);
const RECEIVER_MIN_BACKOFF: Duration = Duration::from_secs(5);
const RECEIVER_MAX_BACKOFF: Duration = Duration::from_secs(300);

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        // Plain text for the journal; colours only on a terminal.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,sqlx=warn".into()),
        )
        .init();
    let cli = Cli::parse();

    let config = match Config::load(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            error!("{e}");
            return ExitCode::FAILURE;
        }
    };
    match cli.command.unwrap_or(Command::Run) {
        Command::Check => {
            println!(
                "{}: ok ({} backends, {} channels, {} persons, {} workloads, {} clients, {} policies, {} question policies)",
                cli.config.display(),
                config.backends.len(),
                config.channels.len(),
                config.persons.len(),
                config.workloads.len(),
                config.clients.len(),
                config.policies.policies.len(),
                config.question_policies.policies.len()
            );
            ExitCode::SUCCESS
        }
        Command::Run => match run(cli.config, config).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                error!("{e}");
                ExitCode::FAILURE
            }
        },
    }
}

async fn run(path: PathBuf, config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let daemon = Daemon::build(&config).await?;
    info!(
        backends = config.backends.len(),
        channels = config.channels.len(),
        policies = config.policies.policies.len(),
        "countersignd started"
    );

    let (stop_tx, stop_rx) = watch::channel(false);

    let engine = Arc::clone(&daemon.engine);
    let poll = config.engine.poll_interval;
    let mut stop = stop_rx.clone();
    let ticker = tokio::spawn(async move {
        let mut every = tokio::time::interval(poll);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = every.tick() => engine.tick(Timestamp::now()).await,
                _ = stop.changed() => break,
            }
        }
    });

    let dispatcher = Arc::clone(&daemon.dispatcher);
    let mut stop = stop_rx.clone();
    let delivery = tokio::spawn(async move {
        let mut every = tokio::time::interval(DISPATCH_INTERVAL);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = every.tick() => {
                    if let Err(e) = dispatcher.run_once(Timestamp::now()).await {
                        warn!(error = %e, "outbox delivery failed");
                    }
                }
                _ = stop.changed() => break,
            }
        }
    });

    let receivers: Vec<_> = daemon
        .interactive
        .iter()
        .map(|channel| {
            let channel = Arc::clone(channel);
            let sink: Arc<dyn ActionSink> = daemon.sink.clone();
            let mut stop = stop_rx.clone();
            tokio::spawn(async move {
                tokio::select! {
                    () = receive(channel, sink) => {}
                    _ = stop.changed() => {}
                }
            })
        })
        .collect();

    let mut tls_reloaders = Vec::new();
    let web_tls = load_tls("web UI", config.server.tls.as_ref(), &mut tls_reloaders)?;
    if web_tls.is_none() && !countersignd::config::is_private(config.server.listen.ip()) {
        warn!(
            listen = %config.server.listen,
            "the web UI serves plain HTTP on a public or every address; set server.tls or keep it on a private address behind a TLS proxy"
        );
    }
    let server =
        serve("web UI", config.server.listen, web_tls, countersignd::web::router(daemon.web.clone()), stop_rx.clone())
            .await?;
    info!(url = %config.server.public_url, "web UI public URL");

    let intake = match (&config.intake, daemon.intake.clone()) {
        (Some(ic), Some(state)) => {
            // Config validation guarantees `tls`, or `behind_proxy` on a private address.
            let tls = load_tls("intake API", ic.tls.as_ref(), &mut tls_reloaders)?;
            Some(serve("intake API", ic.listen, tls, countersignd::intake::router(state), stop_rx.clone()).await?)
        }
        _ => None,
    };

    let metrics_server = if let Some(addr) = config.server.metrics_listen {
        if !countersignd::config::is_private(addr.ip()) {
            warn!(listen = %addr, "metrics_listen is on a non-private address; keep it on loopback or a private network");
        }
        let app = countersignd::metrics::router(Arc::clone(daemon.engine.store()), Arc::clone(&daemon.metrics));
        Some(serve("metrics", addr, None, app, stop_rx.clone()).await?)
    } else {
        None
    };

    wait_for_shutdown(&path, &config, &daemon, &tls_reloaders).await;
    info!("shutting down");
    let _ = stop_tx.send(true);
    let mut tasks = vec![ticker, delivery, server];
    tasks.extend(intake);
    tasks.extend(metrics_server);
    tasks.extend(receivers);
    if tokio::time::timeout(Duration::from_secs(10), async {
        for task in tasks {
            let _ = task.await;
        }
    })
    .await
    .is_err()
    {
        warn!("graceful shutdown timed out after 10s; exiting");
    }
    Ok(())
}

fn load_tls(
    what: &'static str,
    tls: Option<&TlsConfig>,
    reloaders: &mut Vec<(&'static str, Arc<CertReloader>)>,
) -> Result<Option<Arc<tokio_rustls::rustls::ServerConfig>>, String> {
    match tls {
        Some(tc) => {
            let (cfg, reloader) = reloadable_server_config(tc)?;
            reloaders.push((what, reloader));
            Ok(Some(cfg))
        }
        None => Ok(None),
    }
}

/// Bind `listen` and serve `app` until `stop` fires: over TLS when a server
/// configuration is given, otherwise plain HTTP for a TLS-terminating proxy.
async fn serve(
    what: &'static str,
    listen: SocketAddr,
    tls: Option<Arc<tokio_rustls::rustls::ServerConfig>>,
    app: axum::Router,
    mut stop: watch::Receiver<bool>,
) -> Result<JoinHandle<()>, Box<dyn std::error::Error>> {
    use axum::serve::ListenerExt as _;

    let tcp = tokio::net::TcpListener::bind(listen).await.map_err(|e| format!("{what}: binding {listen}: {e}"))?;
    let app = app.into_make_service_with_connect_info::<SocketAddr>();
    let shutdown = async move {
        let _ = stop.changed().await;
    };
    let task = if let Some(config) = tls {
        info!(%listen, "{what} listening (HTTPS)");
        // `tap_io` makes the peer address available as `ConnectInfo<SocketAddr>`.
        let listener = TlsListener::new(tcp, config)?.tap_io(|_| {});
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).with_graceful_shutdown(shutdown).await {
                error!(error = %e, "{what} failed");
            }
        })
    } else {
        info!(%listen, "{what} listening (HTTP, TLS terminated in front)");
        tokio::spawn(async move {
            if let Err(e) = axum::serve(tcp, app).with_graceful_shutdown(shutdown).await {
                error!(error = %e, "{what} failed");
            }
        })
    };
    Ok(task)
}

/// Keep an interactive channel's receiver running, backing off on failure.
async fn receive(channel: Arc<dyn Channel>, sink: Arc<dyn ActionSink>) {
    let mut delay = RECEIVER_MIN_BACKOFF;
    loop {
        let started = tokio::time::Instant::now();
        match channel.run(Arc::clone(&sink)).await {
            Ok(()) => return,
            Err(e) => warn!(channel = %channel.name(), error = %e, retry_in = ?delay, "channel receiver stopped"),
        }
        if started.elapsed() > RECEIVER_MAX_BACKOFF {
            delay = RECEIVER_MIN_BACKOFF;
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(RECEIVER_MAX_BACKOFF);
    }
}

/// Wait for SIGINT/SIGTERM. On Unix, SIGHUP reloads persons, workloads,
/// groups, roles, clients, policies and TLS certificates.
#[cfg(unix)]
async fn wait_for_shutdown(
    path: &std::path::Path,
    running: &Config,
    daemon: &Daemon,
    tls_reloaders: &[(&'static str, Arc<CertReloader>)],
) {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut term), Ok(mut hup)) = (signal(SignalKind::terminate()), signal(SignalKind::hangup())) else {
        warn!("cannot install signal handlers; stopping on Ctrl-C only");
        let _ = tokio::signal::ctrl_c().await;
        return;
    };
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return,
            _ = term.recv() => return,
            _ = hup.recv() => reload(path, running, daemon, tls_reloaders),
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown(_: &std::path::Path, _: &Config, _: &Daemon, _: &[(&'static str, Arc<CertReloader>)]) {
    let _ = tokio::signal::ctrl_c().await;
}

/// Swap in the new directory, clients, policies and TLS certificates if valid.
/// Other sections need a restart.
#[cfg_attr(not(unix), allow(dead_code))]
fn reload(
    path: &std::path::Path,
    running: &Config,
    daemon: &Daemon,
    tls_reloaders: &[(&'static str, Arc<CertReloader>)],
) {
    for (what, reloader) in tls_reloaders {
        match reloader.reload() {
            Ok(()) => info!(listener = what, "TLS certificate reloaded"),
            Err(e) => error!(listener = what, "TLS reload failed; keeping previous certificate: {e}"),
        }
    }
    match Config::load(path) {
        Ok(new) => {
            if new.server != running.server
                || new.auth != running.auth
                || new.store.path != running.store.path
                || new.engine.poll_interval != running.engine.poll_interval
                || new.backends != running.backends
                || new.intake != running.intake
                || new.channels != running.channels
            {
                warn!(
                    "server, auth, store.path, engine.poll_interval, backend, intake and channel changes take effect after a restart"
                );
            }
            daemon.engine.set_rules(rules_from(&new));
            info!(
                persons = new.persons.len(),
                clients = new.clients.len(),
                policies = new.policies.policies.len(),
                "configuration reloaded"
            );
        }
        Err(e) => error!("reload failed; keeping the current configuration: {e}"),
    }
}
