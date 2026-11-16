use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use countersignd::config::Config;
use countersignd::{Daemon, rules_from};
use jiff::Timestamp;
use tokio::sync::watch;
use tracing::{error, info, warn};

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
                "{}: ok ({} backends, {} channels, {} approvers, {} policies)",
                cli.config.display(),
                config.backends.len(),
                config.channels.len(),
                config.approvers.len(),
                config.policies.policies.len()
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
            let sink: Arc<dyn countersign_core::ActionSink> = daemon.sink.clone();
            let mut stop = stop_rx.clone();
            tokio::spawn(async move {
                tokio::select! {
                    () = receive(channel, sink) => {}
                    _ = stop.changed() => {}
                }
            })
        })
        .collect();

    let listener = tokio::net::TcpListener::bind(config.server.listen).await?;
    info!(listen = %config.server.listen, url = %config.server.public_url, "web UI listening");
    if !countersignd::config::is_private(config.server.listen.ip()) {
        warn!(listen = %config.server.listen, "the web UI listens on a public or every address; keep it private and put it behind a proxy");
    }
    let app = countersignd::web::router(daemon.web.clone());
    let mut stop = stop_rx.clone();
    let server = tokio::spawn(async move {
        let shutdown = async move {
            let _ = stop.changed().await;
        };
        if let Err(e) = axum::serve(listener, app).with_graceful_shutdown(shutdown).await {
            error!(error = %e, "web server failed");
        }
    });

    let intake = match (&config.intake, daemon.intake.clone()) {
        (Some(ic), Some(state)) => {
            let listener = tokio::net::TcpListener::bind(ic.listen).await?;
            info!(listen = %ic.listen, "intake API listening");
            if !countersignd::config::is_private(ic.listen.ip()) {
                warn!(listen = %ic.listen, "the intake API (plain HTTP) listens on a public or every address; bind it to a private (tailnet) address");
            }
            let app = countersignd::intake::router(state).into_make_service_with_connect_info::<std::net::SocketAddr>();
            let mut stop = stop_rx.clone();
            Some(tokio::spawn(async move {
                let shutdown = async move {
                    let _ = stop.changed().await;
                };
                if let Err(e) = axum::serve(listener, app).with_graceful_shutdown(shutdown).await {
                    error!(error = %e, "intake server failed");
                }
            }))
        }
        _ => None,
    };

    wait_for_shutdown(&path, &config, &daemon).await;
    info!("shutting down");
    let _ = stop_tx.send(true);
    let _ = tokio::join!(ticker, delivery, server);
    if let Some(i) = intake {
        let _ = i.await;
    }
    for r in receivers {
        let _ = r.await;
    }
    Ok(())
}

/// Keep an interactive channel's receiver running, backing off on failure.
async fn receive(channel: Arc<dyn countersign_core::Channel>, sink: Arc<dyn countersign_core::ActionSink>) {
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

/// Wait for SIGINT/SIGTERM. On Unix, SIGHUP reloads policies and approvers.
#[cfg(unix)]
async fn wait_for_shutdown(path: &std::path::Path, running: &Config, daemon: &Daemon) {
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
            _ = hup.recv() => reload(path, running, daemon),
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown(_: &std::path::Path, _: &Config, _: &Daemon) {
    let _ = tokio::signal::ctrl_c().await;
}

/// Swap in new policies and approvers if the file is valid. Other sections
/// need a restart.
#[cfg_attr(not(unix), allow(dead_code))]
fn reload(path: &std::path::Path, running: &Config, daemon: &Daemon) {
    match Config::load(path) {
        Ok(new) => {
            if new.server != running.server
                || new.store != running.store
                || new.engine.poll_interval != running.engine.poll_interval
                || new.backends != running.backends
                || new.intake != running.intake
                || new.channels != running.channels
            {
                warn!("server, store, engine timing, backend, intake and channel changes take effect after a restart");
            }
            daemon.engine.set_rules(rules_from(&new));
            info!(policies = new.policies.policies.len(), approvers = new.approvers.len(), "configuration reloaded");
        }
        Err(e) => error!("reload failed; keeping the current configuration: {e}"),
    }
}
