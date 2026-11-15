//! `countersign-sudo [CONFIG]`: run by `pam_exec` during `sudo` authentication.
//!
//! Messages go to stdout, which `pam_exec`'s `stdout` option shows to the
//! user. Exit status 0 means approved; anything else fails authentication.

use std::path::PathBuf;
use std::process::ExitCode;

use countersign_sudo::{CONFIG_PATH, Error, Outcome};

fn main() -> ExitCode {
    let path = std::env::args_os().nth(1).map_or_else(|| PathBuf::from(CONFIG_PATH), PathBuf::from);
    let outcome = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt.block_on(run(path)),
        Err(e) => Err(Error::Context(e.to_string())),
    };
    match outcome {
        Ok(Outcome::Approved { window }) => {
            println!("countersign: approved{}", if window { " (within an approval window)" } else { "" });
            ExitCode::SUCCESS
        }
        Ok(Outcome::Refused(why)) => {
            println!("countersign: not approved: {why}");
            ExitCode::FAILURE
        }
        Err(e) => {
            println!("countersign: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(unix)]
async fn run(path: PathBuf) -> Result<Outcome, Error> {
    use tokio::signal::unix::{SignalKind, signal};

    let config = countersign_sudo::Config::load(&path)?;
    let env = std::env::vars().collect();
    let invocation = countersign_sudo::invocation::read(
        &countersign_sudo::System,
        std::os::unix::process::parent_id(),
        &env,
        &config.sudo_binaries,
    )?;
    let key = countersign_sudo::read_key(&config.key_file)?;
    let client = countersign_sudo::Client::new(&config.server, key)?;

    let mut signals = Vec::new();
    for kind in [SignalKind::interrupt(), SignalKind::terminate(), SignalKind::hangup()] {
        signals.push(signal(kind).map_err(|e| Error::Context(format!("cannot handle signals: {e}")))?);
    }
    let cancel = async move {
        let waits = signals.iter_mut().map(|s| Box::pin(s.recv()));
        let _ = futures_select_any(waits).await;
    };
    let mut say = |m: &str| println!("{m}");
    Ok(client.ask(&invocation, config.timeout, cancel, &mut say).await)
}

/// Resolve when the first of several futures does.
#[cfg(unix)]
async fn futures_select_any<F: Future + Unpin>(futures: impl IntoIterator<Item = F>) {
    let mut futures: Vec<F> = futures.into_iter().collect();
    std::future::poll_fn(|cx| {
        for f in &mut futures {
            if std::pin::Pin::new(f).poll(cx).is_ready() {
                return std::task::Poll::Ready(());
            }
        }
        std::task::Poll::Pending
    })
    .await;
}

#[cfg(not(unix))]
#[allow(clippy::unused_async)] // same signature as the Unix version
async fn run(_: PathBuf) -> Result<Outcome, Error> {
    Err(Error::Context("countersign-sudo only runs on Linux".into()))
}
