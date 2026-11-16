//! `countersign-sudo [CONFIG]`: run by `pam_exec` during `sudo` authentication.
//!
//! Exit status 0 means approved; anything else fails authentication.
//!
//! Messages (the approval link, the outcome) go to the calling `sudo`'s
//! stderr when that is a terminal or a pipe. Do not use `pam_exec`'s `stdout`
//! option: without a terminal (`sudo -n`) the PAM conversation fails and
//! `pam_exec` then fails authentication even when the helper approved.

use std::path::PathBuf;
use std::process::ExitCode;

use countersign_sudo::{CONFIG_PATH, Error, Outcome};

fn main() -> ExitCode {
    #[cfg(unix)]
    {
        *OUTPUT.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            open_caller_stderr(std::os::unix::process::parent_id());
    }
    let path = std::env::args_os().nth(1).map_or_else(|| PathBuf::from(CONFIG_PATH), PathBuf::from);
    let outcome = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt.block_on(run(path)),
        Err(e) => Err(Error::Context(e.to_string())),
    };
    match outcome {
        Ok(Outcome::Approved { window }) => {
            say(&format!("countersign: approved{}", if window { " (within an approval window)" } else { "" }));
            ExitCode::SUCCESS
        }
        Ok(Outcome::Refused(why)) => {
            say(&format!("countersign: not approved: {why}"));
            ExitCode::FAILURE
        }
        Err(e) => {
            say(&format!("countersign: {e}"));
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
    Ok(client.ask(&invocation, config.timeout, cancel, &mut |m: &str| say(m)).await)
}

/// Where messages for the person or program running `sudo` go.
static OUTPUT: std::sync::Mutex<Option<std::fs::File>> = std::sync::Mutex::new(None);

/// Show a message to the person or program running `sudo`.
fn say(message: &str) {
    use std::io::Write as _;
    if let Some(f) = OUTPUT.lock().unwrap_or_else(std::sync::PoisonError::into_inner).as_mut() {
        let _ = writeln!(f, "{message}");
    }
}

/// Open the calling `sudo`'s stderr. `pam_exec` gives the helper pipes that
/// nobody reads and no controlling terminal, so this is the only way to
/// reach the user. Reopening runs as root, so only pipes and terminals are
/// accepted: a caller could point its stderr at a file it cannot write.
/// A terminal is opened with `O_NOCTTY`, so it never becomes the helper's
/// controlling terminal (whose signals would then reach the helper).
#[cfg(unix)]
fn open_caller_stderr(pid: u32) -> Option<std::fs::File> {
    use std::os::unix::fs::FileTypeExt as _;
    let link = format!("/proc/{pid}/fd/2");
    let target = std::fs::read_link(&link).ok()?;
    let kind = std::fs::metadata(&link).ok()?.file_type();
    let terminal = kind.is_char_device()
        && target.to_str().is_some_and(|t| t.starts_with("/dev/pts/") || t.starts_with("/dev/tty"));
    if !(kind.is_fifo() || terminal) {
        return None;
    }
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new().append(true).custom_flags(libc::O_NOCTTY).open(&link).ok()
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
