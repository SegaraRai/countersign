//! `countersign-sudo [CONFIG]`: run by `pam_exec` during `sudo` authentication.
//!
//! Exit status 0 means approved; anything else fails authentication.
//!
//! `countersign-sudo run [--reason TEXT] [--sensitive] -- COMMAND...` is for
//! people: it runs `sudo -- COMMAND...` with the reason and the sensitive
//! flag in the environment, where the PAM side reads them.
//!
//! Messages (the approval link, the outcome) go to the calling `sudo`'s
//! stderr when that is a terminal or a pipe. Do not use `pam_exec`'s `stdout`
//! option: without a terminal (`sudo -n`) the PAM conversation fails and
//! `pam_exec` then fails authentication even when the helper approved.

use std::path::PathBuf;
use std::process::ExitCode;

use countersign_sudo::{CONFIG_PATH, Error, Outcome};

const RUN_USAGE: &str = "usage: countersign-sudo run [--reason TEXT] [--sensitive] -- COMMAND [ARG]...";

fn main() -> ExitCode {
    if std::env::args_os().nth(1).is_some_and(|a| a == "run") {
        return run_sudo(std::env::args_os().skip(2).collect());
    }
    if std::env::args_os().nth(1).is_some_and(|a| a == "enroll") {
        return enroll(std::env::args().skip(2).collect());
    }
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
    let client =
        countersign_sudo::Client::new(&config.server, key, config.ca_file.as_deref(), config.server_keys.clone())?;

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

/// What `countersign-sudo run` was asked to do.
#[derive(Debug, PartialEq, Eq)]
struct RunArgs {
    reason: Option<std::ffi::OsString>,
    sensitive: bool,
    command: Vec<std::ffi::OsString>,
}

fn parse_run_args(args: Vec<std::ffi::OsString>) -> Result<RunArgs, String> {
    let mut it = args.into_iter();
    let mut reason = None;
    let mut sensitive = false;
    while let Some(a) = it.next() {
        match a.to_str() {
            Some("--") => break,
            Some("--sensitive") => sensitive = true,
            Some("--reason") => reason = Some(it.next().ok_or("--reason needs a value")?),
            Some(s) if s.starts_with("--reason=") => reason = Some(s["--reason=".len()..].into()),
            _ => return Err(format!("unexpected argument {}", a.to_string_lossy())),
        }
    }
    let command: Vec<_> = it.collect();
    if command.is_empty() {
        return Err("no command given".into());
    }
    Ok(RunArgs { reason, sensitive, command })
}

const ENROLL_USAGE: &str = "usage: countersign-sudo enroll --server URL [--ca-file PEM] [--server-key ed25519:...] \
                            [--config PATH] [--key-file PATH]";

/// Set this host up: pin countersign's key, create the host key, write the
/// configuration, and print the `[[client]]` entry for countersign.
fn enroll(args: Vec<String>) -> ExitCode {
    let mut e = countersign_sudo::Enroll {
        server: String::new(),
        ca_file: None,
        server_key: None,
        config: PathBuf::from(CONFIG_PATH),
        key_file: PathBuf::from("/etc/countersign/host.key"),
    };
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        let Some(v) = it.next() else {
            eprintln!("countersign-sudo: {a} needs a value\n{ENROLL_USAGE}");
            return ExitCode::from(2);
        };
        match a.as_str() {
            "--server" => e.server = v,
            "--ca-file" => e.ca_file = Some(PathBuf::from(v)),
            "--server-key" => e.server_key = Some(v),
            "--config" => e.config = PathBuf::from(v),
            "--key-file" => e.key_file = PathBuf::from(v),
            _ => {
                eprintln!("countersign-sudo: unknown option {a}\n{ENROLL_USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    if e.server.is_empty() {
        eprintln!("{ENROLL_USAGE}");
        return ExitCode::from(2);
    }
    let mut confirm = |key: &str| {
        use std::io::{BufRead as _, Write as _};
        println!("countersign reports this approval signing key:\n\n  {key}\n");
        println!("Compare it with the key countersignd logs at startup (or `countersign signing-key --public`).");
        print!("Trust it? [y/N] ");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line).is_ok() && matches!(line.trim(), "y" | "Y" | "yes")
    };
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| Error::Context(err.to_string()))
        .and_then(|rt| rt.block_on(countersign_sudo::enroll(&e, &mut confirm)));
    match result {
        Ok(client) => {
            println!("wrote {} and {}.", e.config.display(), e.key_file.display());
            println!("Add this host to countersign's configuration:\n\n{client}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("countersign-sudo: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Replace this process with `sudo -- COMMAND...`. Returns only on failure.
fn run_sudo(args: Vec<std::ffi::OsString>) -> ExitCode {
    let args = match parse_run_args(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("countersign-sudo: {e}\n{RUN_USAGE}");
            return ExitCode::from(2);
        }
    };
    let mut cmd = std::process::Command::new("sudo");
    cmd.arg("--").args(&args.command);
    match &args.reason {
        Some(r) => cmd.env(countersign_sudo::invocation::REASON_ENV, r),
        None => cmd.env_remove(countersign_sudo::invocation::REASON_ENV),
    };
    if args.sensitive {
        cmd.env(countersign_sudo::invocation::SENSITIVE_ENV, "1");
    } else {
        cmd.env_remove(countersign_sudo::invocation::SENSITIVE_ENV);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        let e = cmd.exec();
        eprintln!("countersign-sudo: cannot run sudo: {e}");
        ExitCode::FAILURE
    }
    #[cfg(not(unix))]
    {
        let _ = cmd;
        eprintln!("countersign-sudo only runs on Linux");
        ExitCode::FAILURE
    }
}

#[cfg(not(unix))]
#[allow(clippy::unused_async)] // same signature as the Unix version
async fn run(_: PathBuf) -> Result<Outcome, Error> {
    Err(Error::Context("countersign-sudo only runs on Linux".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(v: &[&str]) -> Vec<std::ffi::OsString> {
        v.iter().map(Into::into).collect()
    }

    #[test]
    fn run_arguments_parse() {
        let a = parse_run_args(os(&["--reason", "fix dns", "--sensitive", "--", "systemctl", "restart", "x"])).unwrap();
        assert_eq!(a.reason, Some("fix dns".into()));
        assert!(a.sensitive);
        assert_eq!(a.command, os(&["systemctl", "restart", "x"]));
        let a = parse_run_args(os(&["--reason=r", "--", "id"])).unwrap();
        assert_eq!(a.reason, Some("r".into()));
        assert!(!a.sensitive);
        assert!(parse_run_args(os(&["--", ""])).is_ok());
        assert!(parse_run_args(os(&["--"])).is_err());
        assert!(parse_run_args(os(&["id"])).is_err());
        assert!(parse_run_args(os(&["--reason"])).is_err());
    }
}
