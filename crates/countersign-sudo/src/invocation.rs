//! What `sudo` was asked to do, read from the waiting `sudo` process.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::Error;

/// Environment variable, in the caller's environment, holding a free-text
/// reason shown to approvers.
pub const REASON_ENV: &str = "COUNTERSIGN_REASON";

/// Environment variable, in the caller's environment: `1` asks to keep the
/// details out of chat channels (the policy decides whether that is honoured).
pub const SENSITIVE_ENV: &str = "COUNTERSIGN_SENSITIVE";

/// Binaries accepted as the calling `sudo` when the configuration does not
/// list any.
pub const DEFAULT_SUDO_BINARIES: &[&str] = &[
    "/usr/bin/sudo",
    "/usr/bin/sudoedit",
    "/usr/bin/sudo-rs",
    "/usr/lib/cargo/bin/sudo",
    "/usr/lib/cargo/bin/sudoedit",
];

/// One `sudo` invocation, as sent to countersign.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Invocation {
    pub user: String,
    /// The whole `sudo` command line as `sudo` received it, with the
    /// program name normalised to `sudo` or `sudoedit`. Approvers see this
    /// line and the approval signature covers it; countersign reads who it
    /// runs as and which command it is from it.
    pub sudo_argv: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tty: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub sensitive: bool,
}

/// Access to the calling process and the user database. Abstracted for tests.
pub trait Host {
    fn exe(&self, pid: u32) -> std::io::Result<PathBuf>;
    fn cmdline(&self, pid: u32) -> std::io::Result<Vec<u8>>;
    fn environ(&self, pid: u32) -> std::io::Result<Vec<u8>>;
    fn cwd(&self, pid: u32) -> std::io::Result<PathBuf>;
    /// The `Uid:` line of `/proc/<pid>/status`.
    fn status(&self, pid: u32) -> std::io::Result<String>;
    /// `/etc/passwd`.
    fn passwd(&self) -> std::io::Result<String>;
}

/// The real system.
#[derive(Debug, Clone, Copy, Default)]
pub struct System;

impl Host for System {
    fn exe(&self, pid: u32) -> std::io::Result<PathBuf> {
        std::fs::read_link(format!("/proc/{pid}/exe"))
    }
    fn cmdline(&self, pid: u32) -> std::io::Result<Vec<u8>> {
        std::fs::read(format!("/proc/{pid}/cmdline"))
    }
    fn environ(&self, pid: u32) -> std::io::Result<Vec<u8>> {
        std::fs::read(format!("/proc/{pid}/environ"))
    }
    fn cwd(&self, pid: u32) -> std::io::Result<PathBuf> {
        std::fs::read_link(format!("/proc/{pid}/cwd"))
    }
    fn status(&self, pid: u32) -> std::io::Result<String> {
        std::fs::read_to_string(format!("/proc/{pid}/status"))
    }
    fn passwd(&self) -> std::io::Result<String> {
        std::fs::read_to_string("/etc/passwd")
    }
}

fn nul_split(bytes: &[u8]) -> Vec<String> {
    let trimmed = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    if trimmed.is_empty() {
        return Vec::new();
    }
    trimmed.split(|&b| b == 0).map(|s| String::from_utf8_lossy(s).into_owned()).collect()
}

/// Read the invocation of the `sudo` process `pid` that is authenticating
/// `PAM_USER`. `env` is this helper's environment (set by `pam_exec`).
pub fn read(
    host: &dyn Host,
    pid: u32,
    env: &BTreeMap<String, String>,
    sudo_binaries: &[PathBuf],
) -> Result<Invocation, Error> {
    let var = |k: &str| env.get(k).map_or_default(String::as_str);
    if var("PAM_TYPE") != "auth" {
        return Err(Error::Context(format!("expected PAM_TYPE=auth, got {:?}", var("PAM_TYPE"))));
    }
    if !matches!(var("PAM_SERVICE"), "sudo" | "sudo-i") {
        return Err(Error::Context(format!("not a sudo PAM service: {:?}", var("PAM_SERVICE"))));
    }
    let user = var("PAM_USER");
    if user.is_empty() {
        return Err(Error::Context("PAM_USER is not set".into()));
    }

    let io =
        |what: &'static str| move |e: std::io::Error| Error::Context(format!("cannot read the caller's {what}: {e}"));
    let exe = host.exe(pid).map_err(io("executable"))?;
    if !sudo_binaries.contains(&exe) {
        return Err(Error::Context(format!("the caller is {}, not sudo", exe.display())));
    }

    // The caller's real uid must be PAM_USER's: sudo authenticates the
    // invoking user, who is the real uid of the setuid process.
    let status = host.status(pid).map_err(io("status"))?;
    let real_uid = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|l| l.split_whitespace().next())
        .ok_or_else(|| Error::Context("no Uid line in the caller's status".into()))?;
    let passwd = host.passwd().map_err(io("user database"))?;
    let user_uid = passwd.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next() == Some(user)).then(|| f.nth(1)).flatten()
    });
    if user_uid != Some(real_uid) {
        return Err(Error::Context(format!("PAM_USER {user} is not the user running sudo (uid {real_uid})")));
    }

    let mut sudo_argv = nul_split(&host.cmdline(pid).map_err(io("command line"))?);
    let Some(program) = sudo_argv.first_mut() else {
        return Err(Error::Context("the caller's command line is empty".into()));
    };
    *program = countersign_core::sudo::program(program).to_owned();
    let environ = nul_split(&host.environ(pid).unwrap_or_default());
    let env_value = |name: &str| {
        environ.iter().find_map(|kv| kv.strip_prefix(name).and_then(|r| r.strip_prefix('=')).map(str::trim))
    };
    let reason = env_value(REASON_ENV).filter(|r| !r.is_empty()).map(str::to_owned);
    let sensitive = env_value(SENSITIVE_ENV).is_some_and(|v| matches!(v, "1" | "true" | "yes"));

    Ok(Invocation {
        user: user.to_owned(),
        sudo_argv,
        cwd: host.cwd(pid).ok().map(|p| p.display().to_string()),
        tty: Some(var("PAM_TTY")).filter(|t| !t.is_empty()).map(str::to_owned),
        reason,
        sensitive,
    })
}
