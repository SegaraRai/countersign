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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runas: Option<String>,
    pub argv: Vec<String>,
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
    let var = |k: &str| env.get(k).map(String::as_str).unwrap_or_default();
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

    let args = nul_split(&host.cmdline(pid).map_err(io("command line"))?);
    let parsed = parse_sudo_args(&args);
    let environ = nul_split(&host.environ(pid).unwrap_or_default());
    let env_value = |name: &str| {
        environ.iter().find_map(|kv| kv.strip_prefix(name).and_then(|r| r.strip_prefix('=')).map(str::trim))
    };
    let reason = env_value(REASON_ENV).filter(|r| !r.is_empty()).map(str::to_owned);
    let sensitive = env_value(SENSITIVE_ENV).is_some_and(|v| matches!(v, "1" | "true" | "yes"));

    Ok(Invocation {
        user: user.to_owned(),
        runas: parsed.runas,
        argv: parsed.command,
        cwd: host.cwd(pid).ok().map(|p| p.display().to_string()),
        tty: Some(var("PAM_TTY")).filter(|t| !t.is_empty()).map(str::to_owned),
        reason,
        sensitive,
    })
}

/// The parts of a `sudo` command line that matter to approvers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    /// `-u`/`--user`, if given.
    pub runas: Option<String>,
    /// The command, or a description such as `(login shell)` when `sudo`
    /// runs no explicit command. Unrecognised options make this the raw
    /// arguments, so they cannot match command-specific policies.
    pub command: Vec<String>,
}

// Only options that do not change what runs, or how, are recognised.
// Anything else makes the command the raw arguments, which command-specific
// policies do not match. Deliberately left out:
// - `-E`/`--preserve-env`: the caller's environment (LD_PRELOAD, PYTHONPATH,
//   APT_CONFIG, ...) can make a harmless-looking command do anything;
// - `-D`/`--chdir` and `-R`/`--chroot`: relative paths and the programs found
//   resolve somewhere else than approvers assume;
// - `-g`/`--group`: runs with another group, which `runas` would not show.

/// Short options that take a value.
const SHORT_WITH_VALUE: &[char] = &['C', 'h', 'p', 'r', 't', 'T', 'U', 'u'];
/// Short options without a value.
const SHORT_FLAGS: &[char] = &['A', 'b', 'B', 'e', 'H', 'i', 'K', 'k', 'l', 'N', 'n', 'P', 'S', 's', 'V', 'v'];
const LONG_WITH_VALUE: &[&str] =
    &["user", "prompt", "close-from", "host", "role", "type", "command-timeout", "other-user"];
const LONG_FLAGS: &[&str] = &[
    "askpass",
    "background",
    "bell",
    "edit",
    "help",
    "set-home",
    "login",
    "remove-timestamp",
    "reset-timestamp",
    "list",
    "no-update",
    "non-interactive",
    "preserve-groups",
    "stdin",
    "shell",
    "version",
    "validate",
];

/// Parse `sudo`'s arguments (`args[0]` is the program).
pub fn parse_sudo_args(args: &[String]) -> Parsed {
    let raw = || Parsed { runas: None, command: args.iter().skip(1).cloned().collect() };
    let program = args.first().map(|a| a.rsplit('/').next().unwrap_or(a)).unwrap_or_default();
    let Some(opts) = parse_options(args) else { return raw() };
    let rest = &args[opts.end.min(args.len())..];
    match describe(program, &opts.modes, rest) {
        Some(command) => Parsed { runas: opts.runas, command },
        None => raw(),
    }
}

struct Options {
    runas: Option<String>,
    /// Mode letters seen (`i`, `s`, `e`, `l`, `v`, ...).
    modes: Vec<char>,
    /// Index of the first argument after the options.
    end: usize,
}

/// Walk the options. `None` if any is unknown or lacks its value.
fn parse_options(args: &[String]) -> Option<Options> {
    let mut o = Options { runas: None, modes: Vec::new(), end: 1 };
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            i += 1;
            break;
        }
        if let Some(long) = a.strip_prefix("--") {
            let (name, inline) = long.split_once('=').map_or((long, None), |(n, v)| (n, Some(v.to_owned())));
            if LONG_WITH_VALUE.contains(&name) {
                let value = if let Some(v) = inline {
                    v
                } else {
                    i += 1;
                    args.get(i)?.clone()
                };
                if name == "user" {
                    o.runas = Some(value);
                }
            } else if LONG_FLAGS.contains(&name) {
                o.modes.push(match name {
                    "login" => 'i',
                    "shell" => 's',
                    "edit" => 'e',
                    "list" => 'l',
                    "validate" => 'v',
                    "version" => 'V',
                    "help" => 'h',
                    "remove-timestamp" => 'K',
                    _ => '-',
                });
            } else {
                return None;
            }
            i += 1;
            continue;
        }
        let Some(cluster) = a.strip_prefix('-').filter(|c| !c.is_empty()) else { break };
        for (pos, c) in cluster.char_indices() {
            if SHORT_WITH_VALUE.contains(&c) {
                let attached = &cluster[pos + c.len_utf8()..];
                let value = if attached.is_empty() {
                    i += 1;
                    args.get(i)?.clone()
                } else {
                    attached.to_owned()
                };
                if c == 'u' {
                    o.runas = Some(value);
                }
                break;
            } else if SHORT_FLAGS.contains(&c) {
                o.modes.push(c);
            } else {
                return None;
            }
        }
        i += 1;
    }
    o.end = i;
    Some(o)
}

/// What will run, for approvers. `None` when there is nothing sensible to
/// show (no command and no mode that implies one).
fn describe(program: &str, modes: &[char], rest: &[String]) -> Option<Vec<String>> {
    if program == "sudoedit" || modes.contains(&'e') {
        return Some(std::iter::once("sudoedit".to_owned()).chain(rest.iter().cloned()).collect());
    }
    // `VAR=value` before the command sets the command's environment.
    if rest.first().is_some_and(|a| a.split_once('=').is_some_and(|(name, _)| !name.is_empty() && !name.contains('/')))
    {
        return None;
    }
    // With -s or -i the command runs through a shell (with -s, the one named
    // by the caller's SHELL), so it is labelled and cannot match a policy
    // written for the bare command.
    let shell = if modes.contains(&'i') {
        Some("(login shell)")
    } else if modes.contains(&'s') {
        Some("(shell)")
    } else {
        None
    };
    if !rest.is_empty() {
        return Some(shell.map(str::to_owned).into_iter().chain(rest.iter().cloned()).collect());
    }
    let label = if let Some(m) = modes.iter().find(|m| matches!(m, 'l' | 'v' | 'V' | 'h' | 'K' | 'k')) {
        match m {
            'l' => "(list privileges)",
            'v' => "(validate)",
            'V' => "(version)",
            'h' => "(help)",
            _ => "(reset timestamp)",
        }
    } else if modes.contains(&'i') {
        "(login shell)"
    } else if modes.contains(&'s') {
        "(shell)"
    } else {
        return None;
    };
    Some(vec![label.to_owned()])
}
