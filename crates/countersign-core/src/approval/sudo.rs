//! Reading a `sudo` command line the way approvers and policies need it.
//!
//! The helper on the host sends the command line exactly as `sudo` received
//! it; that raw line is what approvers see and what the approval signature
//! covers. countersign's own reading of it ([`parse`]) decides who the
//! command runs as and which command it is, for policy matching. Options it
//! does not understand make the reading fall back to the raw arguments, so
//! a command-specific policy (such as a window for `apt*`) cannot match
//! something that only looks like that command.

/// countersign's reading of a `sudo` command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    /// `-u`/`--user`, if given.
    pub runas: Option<String>,
    /// The command, or a description such as `(login shell)` when `sudo`
    /// runs no explicit command. When the line could not be interpreted
    /// this is the raw arguments after the program.
    pub command: Vec<String>,
    /// Why the line was not interpreted, for approvers. `None` when it was.
    pub uninterpreted: Option<String>,
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

/// Explanations for options countersign deliberately does not interpret.
fn why_not(option: &str) -> String {
    let what = match option {
        "-E" | "--preserve-env" => "keeps the caller's environment",
        "-D" | "--chdir" => "changes the working directory",
        "-R" | "--chroot" => "changes the root directory",
        "-g" | "--group" => "runs with another group",
        _ => return format!("{option} is not an option countersign interprets"),
    };
    format!("{option} {what}")
}

/// The program name `sudo` acts as for `argv0`: `sudoedit` or `sudo`.
#[must_use]
pub fn program(argv0: &str) -> &'static str {
    if argv0.rsplit('/').next() == Some("sudoedit") { "sudoedit" } else { "sudo" }
}

/// Read `sudo`'s arguments (`args[0]` is the program).
#[must_use]
pub fn parse(args: &[String]) -> Parsed {
    let raw = |why: String| Parsed {
        runas: None,
        command: args.iter().skip(1).cloned().collect(),
        uninterpreted: Some(format!("{why}, so policies for specific commands do not apply")),
    };
    let program = program(args.first().map_or("", String::as_str));
    let opts = match parse_options(args) {
        Ok(o) => o,
        Err(option) => return raw(why_not(&option)),
    };
    let rest = &args[opts.end.min(args.len())..];
    match describe(program, &opts.modes, rest) {
        Ok(command) => Parsed { runas: opts.runas, command, uninterpreted: None },
        Err(why) => raw(why.to_owned()),
    }
}

struct Options {
    runas: Option<String>,
    /// Mode letters seen (`i`, `s`, `e`, `l`, `v`, ...).
    modes: Vec<char>,
    /// Index of the first argument after the options.
    end: usize,
}

/// Walk the options. `Err` names the first one that is unknown or lacks its
/// value.
fn parse_options(args: &[String]) -> Result<Options, String> {
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
                    args.get(i).ok_or_else(|| format!("--{name}"))?.clone()
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
                return Err(format!("--{name}"));
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
                    args.get(i).ok_or_else(|| format!("-{c}"))?.clone()
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
                return Err(format!("-{c}"));
            }
        }
        i += 1;
    }
    o.end = i;
    Ok(o)
}

/// What will run, for policies. `Err` says why there is nothing sensible to
/// match on.
fn describe(program: &str, modes: &[char], rest: &[String]) -> Result<Vec<String>, &'static str> {
    if program == "sudoedit" || modes.contains(&'e') {
        return Ok(std::iter::once("sudoedit".to_owned()).chain(rest.iter().cloned()).collect());
    }
    // `VAR=value` before the command sets the command's environment.
    if rest.first().is_some_and(|a| a.split_once('=').is_some_and(|(name, _)| !name.is_empty() && !name.contains('/')))
    {
        return Err("VAR=value sets the command's environment");
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
        return Ok(shell.map(str::to_owned).into_iter().chain(rest.iter().cloned()).collect());
    }
    let label = if let Some(m) = modes.iter().find(|m| matches!(m, 'l' | 'v' | 'V' | 'h' | 'K' | 'k')) {
        match m {
            'l' => "(list privileges)",
            'v' => "(validate)",
            'V' => "(version)",
            'h' => "(help)",
            _ => "(reset timestamp)",
        }
    } else if let Some(shell) = shell {
        shell
    } else {
        return Err("there is no command");
    };
    Ok(vec![label.to_owned()])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|a| (*a).to_owned()).collect()
    }

    fn parsed(s: &[&str]) -> Parsed {
        parse(&args(s))
    }

    fn read(runas: Option<&str>, command: &[&str]) -> Parsed {
        Parsed { runas: runas.map(str::to_owned), command: args(command), uninterpreted: None }
    }

    #[test]
    fn reads_common_sudo_command_lines() {
        assert_eq!(parsed(&["sudo", "apt", "upgrade", "-y"]), read(None, &["apt", "upgrade", "-y"]));
        assert_eq!(
            parsed(&["sudo", "-u", "postgres", "psql", "-c", "select 1"]),
            read(Some("postgres"), &["psql", "-c", "select 1"])
        );
        assert_eq!(parsed(&["sudo", "-nupostgres", "id"]).runas.as_deref(), Some("postgres"));
        assert_eq!(parsed(&["sudo", "--user=www", "--", "ls", "-l"]), read(Some("www"), &["ls", "-l"]));
        assert_eq!(parsed(&["sudo", "--user", "www", "-H", "env"]).command, args(&["env"]));
        assert_eq!(parsed(&["sudo", "-i"]).command, args(&["(login shell)"]));
        assert_eq!(parsed(&["sudo", "-iu", "deploy"]), read(Some("deploy"), &["(login shell)"]));
        assert_eq!(parsed(&["sudo", "-s"]).command, args(&["(shell)"]));
        assert_eq!(parsed(&["sudo", "-i", "whoami"]).command, args(&["(login shell)", "whoami"]));
        assert_eq!(parsed(&["sudo", "-v"]).command, args(&["(validate)"]));
        assert_eq!(parsed(&["sudo", "-l"]).command, args(&["(list privileges)"]));
        assert_eq!(parsed(&["sudo", "-e", "/etc/hosts"]).command, args(&["sudoedit", "/etc/hosts"]));
        assert_eq!(parsed(&["sudoedit", "/etc/hosts"]).command, args(&["sudoedit", "/etc/hosts"]));
    }

    #[test]
    fn options_it_does_not_interpret_fall_back_to_the_raw_arguments() {
        // Unrecognised syntax must not be mistaken for an innocuous command.
        let p = parsed(&["sudo", "-E", "apt", "upgrade"]);
        assert_eq!(p.command, args(&["-E", "apt", "upgrade"]));
        assert_eq!(
            p.uninterpreted.as_deref(),
            Some("-E keeps the caller's environment, so policies for specific commands do not apply")
        );
        assert_eq!(parsed(&["sudo", "-X", "id"]).command, args(&["-X", "id"]));
        assert!(parsed(&["sudo", "-X", "id"]).uninterpreted.unwrap().starts_with("-X is not an option"));
        assert_eq!(parsed(&["sudo", "--chdir=/tmp", "id"]).command, args(&["--chdir=/tmp", "id"]));
        let p = parsed(&["sudo", "LD_PRELOAD=/x.so", "apt"]);
        assert_eq!(p.command, args(&["LD_PRELOAD=/x.so", "apt"]));
        assert!(p.uninterpreted.unwrap().starts_with("VAR=value"));
        assert!(parsed(&["sudo", "-u"]).uninterpreted.is_some());
        assert!(parsed(&["sudo"]).uninterpreted.is_some());
    }

    /// Command lines whose command looks harmless but is not what runs, or not
    /// how approvers would assume, never come out as the bare command, so they
    /// cannot match a policy written for it.
    #[test]
    fn options_that_change_what_runs_are_not_hidden() {
        for argv in [
            &["sudo", "-E", "id"][..],
            &["sudo", "--preserve-env", "id"],
            &["sudo", "--preserve-env=LD_PRELOAD", "id"],
            &["sudo", "-D", "/tmp", "id"],
            &["sudo", "--chdir=/tmp", "id"],
            &["sudo", "-R", "/tmp/root", "id"],
            &["sudo", "--chroot", "/tmp/root", "id"],
            &["sudo", "-g", "disk", "id"],
            &["sudo", "-nE", "id"],
            &["sudo", "LD_PRELOAD=/tmp/x.so", "id"],
            &["sudo", "-u", "root", "PATH=/tmp", "id"],
        ] {
            let p = parsed(argv);
            assert_eq!(p.command, args(argv)[1..], "{argv:?}");
            assert_ne!(p.command, args(&["id"]), "{argv:?}");
        }
        // A shell runs the command (with -s, whichever the caller's SHELL names).
        assert_eq!(parsed(&["sudo", "-s", "id"]).command, args(&["(shell)", "id"]));
        assert_eq!(parsed(&["sudo", "--shell", "id"]).command, args(&["(shell)", "id"]));
        assert_eq!(parsed(&["sudo", "-u", "root", "-i", "id"]).command, args(&["(login shell)", "id"]));
        // An argument that merely contains '=' after the command is fine.
        assert_eq!(parsed(&["sudo", "env", "A=1"]).command, args(&["env", "A=1"]));
        assert_eq!(parsed(&["sudo", "./a=b"]).command, args(&["./a=b"]));
        assert_eq!(parsed(&["sudo", "--frobnicate", "apt"]).command, args(&["--frobnicate", "apt"]));
        assert_eq!(parsed(&["sudo", "-u"]).command, args(&["-u"]));
        assert_eq!(parsed(&["sudo"]).command, Vec::<String>::new());
    }

    #[test]
    fn the_program_is_sudo_or_sudoedit() {
        assert_eq!(program("/usr/bin/sudo"), "sudo");
        assert_eq!(program("sudo-rs"), "sudo");
        assert_eq!(program("/usr/lib/cargo/bin/sudoedit"), "sudoedit");
    }
}
