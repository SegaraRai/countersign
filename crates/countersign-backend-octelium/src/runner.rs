//! Running `octeliumctl`.

use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt as _};

/// Upper bound on bytes read from `octeliumctl`'s stdout (4 MiB).
const MAX_STDOUT: usize = 4 * 1024 * 1024;
/// Upper bound on bytes read from `octeliumctl`'s stderr (64 KiB).
const MAX_STDERR: usize = 64 * 1024;

/// Result of one command invocation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CmdOutput {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

#[derive(Debug)]
pub enum RunError {
    Spawn(std::io::Error),
    Timeout(Duration),
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn(e) => write!(f, "failed to run octeliumctl: {e}"),
            Self::Timeout(d) => write!(f, "octeliumctl did not finish within {}s", d.as_secs()),
        }
    }
}

/// Runs `octeliumctl` with the given arguments. Abstracted for tests.
#[async_trait]
pub trait Runner: Send + Sync + fmt::Debug {
    async fn run(&self, args: &[String]) -> Result<CmdOutput, RunError>;
}

/// Runs a real `octeliumctl` process.
#[derive(Debug, Clone)]
pub struct ProcessRunner {
    pub program: PathBuf,
    pub timeout: Duration,
}

#[async_trait]
impl Runner for ProcessRunner {
    async fn run(&self, args: &[String]) -> Result<CmdOutput, RunError> {
        let mut cmd = tokio::process::Command::new(&self.program);
        // The daemon's own secrets (bot tokens, client secrets) may be in its
        // environment; octeliumctl has no use for them.
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("COUNTERSIGN_") {
                cmd.env_remove(key);
            }
        }
        cmd.args(args.iter().map(OsString::from))
            // One OS thread is plenty for a single request and saves CPU.
            .env("GOMAXPROCS", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = cmd.spawn().map_err(RunError::Spawn)?;
        let Some(stdout) = child.stdout.take() else {
            return Err(RunError::Spawn(std::io::Error::other("stdout was not piped")));
        };
        let Some(stderr) = child.stderr.take() else {
            return Err(RunError::Spawn(std::io::Error::other("stderr was not piped")));
        };
        let run = async {
            let (out, err, status) =
                tokio::join!(read_bounded(stdout, MAX_STDOUT), read_bounded(stderr, MAX_STDERR), child.wait());
            let status = status.map_err(RunError::Spawn)?;
            let stdout = out.map_err(RunError::Spawn)?;
            let stderr = err.map_err(RunError::Spawn)?;
            Ok(CmdOutput { success: status.success(), stdout, stderr: String::from_utf8_lossy(&stderr).into_owned() })
        };
        if let Ok(r) = tokio::time::timeout(self.timeout, run).await {
            r
        } else {
            let _ = child.kill().await;
            Err(RunError::Timeout(self.timeout))
        }
    }
}

async fn read_bounded(mut reader: impl AsyncRead + Unpin, limit: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 8192];
    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        let room = limit.saturating_sub(buf.len());
        if room > 0 {
            buf.extend_from_slice(&chunk[..n.min(room)]);
        }
    }
    Ok(buf)
}
