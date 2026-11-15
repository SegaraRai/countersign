//! Running `octeliumctl`.

use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;

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
        cmd.args(args.iter().map(OsString::from))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let out = match tokio::time::timeout(self.timeout, cmd.output()).await {
            Ok(r) => r.map_err(RunError::Spawn)?,
            Err(_) => return Err(RunError::Timeout(self.timeout)),
        };
        Ok(CmdOutput {
            success: out.status.success(),
            stdout: out.stdout,
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}
