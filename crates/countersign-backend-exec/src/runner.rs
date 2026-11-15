//! Running the helper program.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt as _;

/// Result of one invocation.
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
            Self::Spawn(e) => write!(f, "failed to run the helper: {e}"),
            Self::Timeout(d) => write!(f, "the helper did not finish within {}s", d.as_secs()),
        }
    }
}

/// Runs the helper for one operation. Abstracted for tests.
#[async_trait]
pub trait Runner: Send + Sync + fmt::Debug {
    async fn run(&self, op: &str, input: &[u8]) -> Result<CmdOutput, RunError>;
}

/// Runs a real process: `program args... <op>`, the request on stdin.
#[derive(Debug, Clone)]
pub struct ProcessRunner {
    pub program: PathBuf,
    pub args: Vec<String>,
    /// The complete environment of the child (nothing is inherited).
    pub env: BTreeMap<String, String>,
    pub timeout: Duration,
}

#[async_trait]
impl Runner for ProcessRunner {
    async fn run(&self, op: &str, input: &[u8]) -> Result<CmdOutput, RunError> {
        let mut cmd = tokio::process::Command::new(&self.program);
        cmd.args(&self.args)
            .arg(op)
            .env_clear()
            .envs(&self.env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let run = async {
            let mut child = cmd.spawn()?;
            if let Some(mut stdin) = child.stdin.take() {
                // A helper may exit without reading; that is its business.
                let _ = stdin.write_all(input).await;
                drop(stdin);
            }
            child.wait_with_output().await
        };
        let out = match tokio::time::timeout(self.timeout, run).await {
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
