//! Running the helper program.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// Cap on stderr read into memory (stdout is capped at `crate::MAX_OUTPUT + 1`).
const MAX_STDERR_BYTES: u64 = 64 * 1024;

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
            let stdout_cap = (crate::MAX_OUTPUT + 1) as u64;
            let child_stdout = child.stdout.take();
            let child_stderr = child.stderr.take();
            let read_stdout = async {
                let mut buf = Vec::new();
                if let Some(out) = child_stdout {
                    out.take(stdout_cap).read_to_end(&mut buf).await?;
                }
                Ok::<_, std::io::Error>(buf)
            };
            let read_stderr = async {
                let mut buf = Vec::new();
                if let Some(err) = child_stderr {
                    err.take(MAX_STDERR_BYTES).read_to_end(&mut buf).await?;
                }
                Ok::<_, std::io::Error>(buf)
            };
            let (stdout, stderr, status) = tokio::try_join!(read_stdout, read_stderr, child.wait())?;
            Ok::<_, std::io::Error>(CmdOutput {
                success: status.success(),
                stdout,
                stderr: String::from_utf8_lossy(&stderr).into_owned(),
            })
        };
        match tokio::time::timeout(self.timeout, run).await {
            Ok(r) => r.map_err(RunError::Spawn),
            Err(_) => Err(RunError::Timeout(self.timeout)),
        }
    }
}
