//! CLI client for asking structured questions through countersign's intake API.
//!
//! Designed for CI approval/confirmation gates, shell scripts, and AI agents
//! running without MCP:
//! - Progress and the review URL go to `stderr`.
//! - The final outcome JSON goes to `stdout`.
//! - Exit codes distinguish outcomes cleanly:
//!   - `0`: answered (`accept`)
//!   - `2`: declined (`decline`)
//!   - `3`: expired (no answer in time)
//!   - `4`: withdrawn (cancelled)
//!   - `1`: error (usage, auth, network, policy refusal)

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::{Args, Parser};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Exit code for an accepted answer.
pub const EXIT_ANSWERED: u8 = 0;
/// Exit code for operational, auth, or usage errors.
pub const EXIT_ERROR: u8 = 1;
/// Exit code when a responder declined the question.
pub const EXIT_DECLINED: u8 = 2;
/// Exit code when nobody answered before the deadline.
pub const EXIT_EXPIRED: u8 = 3;
/// Exit code when the question was withdrawn (e.g. Ctrl-C / SIGTERM).
pub const EXIT_WITHDRAWN: u8 = 4;

const POLL_WAIT_SECS: u64 = 50;
const HTTP_TIMEOUT: Duration = Duration::from_secs(70);

#[derive(Debug, Parser)]
#[command(
    name = "countersign-ask",
    version,
    about = "Ask a human a structured question through countersign and wait for the answer"
)]
pub struct Cli {
    /// countersign intake base URL (`https://...`, or `<http://localhost>` for local dev).
    #[arg(long, env = "COUNTERSIGN_SERVER")]
    pub server: String,

    /// Client bearer token (or set `COUNTERSIGN_TOKEN`). Prefer --token-file or --github-oidc.
    #[arg(long, env = "COUNTERSIGN_TOKEN", conflicts_with_all = ["token_file", "github_oidc"])]
    pub token: Option<String>,

    /// File holding the client bearer token (`cshk_…`).
    #[arg(long, conflicts_with_all = ["token", "github_oidc"])]
    pub token_file: Option<PathBuf>,

    /// Fetch an OIDC JWT from GitHub Actions (`ACTIONS_ID_TOKEN_REQUEST_URL`).
    #[arg(long, conflicts_with_all = ["token", "token_file"])]
    pub github_oidc: bool,

    /// Audience requested when using --github-oidc.
    #[arg(long, default_value = "countersign", requires = "github_oidc")]
    pub audience: String,

    /// Extra PEM CA certificate(s) to trust for the intake server.
    #[arg(long)]
    pub ca_file: Option<PathBuf>,

    /// Question shown to responders.
    #[arg(long, short)]
    pub message: String,

    #[command(flatten)]
    pub schema: SchemaArgs,

    /// Field name used by --yes-no, --choice, and --text.
    #[arg(long, default_value = "answer")]
    pub field: String,

    /// Optional context key=value pairs shown alongside the question.
    #[arg(long = "context", value_name = "KEY=VALUE")]
    pub context: Vec<String>,

    /// Mark the question text and schema as confidential (kept out of chat).
    #[arg(long)]
    pub confidential: bool,

    /// Hint to responders that their answer may be confidential.
    #[arg(long)]
    pub answer_may_be_confidential: bool,

    /// Maximum time to wait before withdrawing the question (e.g. 15m, 300s).
    #[arg(long, default_value = "15m", value_parser = humantime::parse_duration)]
    pub timeout: Duration,
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct SchemaArgs {
    /// Ask a boolean Yes/No question.
    #[arg(long)]
    pub yes_no: bool,

    /// Ask a single-select question (repeat for each option, e.g. --choice main --choice release).
    #[arg(long = "choice", value_name = "OPTION")]
    pub choices: Vec<String>,

    /// Ask for a freeform text response.
    #[arg(long)]
    pub text: bool,

    /// Inline JSON Schema (MCP elicitation subset).
    #[arg(long, value_name = "JSON")]
    pub schema: Option<String>,

    /// Path to a JSON Schema file (MCP elicitation subset).
    #[arg(long, value_name = "PATH")]
    pub schema_file: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum AskError {
    #[error("{0}")]
    Usage(String),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("server rejected request ({status}): {message}")]
    Rejected { status: u16, message: String },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuestionResponse {
    pub id: String,
    pub state: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub content: Option<Value>,
    #[serde(default)]
    pub answered_by: Option<String>,
    #[serde(default)]
    pub answered_at: Option<String>,
    #[serde(default)]
    pub confidential: Option<bool>,
}

/// Build the `requestedSchema` JSON from CLI flags.
pub fn build_schema(args: &SchemaArgs, field: &str) -> Result<Value, AskError> {
    if args.yes_no {
        return Ok(json!({
            "type": "object",
            "properties": { field: { "type": "boolean" } },
            "required": [field],
        }));
    }
    if !args.choices.is_empty() {
        return Ok(json!({
            "type": "object",
            "properties": { field: { "type": "string", "enum": args.choices } },
            "required": [field],
        }));
    }
    if args.text {
        return Ok(json!({
            "type": "object",
            "properties": { field: { "type": "string", "minLength": 1 } },
            "required": [field],
        }));
    }
    if let Some(raw) = &args.schema {
        return serde_json::from_str(raw).map_err(|e| AskError::Usage(format!("invalid --schema JSON: {e}")));
    }
    if let Some(path) = &args.schema_file {
        let raw =
            std::fs::read_to_string(path).map_err(|e| AskError::Usage(format!("reading {}: {e}", path.display())))?;
        return serde_json::from_str(&raw)
            .map_err(|e| AskError::Usage(format!("invalid JSON in {}: {e}", path.display())));
    }
    Err(AskError::Usage("specify one of --yes-no, --choice, --text, --schema, or --schema-file".into()))
}

/// Parse `--context KEY=VALUE` entries.
pub fn parse_context(entries: &[String]) -> Result<BTreeMap<String, String>, AskError> {
    let mut map = BTreeMap::new();
    for entry in entries {
        let Some((k, v)) = entry.split_once('=') else {
            return Err(AskError::Usage(format!("invalid --context {entry:?}: expected KEY=VALUE")));
        };
        let k = k.trim();
        if k.is_empty() {
            return Err(AskError::Usage(format!("invalid --context {entry:?}: key is empty")));
        }
        map.insert(k.to_owned(), v.to_owned());
    }
    Ok(map)
}

/// Map a terminal question state to a CLI exit code.
pub fn exit_code_for_state(state: &str) -> u8 {
    match state {
        "answered" => EXIT_ANSWERED,
        "declined" => EXIT_DECLINED,
        "expired" => EXIT_EXPIRED,
        "withdrawn" => EXIT_WITHDRAWN,
        _ => EXIT_ERROR,
    }
}

fn build_http(server: &str, ca_file: Option<&Path>) -> Result<reqwest::Client, AskError> {
    if !countersign_core::url::is_secure(server) {
        return Err(AskError::Usage(format!(
            "server must be an https:// URL (http:// only for localhost), got {server:?}"
        )));
    }
    let mut builder = reqwest::Client::builder()
        .https_only(!countersign_core::url::is_local_http(server))
        .timeout(HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("countersign-ask/", env!("CARGO_PKG_VERSION")));
    if let Some(path) = ca_file {
        let pem = std::fs::read(path).map_err(|e| AskError::Usage(format!("reading {}: {e}", path.display())))?;
        let certs = reqwest::Certificate::from_pem_bundle(&pem)
            .map_err(|e| AskError::Usage(format!("parsing {}: {e}", path.display())))?;
        if certs.is_empty() {
            return Err(AskError::Usage(format!("{}: no certificates found", path.display())));
        }
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }
    builder.build().map_err(|e| AskError::Http(e.to_string()))
}

async fn resolve_token(cli: &Cli, http: &reqwest::Client) -> Result<String, AskError> {
    if let Some(tok) = &cli.token {
        let t = tok.trim();
        if !t.is_empty() {
            return Ok(t.to_owned());
        }
    }
    if let Some(path) = &cli.token_file {
        let raw =
            std::fs::read_to_string(path).map_err(|e| AskError::Usage(format!("reading {}: {e}", path.display())))?;
        let t = raw.trim();
        if t.is_empty() {
            return Err(AskError::Usage(format!("{} is empty", path.display())));
        }
        return Ok(t.to_owned());
    }
    if cli.github_oidc {
        return fetch_github_oidc_token(http, &cli.audience).await;
    }
    Err(AskError::Usage("provide --token / COUNTERSIGN_TOKEN, --token-file, or --github-oidc".into()))
}

async fn fetch_github_oidc_token(http: &reqwest::Client, audience: &str) -> Result<String, AskError> {
    let url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL")
        .map_err(|_| AskError::Usage("ACTIONS_ID_TOKEN_REQUEST_URL is not set (enable `id-token: write`)".into()))?;
    let req_token = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        .map_err(|_| AskError::Usage("ACTIONS_ID_TOKEN_REQUEST_TOKEN is not set".into()))?;
    if !countersign_core::url::is_secure(&url) {
        return Err(AskError::Usage("ACTIONS_ID_TOKEN_REQUEST_URL must be https://".into()));
    }
    let sep = if url.contains('?') { '&' } else { '?' };
    let full = format!("{url}{sep}audience={audience}");
    let resp = http
        .get(&full)
        .bearer_auth(req_token)
        .send()
        .await
        .map_err(|e| AskError::Http(format!("GitHub OIDC token request failed: {}", e.without_url())))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(AskError::Rejected {
            status: status.as_u16(),
            message: "GitHub OIDC token endpoint refused request".into(),
        });
    }
    let body: Value = resp.json().await.map_err(|e| AskError::Http(e.to_string()))?;
    body.get("value")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| AskError::Http("GitHub OIDC response contained no token".into()))
}

async fn withdraw(http: &reqwest::Client, base: &str, token: &str, id: &str) {
    let url = format!("{base}/intake/v1/questions/{id}");
    let _ = http.delete(&url).bearer_auth(token).send().await;
}

/// Submit the question, wait for the outcome (withdrawing on timeout or signal),
/// and return the final [`QuestionResponse`].
pub async fn run(cli: &Cli) -> Result<QuestionResponse, AskError> {
    let base = cli.server.trim_end_matches('/');
    let schema = build_schema(&cli.schema, &cli.field)?;
    let context = parse_context(&cli.context)?;
    let http = build_http(base, cli.ca_file.as_deref())?;
    let token = resolve_token(cli, &http).await?;

    let mut payload = json!({
        "message": cli.message,
        "requestedSchema": schema,
        "confidentiality": {
            "question": cli.confidential,
            "answerMayBe": cli.answer_may_be_confidential,
        }
    });
    if !context.is_empty() {
        payload["context"] = json!(context);
    }

    let create_url = format!("{base}/intake/v1/questions");
    let resp = http
        .post(&create_url)
        .bearer_auth(&token)
        .json(&payload)
        .send()
        .await
        .map_err(|e| AskError::Http(e.without_url().to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(AskError::Rejected { status: status.as_u16(), message: text });
    }
    let created: QuestionResponse = resp.json().await.map_err(|e| AskError::Http(e.to_string()))?;
    if let Some(url) = &created.url {
        eprintln!("countersign: waiting for answer at {url}");
    } else {
        eprintln!("countersign: waiting for answer (id={})", created.id);
    }

    let deadline = Instant::now() + cli.timeout;
    let poll_url = format!("{base}/intake/v1/questions/{}", created.id);

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            eprintln!("countersign: local timeout reached; withdrawing question");
            withdraw(&http, base, &token, &created.id).await;
            return Ok(QuestionResponse {
                id: created.id,
                state: "withdrawn".into(),
                url: created.url,
                action: Some("cancel".into()),
                content: None,
                answered_by: None,
                answered_at: None,
                confidential: None,
            });
        }
        let wait = remaining.as_secs().clamp(1, POLL_WAIT_SECS);
        let req = http.get(&poll_url).bearer_auth(&token).query(&[("wait", wait)]).send();
        let resp = tokio::select! {
            res = req => res.map_err(|e| AskError::Http(e.without_url().to_string()))?,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("countersign: interrupted; withdrawing question");
                withdraw(&http, base, &token, &created.id).await;
                return Ok(QuestionResponse {
                    id: created.id,
                    state: "withdrawn".into(),
                    url: created.url,
                    action: Some("cancel".into()),
                    content: None,
                    answered_by: None,
                    answered_at: None,
                    confidential: None,
                });
            }
        };
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(AskError::Rejected { status: status.as_u16(), message: text });
        }
        let current: QuestionResponse = resp.json().await.map_err(|e| AskError::Http(e.to_string()))?;
        if current.state != "pending" {
            return Ok(current);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_yes_no_choice_and_text_schemas() {
        let cli = Cli::try_parse_from([
            "countersign-ask",
            "--server",
            "https://cs.example",
            "--token",
            "tok",
            "--message",
            "Proceed?",
            "--yes-no",
        ])
        .unwrap();
        let s = build_schema(&cli.schema, &cli.field).unwrap();
        assert_eq!(s["properties"]["answer"]["type"], "boolean");

        let cli2 = Cli::try_parse_from([
            "countersign-ask",
            "--server",
            "https://cs.example",
            "--token",
            "tok",
            "--message",
            "Branch?",
            "--choice",
            "main",
            "--choice",
            "release",
            "--field",
            "branch",
        ])
        .unwrap();
        let s2 = build_schema(&cli2.schema, &cli2.field).unwrap();
        assert_eq!(s2["properties"]["branch"]["enum"], json!(["main", "release"]));
    }

    #[test]
    fn parses_context_and_exit_codes() {
        let ctx = parse_context(&["env=prod".into(), "sha=abc=123".into()]).unwrap();
        assert_eq!(ctx.get("env").map(String::as_str), Some("prod"));
        assert_eq!(ctx.get("sha").map(String::as_str), Some("abc=123"));
        assert!(parse_context(&["missing-equals".into()]).is_err());

        assert_eq!(exit_code_for_state("answered"), EXIT_ANSWERED);
        assert_eq!(exit_code_for_state("declined"), EXIT_DECLINED);
        assert_eq!(exit_code_for_state("expired"), EXIT_EXPIRED);
        assert_eq!(exit_code_for_state("withdrawn"), EXIT_WITHDRAWN);
    }
}
