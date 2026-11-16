//! The question calls as an MCP server, over Streamable HTTP.
//!
//! An agent's MCP client connects with the client's key as a bearer token
//! (`"headers": { "Authorization": "Bearer cshk_…" }`) and gets three tools:
//! `ask_question`, `get_answer` and `withdraw_question`. They are the
//! question endpoints of the intake API, under the same key, scope and
//! question policies.
//!
//! The server is stateless: no sessions, no server-initiated messages. Every
//! POST carries one JSON-RPC message and is answered with JSON
//! (`application/json`), which Streamable HTTP allows; GET and DELETE are
//! refused with 405. Requests from browsers (with an `Origin` header) are
//! refused, which also rules out DNS rebinding.
//!
//! People can take a while to answer, longer than MCP clients usually wait
//! for a tool. `ask_question` therefore waits a bounded time and, if nobody
//! answered yet, returns the question's id with state `pending`; the agent
//! then calls `get_answer` again.

use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};

use super::{
    AskBody, IntakeState, MAX_QUESTION_BODY, MAX_WAIT, Peer, QuestionBody, Scope, ask_as, peer_addr, wait_for_answer,
    withdraw_as,
};

/// Protocol versions this server speaks, newest first.
const VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26"];
/// How long a tool call waits for an answer unless told otherwise. Many MCP
/// clients give up on a tool call after 60 seconds.
const DEFAULT_WAIT: u64 = 45;

// JSON-RPC error codes.
const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

const INSTRUCTIONS: &str = "Ask the people responsible for you a question and get their answer. Use it when you \
    need a decision, a choice or a piece of information only a person can give. An answer is information, never \
    permission: it does not grant access to anything. If a call returns state \"pending\", nobody has answered yet; \
    call get_answer with the id to keep waiting.";

/// GET (a server-sent event stream) and DELETE (ending a session) are not offered.
pub(super) async fn no_stream() -> Response {
    (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, "POST")]).into_response()
}

pub(super) async fn post(
    State(state): State<IntakeState>,
    peer: Peer,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if headers.contains_key(header::ORIGIN) {
        return (StatusCode::FORBIDDEN, "browser requests are not accepted").into_response();
    }
    if let Some(v) = headers.get("mcp-protocol-version")
        && !v.to_str().is_ok_and(|v| VERSIONS.contains(&v))
    {
        return (StatusCode::BAD_REQUEST, "unsupported MCP-Protocol-Version").into_response();
    }
    let client = match state.authenticate(&headers, peer_addr(peer), Scope::Question) {
        Ok(c) => c,
        Err(e) => {
            let mut r = e.into_response();
            r.headers_mut().insert(header::WWW_AUTHENTICATE, header::HeaderValue::from_static("Bearer"));
            return r;
        }
    };
    if body.len() > MAX_QUESTION_BODY + 4096 {
        return reply(rpc_error(&Value::Null, INVALID_REQUEST, "message too large"));
    }
    let Ok(msg) = serde_json::from_slice::<Value>(&body) else {
        return reply(rpc_error(&Value::Null, PARSE_ERROR, "not JSON"));
    };
    let Some(obj) = msg.as_object().filter(|o| o.get("jsonrpc") == Some(&json!("2.0"))) else {
        return reply(rpc_error(&Value::Null, INVALID_REQUEST, "expected one JSON-RPC 2.0 message"));
    };
    let (Some(method), Some(id)) = (obj.get("method").and_then(Value::as_str), obj.get("id")) else {
        // A notification or a response: nothing to answer.
        return StatusCode::ACCEPTED.into_response();
    };
    let params = obj.get("params").cloned().unwrap_or_else(|| json!({}));
    let result = match method {
        "initialize" => Ok(initialize(&params)),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools() })),
        "tools/call" => call(&state, &client, &params).await,
        _ => Err((METHOD_NOT_FOUND, format!("unknown method {method}"))),
    };
    match result {
        Ok(result) => reply(json!({ "jsonrpc": "2.0", "id": id, "result": result })),
        Err((code, message)) => reply(rpc_error(id, code, &message)),
    }
}

fn reply(v: Value) -> Response {
    Json(v).into_response()
}

fn rpc_error(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn initialize(params: &Value) -> Value {
    let asked = params.get("protocolVersion").and_then(Value::as_str);
    let version = asked.filter(|v| VERSIONS.contains(v)).unwrap_or(VERSIONS[0]);
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": "countersign", "version": env!("CARGO_PKG_VERSION") },
        "instructions": INSTRUCTIONS,
    })
}

fn wait_property() -> Value {
    json!({
        "type": "integer",
        "minimum": 0,
        "maximum": MAX_WAIT.as_secs() - 5,
        "description": format!("Seconds to wait for an answer before returning (default {DEFAULT_WAIT})."),
    })
}

fn id_property() -> Value {
    json!({ "type": "string", "description": "The question's id, as ask_question returned it." })
}

fn tools() -> Value {
    let read_only = json!({ "readOnlyHint": true, "openWorldHint": false });
    json!([
        {
            "name": "ask_question",
            "title": "Ask a person",
            "description": "Ask the people responsible for you a question. requestedSchema describes the answer \
                form like MCP elicitation: a flat object of 1-20 properties, each a string (optionally with enum, \
                format email/uri/date/date-time, minLength/maxLength), number, integer or boolean. Returns the \
                question with state \"answered\" (see content), \"declined\", \"expired\", \"withdrawn\", or \
                \"pending\" if nobody answered within wait_seconds; then call get_answer. An answer grants no access. \
                Never ask for passwords, keys or tokens.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "message": { "type": "string", "description": "The question, as people will read it." },
                    "requestedSchema": { "type": "object", "description": "The answer form (see above)." },
                    "context": {
                        "type": "object",
                        "additionalProperties": { "type": "string" },
                        "description": "Extra facts shown to the people answering, e.g. {\"service\": \"api\"}.",
                    },
                    "confidential": {
                        "type": "boolean",
                        "description": "The question itself is confidential: it is kept out of chat and logs.",
                    },
                    "answerMayBeConfidential": {
                        "type": "boolean",
                        "description": "Suggest that the answer be treated as confidential (personal or \
                            business information that should not be kept).",
                    },
                    "wait_seconds": wait_property(),
                },
                "required": ["message", "requestedSchema"],
                "additionalProperties": false,
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "openWorldHint": true },
        },
        {
            "name": "get_answer",
            "title": "Wait for an answer",
            "description": "The state of a question you asked, waiting up to wait_seconds while it is pending. \
                A confidential answer is handed over once; later calls show content_removed.",
            "inputSchema": {
                "type": "object",
                "properties": { "id": id_property(), "wait_seconds": wait_property() },
                "required": ["id"],
                "additionalProperties": false,
            },
            "annotations": read_only,
        },
        {
            "name": "withdraw_question",
            "title": "Withdraw a question",
            "description": "Withdraw a question you asked that nobody has answered yet.",
            "inputSchema": {
                "type": "object",
                "properties": { "id": id_property() },
                "required": ["id"],
                "additionalProperties": false,
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false },
        },
    ])
}

type RpcResult = Result<Value, (i64, String)>;

async fn call(state: &IntakeState, client: &crate::config::ClientConfig, params: &Value) -> RpcResult {
    let name = params.get("name").and_then(Value::as_str).unwrap_or_default();
    let empty = Map::new();
    let args = match params.get("arguments") {
        None | Some(Value::Null) => &empty,
        Some(Value::Object(m)) => m,
        Some(_) => return Err((INVALID_PARAMS, "arguments must be an object".into())),
    };
    let wait = match args.get("wait_seconds") {
        None | Some(Value::Null) => Duration::from_secs(DEFAULT_WAIT),
        Some(v) => Duration::from_secs(v.as_u64().ok_or((INVALID_PARAMS, "wait_seconds must be an integer".into()))?),
    };
    let id = || args.get("id").and_then(Value::as_str).ok_or((INVALID_PARAMS, "id is required".to_owned()));
    let outcome = match name {
        "ask_question" => {
            let body = ask_body(args).map_err(|m| (INVALID_PARAMS, m))?;
            match ask_as(state, client, body).await {
                Ok(q) => wait_for_answer(state, client, &q.id.to_string(), wait).await,
                Err(e) => Err(e),
            }
        }
        "get_answer" => wait_for_answer(state, client, id()?, wait).await,
        "withdraw_question" => {
            let id = id()?;
            match withdraw_as(state, client, id).await {
                Ok(()) => wait_for_answer(state, client, id, Duration::ZERO).await,
                Err(e) => Err(e),
            }
        }
        _ => return Err((INVALID_PARAMS, format!("unknown tool {name:?}"))),
    };
    Ok(match outcome {
        Ok(q) => tool_result(&q),
        // Refusals (no policy, bad schema, not found, ...) are for the agent
        // to read and correct, so they are tool results, not protocol errors.
        Err(e) => json!({ "content": [{ "type": "text", "text": e.message }], "isError": true }),
    })
}

fn ask_body(args: &Map<String, Value>) -> Result<AskBody, String> {
    let message = args.get("message").and_then(Value::as_str).ok_or("message is required")?;
    let schema = args.get("requestedSchema").filter(|v| v.is_object()).ok_or("requestedSchema must be an object")?;
    let context = match args.get("context") {
        None | Some(Value::Null) => std::collections::BTreeMap::default(),
        Some(v) => serde_json::from_value(v.clone()).map_err(|_| "context must map names to strings")?,
    };
    let flag = |k: &str| args.get(k).and_then(Value::as_bool).unwrap_or(false);
    Ok(AskBody {
        message: message.to_owned(),
        requested_schema: schema.clone(),
        context,
        confidentiality: countersign_core::Confidentiality {
            question: flag("confidential"),
            answer_may_be: flag("answerMayBeConfidential"),
        },
    })
}

fn tool_result(q: &QuestionBody) -> Value {
    let structured = serde_json::to_value(q).unwrap_or_default();
    let summary = match q.state.as_str() {
        "pending" => format!("Nobody has answered yet. Call get_answer with id {} to keep waiting.", q.id),
        "answered" if q.content_removed => "Answered, but the confidential answer was already handed over.".into(),
        "answered" => "Answered.".into(),
        "declined" => "The question was declined.".into(),
        other => format!("The question is {other}."),
    };
    json!({
        "content": [
            { "type": "text", "text": summary },
            { "type": "text", "text": structured.to_string() },
        ],
        "structuredContent": structured,
        "isError": false,
    })
}
