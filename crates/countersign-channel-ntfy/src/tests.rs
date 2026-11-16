use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use countersign_core::{
    ActorId, Assurance, Channel, ChannelError, ChannelName, DomainEvent, Notification, PendingSubject, PolicyName,
    Request, RequestState, Requester, Requirements, Selector, SubjectFacts, SubjectRef,
};
use jiff::Timestamp;

use super::{NtfyChannel, NtfyConfig, Publish, publish};

fn request() -> Request {
    let pending = PendingSubject {
        subject: SubjectRef { backend: "oct".into(), kind: "session".into(), id: "s-1".into() },
        facts: SubjectFacts {
            source: None,
            initiator: None,
            sensitive: false,
            requester: Requester {
                id: "agent-7".into(),
                display_name: None,
                groups: BTreeSet::new(),
                ..Requester::default()
            },
            target: Some("db-prod".into()),
            requested_ttl: None,
            reason: Some("rotate\nkeys\u{7}".into()),
            attributes: BTreeMap::new(),
        },
        observed_at: Timestamp::UNIX_EPOCH,
    };
    let reqs = Requirements {
        policy: PolicyName::new("ops"),
        approvers: vec![Selector::Person(ActorId::new("bob"))],
        quorum: 1,
        min_assurance: Assurance::FreshAuth,
        ttl: Duration::from_secs(1800),
        pending_timeout: Duration::from_secs(600),
        exclude: BTreeSet::from([countersign_core::Exclusion::Requester]),
        require_initiator: false,
        grant: countersign_core::GrantMode::Once,
    };
    Request::open(pending, reqs, false, Timestamp::UNIX_EPOCH).0
}

fn config(details: bool) -> NtfyConfig {
    toml::from_str(&format!("server = \"https://ntfy.example\"\ntopic = \"cs-ops\"\ndetails = {details}")).unwrap()
}

const URL: &str = "https://cs.example/requests/x";

#[test]
fn new_requests_carry_details_and_a_review_button() {
    let r = request();
    let ev = DomainEvent::Requested { request_id: r.id, at: Timestamp::UNIX_EPOCH };
    let p = publish(
        &config(true),
        Notification {
            item: countersign_core::Item::Approval(&r),
            event_id: countersign_core::EventId::new(),
            event: &ev,
            web_url: URL,
        },
    );
    assert_eq!(p.topic, "cs-ops");
    assert_eq!(p.title, "Access request: agent-7");
    assert_eq!(p.priority, 4);
    assert_eq!(p.tags, ["key"]);
    assert_eq!(
        p.message,
        "Requester: agent-7\nTarget: db-prod\nPolicy: ops\nDuration: 30m\nReason: rotate keys\nDecide by 1970-01-01 00:10 UTC"
    );
    assert_eq!(p.click.as_deref(), Some(URL));
    assert_eq!(p.actions.len(), 1);
    assert_eq!((p.actions[0].label.as_str(), p.actions[0].action.as_str()), ("Review", "view"));
}

#[test]
fn without_details_nothing_about_the_request_leaves() {
    let mut r = request();
    let ev = DomainEvent::Requested { request_id: r.id, at: Timestamp::UNIX_EPOCH };
    let p = publish(
        &config(false),
        Notification {
            item: countersign_core::Item::Approval(&r),
            event_id: countersign_core::EventId::new(),
            event: &ev,
            web_url: URL,
        },
    );
    let json = serde_json::to_string(&p).unwrap();
    for secret in ["agent-7", "db-prod", "rotate", "\"ops\""] {
        assert!(!json.contains(secret), "{secret} leaked: {json}");
    }
    assert_eq!(p.title, "Access request");

    r.state = RequestState::Failed { error: "boom db-prod".into() };
    let ev = DomainEvent::GrantFailed { request_id: r.id, error: "boom db-prod".into(), at: Timestamp::UNIX_EPOCH };
    let p = publish(
        &config(false),
        Notification {
            item: countersign_core::Item::Approval(&r),
            event_id: countersign_core::EventId::new(),
            event: &ev,
            web_url: "relative/x",
        },
    );
    assert!(!serde_json::to_string(&p).unwrap().contains("db-prod"));
    assert_eq!(p.click, None, "non-http links are dropped");
    assert_eq!(p.actions, []);
}

#[test]
fn outcomes_say_what_happened() {
    let mut r = request();
    let until = Timestamp::from_second(3600).unwrap();
    r.state = RequestState::Active { until };
    let ev = DomainEvent::Granted { request_id: r.id, until, at: Timestamp::UNIX_EPOCH };
    let p = publish(
        &config(true),
        Notification {
            item: countersign_core::Item::Approval(&r),
            event_id: countersign_core::EventId::new(),
            event: &ev,
            web_url: URL,
        },
    );
    assert_eq!(p.title, "Access granted: agent-7");
    assert!(p.message.ends_with("Active until 1970-01-01 01:00 UTC"), "{}", p.message);
    assert_eq!(p.priority, 3);
    assert_eq!(p.actions[0].label, "Open");
}

#[test]
fn bad_configs_are_rejected() {
    let name = ChannelName::new("n");
    let mk = |s: &str| NtfyChannel::new(name.clone(), toml::from_str(s).unwrap());
    assert!(mk("server = \"ftp://x\"\ntopic = \"t\"").is_err());
    assert!(mk("server = \"https://x\"\ntopic = \"a/b\"").is_err());
    assert!(mk("server = \"https://x\"\ntopic = \"t\"\npriority = 9").is_err());
    assert!(toml::from_str::<NtfyConfig>("server = \"https://x\"\ntopic = \"t\"\ntoken = \"x\"").is_err());
}

// ---- over HTTP ----------------------------------------------------------

#[derive(Default)]
struct Captured {
    bodies: Vec<Publish>,
    auth: Vec<Option<String>>,
}

async fn server(status: StatusCode) -> (String, Arc<Mutex<Captured>>) {
    let seen = Arc::new(Mutex::new(Captured::default()));
    let s = Arc::clone(&seen);
    let app = Router::new().route(
        "/",
        post(move |headers: HeaderMap, body: String| {
            let s = Arc::clone(&s);
            async move {
                let mut c = s.lock().unwrap();
                c.bodies.push(serde_json::from_str(&body).unwrap());
                c.auth.push(headers.get("authorization").map(|v| v.to_str().unwrap().to_owned()));
                (status, [("retry-after", "7")], "")
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), seen)
}

fn channel(server: &str, token_file: Option<&std::path::Path>) -> NtfyChannel {
    let mut c = config(true);
    c.server = format!("{server}/");
    c.token_file = token_file.map(ToOwned::to_owned);
    NtfyChannel::new(ChannelName::new("phone"), c).unwrap()
}

#[tokio::test]
async fn publishes_json_with_bearer_token() {
    let (url, seen) = server(StatusCode::OK).await;
    let dir = std::env::temp_dir().join(format!("cs-ntfy-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let token = dir.join("token");
    std::fs::write(&token, "tk_test\n").unwrap();

    let ch = channel(&url, Some(&token));
    assert!(!format!("{ch:?}").contains("tk_test"), "token is not in Debug output");
    let r = request();
    let ev = DomainEvent::Requested { request_id: r.id, at: Timestamp::UNIX_EPOCH };
    assert_eq!(
        ch.notify(Notification {
            item: countersign_core::Item::Approval(&r),
            event_id: countersign_core::EventId::new(),
            event: &ev,
            web_url: URL
        })
        .await
        .unwrap(),
        None
    );

    {
        let c = seen.lock().unwrap();
        assert_eq!(c.bodies.len(), 1);
        assert_eq!(c.bodies[0].title, "Access request: agent-7");
        assert_eq!(c.auth[0].as_deref(), Some("Bearer tk_test"));
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn http_failures_map_to_retryable_or_permanent_errors() {
    let r = request();
    let ev = DomainEvent::Requested { request_id: r.id, at: Timestamp::UNIX_EPOCH };
    let n = Notification {
        item: countersign_core::Item::Approval(&r),
        event_id: countersign_core::EventId::new(),
        event: &ev,
        web_url: URL,
    };

    let (url, _) = server(StatusCode::TOO_MANY_REQUESTS).await;
    let e = channel(&url, None).notify(n).await.unwrap_err();
    assert!(matches!(e, ChannelError::RateLimited { retry_after: Some(d) } if d == Duration::from_secs(7)), "{e:?}");

    let (url, _) = server(StatusCode::BAD_GATEWAY).await;
    assert!(channel(&url, None).notify(n).await.unwrap_err().is_retryable());

    let (url, _) = server(StatusCode::FORBIDDEN).await;
    assert!(!channel(&url, None).notify(n).await.unwrap_err().is_retryable());

    // Nothing listening.
    let e = channel("http://127.0.0.1:9", None).notify(n).await.unwrap_err();
    assert!(e.is_retryable(), "{e:?}");
}

fn question(confidential: bool) -> countersign_core::Question {
    let policy: countersign_core::QuestionPolicy =
        toml::from_str("name = \"deploys\"\nresponders = [\"person:bob\"]\nconfidential = \"allow\"").unwrap();
    let asker = countersign_core::Asker { client: countersign_core::ClientId::new("agent-host"), actor: None };
    let schema = serde_json::json!({"type": "object", "properties": {"go": {"type": "boolean"}}});
    let confidentiality = countersign_core::Confidentiality { question: confidential, answer_may_be: false };
    countersign_core::Question::ask(
        asker,
        "Rotate the TOP-SECRET key?".into(),
        schema,
        BTreeMap::from([("ticket".to_owned(), "OPS-42".to_owned())]),
        &policy,
        confidentiality,
        Timestamp::UNIX_EPOCH,
    )
    .0
}

#[test]
fn questions_and_sensitive_requests_never_carry_their_text() {
    for confidential in [false, true] {
        let q = question(confidential);
        let ev = DomainEvent::Requested { request_id: q.id, at: Timestamp::UNIX_EPOCH };
        let n = Notification {
            item: countersign_core::Item::Question(&q),
            event_id: countersign_core::EventId::new(),
            event: &ev,
            web_url: URL,
        };
        let p = publish(&config(true), n);
        let all = format!("{} {}", p.title, p.message);
        assert!(!all.contains("TOP-SECRET") && !all.contains("OPS-42"), "{all}");
        assert!(p.title.contains("agent-host"), "{}", p.title);
        assert_eq!(p.actions[0].label, "Answer");
    }

    let mut r = request();
    r.sensitive = true;
    let ev = DomainEvent::Requested { request_id: r.id, at: Timestamp::UNIX_EPOCH };
    let n = Notification {
        item: countersign_core::Item::Approval(&r),
        event_id: countersign_core::EventId::new(),
        event: &ev,
        web_url: URL,
    };
    let p = publish(&config(true), n);
    let all = format!("{} {}", p.title, p.message);
    for secret in ["agent-7", "db-prod", "rotate"] {
        assert!(!all.contains(secret), "{secret} leaked: {all}");
    }
    assert!(p.title.starts_with("Sensitive approval request"), "{}", p.title);
}
