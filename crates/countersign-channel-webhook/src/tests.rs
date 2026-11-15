use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use countersign_core::{
    ApproverId, ApproverSelector, Assurance, Channel, ChannelError, ChannelName, DomainEvent, EventId, Notification,
    PendingSubject, PolicyName, Request, Requester, Requirements, SubjectFacts, SubjectRef,
};
use jiff::Timestamp;

use super::{WebhookChannel, WebhookConfig, parse_secret, sign};

/// The example from the Standard Webhooks specification.
#[test]
fn signature_matches_the_standard_webhooks_example() {
    let key = parse_secret("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw").unwrap();
    assert_eq!(
        sign(&key, "msg_p5jXN8AQM9LWM0D4loKWxJek", 1_614_265_330, br#"{"test": 2432232314}"#),
        "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="
    );
}

#[test]
fn secrets_must_be_long_enough_and_valid() {
    assert!(parse_secret("short").is_err());
    assert!(parse_secret("whsec_!!!notbase64").is_err());
    assert!(parse_secret("whsec_AAAA").is_err(), "decodes to 3 bytes");
    assert_eq!(parse_secret("a-raw-secret-of-24-bytes").unwrap(), b"a-raw-secret-of-24-bytes");
}

fn tmp(name: &str, content: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("cs-webhook-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(name);
    std::fs::write(&p, content).unwrap();
    p
}

fn cfg(s: &str) -> WebhookConfig {
    toml::from_str(s).unwrap()
}

#[test]
fn signing_is_required_unless_explicitly_waived() {
    let name = ChannelName::new("w");
    let secret = tmp("secret-cfg", "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw\n");
    let secret = secret.display().to_string().replace('\\', "/");
    assert!(WebhookChannel::new(name.clone(), &cfg("url = \"https://h.example/x\"")).is_err());
    assert!(WebhookChannel::new(name.clone(), &cfg("url = \"https://h.example/x\"\nunsigned = true")).is_ok());
    assert!(
        WebhookChannel::new(name.clone(), &cfg(&format!("url = \"https://h.example/x\"\nsecret_file = \"{secret}\"")))
            .is_ok()
    );
    assert!(
        WebhookChannel::new(
            name.clone(),
            &cfg(&format!("url = \"https://h.example/x\"\nsecret_file = \"{secret}\"\nunsigned = true"))
        )
        .is_err()
    );
    assert!(WebhookChannel::new(name, &cfg("url = \"file:///etc/passwd\"\nunsigned = true")).is_err());
    assert!(toml::from_str::<WebhookConfig>("url = \"https://x\"\nsecret = \"inline\"").is_err());
}

fn request() -> Request {
    let pending = PendingSubject {
        subject: SubjectRef { backend: "oct".into(), kind: "session".into(), id: "s-1".into() },
        facts: SubjectFacts {
            requester: Requester {
                id: "agent-7".into(),
                display_name: None,
                groups: BTreeSet::new(),
                identities: BTreeSet::new(),
            },
            target: Some("db-prod".into()),
            requested_ttl: None,
            reason: None,
            attributes: BTreeMap::new(),
        },
        observed_at: Timestamp::UNIX_EPOCH,
    };
    let reqs = Requirements {
        policy: PolicyName::new("ops"),
        approvers: vec![ApproverSelector::Approver(ApproverId::new("bob"))],
        quorum: 1,
        min_assurance: Assurance::FreshAuth,
        ttl: Duration::from_secs(1800),
        pending_timeout: Duration::from_secs(600),
        allow_self_approval: false,
    };
    Request::open(pending, reqs, Timestamp::UNIX_EPOCH).0
}

struct Hit {
    headers: HeaderMap,
    body: Bytes,
}

async fn server(status: StatusCode) -> (String, Arc<Mutex<Vec<Hit>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = Arc::clone(&seen);
    let app = Router::new().route(
        "/hook",
        post(move |headers: HeaderMap, body: Bytes| {
            let s = Arc::clone(&s);
            async move {
                s.lock().unwrap().push(Hit { headers, body });
                (status, [("retry-after", "3")], "")
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}/hook"), seen)
}

fn header(h: &HeaderMap, name: &str) -> String {
    h.get(name).unwrap().to_str().unwrap().to_owned()
}

#[tokio::test]
async fn posts_signed_events_that_receivers_can_verify() {
    let (url, seen) = server(StatusCode::NO_CONTENT).await;
    let secret = tmp("secret", "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");
    let token = tmp("token", "hook-token\n");
    let config = WebhookConfig { url, secret_file: Some(secret), bearer_token_file: Some(token), unsigned: false };
    let ch = WebhookChannel::new(ChannelName::new("auto"), &config).unwrap();
    assert!(!format!("{ch:?}").contains("hook-token"));

    let r = request();
    let ev = DomainEvent::Requested { request_id: r.id, at: Timestamp::UNIX_EPOCH };
    let event_id = EventId::new();
    let n = Notification { request: &r, event_id, event: &ev, web_url: "https://cs.example/requests/x" };
    assert_eq!(ch.notify(n).await.unwrap(), None);
    assert_eq!(ch.notify(n).await.unwrap(), None, "a retry");

    let hits = seen.lock().unwrap();
    assert_eq!(hits.len(), 2);
    let key = parse_secret("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw").unwrap();
    for hit in hits.iter() {
        let id = header(&hit.headers, "webhook-id");
        assert_eq!(id, event_id.to_string(), "stable across retries");
        let ts: i64 = header(&hit.headers, "webhook-timestamp").parse().unwrap();
        assert!((Timestamp::now().as_second() - ts).abs() < 60);
        assert_eq!(header(&hit.headers, "webhook-signature"), sign(&key, &id, ts, &hit.body));
        assert_eq!(header(&hit.headers, "authorization"), "Bearer hook-token");
        assert_eq!(header(&hit.headers, "content-type"), "application/json");

        let v: serde_json::Value = serde_json::from_slice(&hit.body).unwrap();
        assert_eq!(v["id"], event_id.to_string());
        assert_eq!(v["type"], "requested");
        assert_eq!(v["url"], "https://cs.example/requests/x");
        assert_eq!(v["event"]["type"], "requested");
        assert_eq!(v["request"]["facts"]["requester"]["id"], "agent-7");
        assert_eq!(v["request"]["state"]["state"], "pending");
    }
    // Tampering is detectable.
    let hit = &hits[0];
    let id = header(&hit.headers, "webhook-id");
    let ts: i64 = header(&hit.headers, "webhook-timestamp").parse().unwrap();
    let mut forged = hit.body.to_vec();
    forged.extend_from_slice(b" ");
    assert_ne!(header(&hit.headers, "webhook-signature"), sign(&key, &id, ts, &forged));
}

#[tokio::test]
async fn unsigned_hooks_send_no_signature_and_errors_are_classified() {
    let r = request();
    let ev = DomainEvent::Expired { request_id: r.id, at: Timestamp::UNIX_EPOCH };
    let n = Notification { request: &r, event_id: EventId::new(), event: &ev, web_url: "https://cs.example/r" };
    let unsigned = |url: String| {
        WebhookChannel::new(
            ChannelName::new("w"),
            &WebhookConfig { url, secret_file: None, bearer_token_file: None, unsigned: true },
        )
        .unwrap()
    };

    let (url, seen) = server(StatusCode::OK).await;
    unsigned(url).notify(n).await.unwrap();
    assert!(seen.lock().unwrap()[0].headers.get("webhook-signature").is_none());

    let (url, _) = server(StatusCode::TOO_MANY_REQUESTS).await;
    let e = unsigned(url).notify(n).await.unwrap_err();
    assert!(matches!(e, ChannelError::RateLimited { retry_after: Some(d) } if d == Duration::from_secs(3)), "{e:?}");
    let (url, _) = server(StatusCode::SERVICE_UNAVAILABLE).await;
    assert!(unsigned(url).notify(n).await.unwrap_err().is_retryable());
    let (url, _) = server(StatusCode::GONE).await;
    assert!(!unsigned(url).notify(n).await.unwrap_err().is_retryable());
    // Redirects are not followed (and not success).
    let (url, _) = server(StatusCode::FOUND).await;
    assert!(unsigned(url).notify(n).await.is_err());
}
