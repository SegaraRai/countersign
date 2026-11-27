use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use jiff::Timestamp;
use serde_json::{Value, json};

use countersign_core::subject::Action as SubjectAction;
use countersign_core::{
    ActionIntent, ActionSink, ActorId, AnswerIntent, Asker, Assurance, ChannelCaps, ChannelName, ClientId,
    Confidentiality, DomainEvent, EventId, GrantMode, Item, Notification, PendingSubject, PolicyName, Question,
    QuestionPolicy, Request, RequestId, Requester, Requirements, Selector, SubjectFacts, SubjectRef, Verdict,
};

use crate::interact::{
    Action, Envelope, Scope, action_id, answer_action_id, decline_action_id, parse_action_id, parse_envelope, perform,
};
use crate::render::{code, mrkdwn, view};
use crate::{SlackConfig, is_allowed_response_url};

fn sample_request(min_assurance: Assurance, sensitive: bool) -> Request {
    let now = Timestamp::from_second(1_700_000_000).unwrap();
    let pending = PendingSubject {
        subject: SubjectRef { backend: "sudo".into(), kind: "sudo".into(), id: "req-1".into() },
        facts: SubjectFacts {
            requester: Requester {
                id: "agent".into(),
                identity: "unix:web-1#agent".into(),
                actor: Some(ActorId::new("deploy-agent")),
                display_name: Some("deploy-agent".into()),
                groups: BTreeSet::new(),
            },
            source: None,
            initiator: None,
            sensitive,
            target: Some("web-1".into()),
            action: Some(SubjectAction::Command {
                line: vec!["sudo".into(), "apt".into(), "update".into()],
                runas: "root".into(),
                cwd: Some("/home/agent".into()),
                notes: vec![],
            }),
            reason: Some("apply security patches".into()),
            requested_ttl: Some(Duration::from_secs(60)),
            attributes: BTreeMap::from([("command".into(), "apt update".into())]),
            binding: None,
        },
        observed_at: now,
    };
    let reqs = Requirements {
        policy: PolicyName::new("sudo-once"),
        approvers: vec![Selector::Group("approvers".into())],
        exclude: BTreeSet::new(),
        require_initiator: false,
        quorum: 1,
        ttl: Duration::from_secs(60),
        min_assurance,
        pending_timeout: Duration::from_secs(300),
        grant: GrantMode::Once,
        scope: BTreeMap::new(),
        channels: Vec::new(),
    };
    Request::open(pending, reqs, sensitive, now).0
}

fn sample_question(confidential: bool, answer_may_be: bool) -> Question {
    let now = Timestamp::from_second(1_700_000_000).unwrap();
    let policy: QuestionPolicy = toml::from_str(
        r#"
        name = "agent-questions"
        match = { asker = "agent-bridge" }
        responders = ["group:approvers"]
        min_assurance = "linked"
        answer_timeout = "10m"
        confidential = "allow"
        "#,
    )
    .unwrap();
    let schema = json!({
        "type": "object",
        "properties": {
            "branch": { "type": "string", "enum": ["main", "release"] }
        },
        "required": ["branch"]
    });
    Question::ask(
        Asker { client: ClientId::new("agent-bridge"), actor: Some(ActorId::new("deploy-agent")) },
        "Which branch should I deploy?".into(),
        schema,
        BTreeMap::new(),
        &policy,
        Confidentiality { question: confidential, answer_may_be },
        now,
    )
    .0
}

fn caps() -> ChannelCaps {
    ChannelCaps { update: true, interactive: true, max_assurance: Some(Assurance::Linked) }
}

fn buttons_in(view: &crate::View) -> Vec<&Value> {
    view.attachments[0]["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|b| b["type"] == "actions")
        .flat_map(|b| b["elements"].as_array().unwrap().iter())
        .collect()
}

#[test]
fn approval_direct_buttons_and_fresh_auth_fallback() {
    let r_linked = sample_request(Assurance::Linked, false);
    let ev = DomainEvent::Requested { request_id: r_linked.id, at: Timestamp::UNIX_EPOCH };
    let v = view(
        Notification {
            item: Item::Approval(&r_linked),
            event_id: EventId::new(),
            event: &ev,
            web_url: "https://cs.example/requests/1",
        },
        caps(),
    );
    let btns = buttons_in(&v);
    assert_eq!(btns.len(), 3);
    assert_eq!(btns[0]["text"]["text"], "Approve");
    assert_eq!(btns[1]["text"]["text"], "Deny");
    assert_eq!(btns[2]["text"]["text"], "Details");

    let r_fresh = sample_request(Assurance::FreshAuth, false);
    let ev2 = DomainEvent::Requested { request_id: r_fresh.id, at: Timestamp::UNIX_EPOCH };
    let v2 = view(
        Notification {
            item: Item::Approval(&r_fresh),
            event_id: EventId::new(),
            event: &ev2,
            web_url: "https://cs.example/requests/2",
        },
        caps(),
    );
    let btns2 = buttons_in(&v2);
    assert_eq!(btns2.len(), 2);
    assert_eq!(btns2[0]["text"]["text"], "Approve in web UI");
    assert_eq!(btns2[0]["url"], "https://cs.example/requests/2");
    assert_eq!(btns2[1]["text"]["text"], "Deny");
}

#[test]
fn sensitive_approval_withholds_details() {
    let r = sample_request(Assurance::Linked, true);
    let ev = DomainEvent::Requested { request_id: r.id, at: Timestamp::UNIX_EPOCH };
    let v = view(
        Notification {
            item: Item::Approval(&r),
            event_id: EventId::new(),
            event: &ev,
            web_url: "https://cs.example/requests/1",
        },
        caps(),
    );
    let rendered = serde_json::to_string(&v.attachments).unwrap();
    assert!(!rendered.contains("apt update"));
    assert!(!rendered.contains("security patches"));
    let btns = buttons_in(&v);
    assert_eq!(btns.len(), 1);
    assert_eq!(btns[0]["text"]["text"], "Review in web UI");
}

#[test]
fn question_choice_buttons_and_confidential_withholding() {
    let q = sample_question(false, false);
    let ev = DomainEvent::Requested { request_id: q.id, at: Timestamp::UNIX_EPOCH };
    let v = view(
        Notification {
            item: Item::Question(&q),
            event_id: EventId::new(),
            event: &ev,
            web_url: "https://cs.example/requests/q1",
        },
        caps(),
    );
    let btns = buttons_in(&v);
    assert_eq!(btns.len(), 3); // main, release, Decline
    assert_eq!(btns[0]["text"]["text"], "main");
    assert_eq!(btns[1]["text"]["text"], "release");
    assert_eq!(btns[2]["text"]["text"], "Decline");

    let q_conf = sample_question(true, true);
    let ev2 = DomainEvent::Requested { request_id: q_conf.id, at: Timestamp::UNIX_EPOCH };
    let v2 = view(
        Notification {
            item: Item::Question(&q_conf),
            event_id: EventId::new(),
            event: &ev2,
            web_url: "https://cs.example/requests/q2",
        },
        caps(),
    );
    let rendered = serde_json::to_string(&v2.attachments).unwrap();
    assert!(!rendered.contains("Which branch"));
    assert!(!rendered.contains("release"));
    let btns2 = buttons_in(&v2);
    assert_eq!(btns2.len(), 1);
    assert_eq!(btns2[0]["text"]["text"], "Answer in web UI");
}

#[test]
fn slack_entities_are_escaped() {
    assert_eq!(mrkdwn("hi <!channel> & <https://evil|x>"), "hi &lt;!channel&gt; &amp; &lt;https://evil|x&gt;");
    assert_eq!(code("<@U123> & `rm`"), "`&lt;@U123&gt; &amp; ˋrmˋ`");
}

#[test]
fn action_id_roundtrip() {
    let id = RequestId::new();
    assert_eq!(parse_action_id(&action_id(Verdict::Approve, id)), Some((Verdict::Approve, id)));
    assert_eq!(parse_action_id(&action_id(Verdict::Deny, id)), Some((Verdict::Deny, id)));
    assert_eq!(parse_action_id("other:approve:123"), None);
}

#[test]
fn response_url_validation() {
    assert!(is_allowed_response_url("https://hooks.slack.com/actions/T123/456/abc"));
    assert!(!is_allowed_response_url("http://hooks.slack.com/actions/T123/456/abc"));
    assert!(!is_allowed_response_url("https://evil.example/hooks.slack.com"));
}

#[test]
fn config_parses_from_toml() {
    let cfg: SlackConfig = toml::from_str(
        r#"
        channel_id = "C012345"
        team_id = "T999"
        bot_token_file = "/etc/countersign/slack-bot"
        app_token_file = "/etc/countersign/slack-app"
        mention_users = ["U1"]
        mention_groups = ["S1"]
        "#,
    )
    .unwrap();
    assert_eq!(cfg.channel_id, "C012345");
    assert_eq!(cfg.team_id.as_deref(), Some("T999"));
}

struct MockSink {
    linked: Mutex<BTreeMap<String, ActorId>>,
    submitted: Mutex<Vec<ActionIntent>>,
    answered: Mutex<Vec<AnswerIntent>>,
}

impl MockSink {
    fn new() -> Self {
        Self { linked: Mutex::default(), submitted: Mutex::default(), answered: Mutex::default() }
    }
}

#[async_trait]
impl ActionSink for MockSink {
    async fn resolve_account(&self, _channel: &ChannelName, external_id: &str) -> Result<Option<ActorId>, String> {
        Ok(self.linked.lock().unwrap().get(external_id).cloned())
    }

    async fn link_account(&self, _channel: &ChannelName, external_id: &str, code: &str) -> Result<ActorId, String> {
        if code == "GOOD-CODE" {
            let alice = ActorId::new("alice");
            self.linked.lock().unwrap().insert(external_id.to_owned(), alice.clone());
            Ok(alice)
        } else {
            Err("invalid code".into())
        }
    }

    async fn submit(&self, intent: ActionIntent) -> Result<Request, String> {
        self.submitted.lock().unwrap().push(intent);
        Ok(sample_request(Assurance::Linked, false))
    }

    async fn answer(&self, intent: AnswerIntent) -> Result<Question, String> {
        self.answered.lock().unwrap().push(intent);
        Ok(sample_question(false, false))
    }
}

#[tokio::test]
async fn socket_mode_link_decide_and_scope_checks() {
    let sink = MockSink::new();
    let scope = Scope { name: ChannelName::new("slack"), channel_id: "C100".into(), team_id: Some("T100".into()) };

    // 1. Link via slash command (allowed from DM).
    let link_env = Envelope {
        envelope_id: Some("env-1".into()),
        kind: "slash_commands".into(),
        payload: json!({
            "command": "/countersign-link",
            "user_id": "U42",
            "channel_id": "D999",
            "team_id": "T100",
            "text": " GOOD-CODE ",
            "response_url": "https://hooks.slack.com/commands/1"
        }),
    };
    let parsed = parse_envelope(&link_env).unwrap();
    assert_eq!(parsed.action, Action::Link { code: "GOOD-CODE".into() });
    let reply = perform(&scope, &sink, &parsed).await;
    assert!(reply.contains("alice"), "reply: {reply}");

    // 2. Approve button in wrong channel is refused.
    let req_id = RequestId::new();
    let wrong_ch = Envelope {
        envelope_id: Some("env-2".into()),
        kind: "interactive".into(),
        payload: json!({
            "type": "block_actions",
            "user": { "id": "U42" },
            "channel": { "id": "C_OTHER" },
            "team": { "id": "T100" },
            "actions": [{ "action_id": action_id(Verdict::Approve, req_id), "value": req_id.to_string() }]
        }),
    };
    let reply = perform(&scope, &sink, &parse_envelope(&wrong_ch).unwrap()).await;
    assert!(reply.contains("does not accept actions here"), "reply: {reply}");
    assert!(sink.submitted.lock().unwrap().is_empty());

    // 3. Approve button in configured channel succeeds.
    let ok_env = Envelope {
        envelope_id: Some("env-3".into()),
        kind: "interactive".into(),
        payload: json!({
            "type": "block_actions",
            "user": { "id": "U42" },
            "channel": { "id": "C100" },
            "team": { "id": "T100" },
            "actions": [{ "action_id": action_id(Verdict::Approve, req_id), "value": req_id.to_string() }]
        }),
    };
    let reply = perform(&scope, &sink, &parse_envelope(&ok_env).unwrap()).await;
    assert!(reply.contains("Recorded your approval as `alice`"), "reply: {reply}");
    assert_eq!(sink.submitted.lock().unwrap().len(), 1);

    // 4. Question answer & decline buttons work.
    let q_id = RequestId::new();
    let ans_env = Envelope {
        envelope_id: Some("env-4".into()),
        kind: "interactive".into(),
        payload: json!({
            "type": "block_actions",
            "user": { "id": "U42" },
            "channel": { "id": "C100" },
            "team": { "id": "T100" },
            "actions": [{ "action_id": answer_action_id(q_id, 0), "value": "{\"branch\":\"main\"}" }]
        }),
    };
    let reply = perform(&scope, &sink, &parse_envelope(&ans_env).unwrap()).await;
    assert!(reply.contains("Recorded your answer as `alice`"), "reply: {reply}");
    assert_eq!(sink.answered.lock().unwrap().len(), 1);

    let dec_env = Envelope {
        envelope_id: Some("env-5".into()),
        kind: "interactive".into(),
        payload: json!({
            "type": "block_actions",
            "user": { "id": "U42" },
            "channel": { "id": "C100" },
            "team": { "id": "T100" },
            "actions": [{ "action_id": decline_action_id(q_id), "value": q_id.to_string() }]
        }),
    };
    let reply = perform(&scope, &sink, &parse_envelope(&dec_env).unwrap()).await;
    assert!(reply.contains("declined to answer"), "reply: {reply}");
    assert_eq!(sink.answered.lock().unwrap().len(), 2);
}
