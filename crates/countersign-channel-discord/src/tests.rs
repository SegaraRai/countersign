use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use countersign_core::{
    ActionIntent, ActionSink, ApproverId, ApproverSelector, Assurance, ChannelCaps, ChannelName, DomainEvent,
    Notification, PendingSubject, PolicyName, Request, RequestState, Requester, Requirements, SubjectFacts, SubjectRef,
    Verdict,
};
use jiff::Timestamp;
use serde_json::json;
use twilight_model::application::interaction::Interaction;
use twilight_model::channel::message::Component;
use twilight_model::channel::message::component::ButtonStyle;
use twilight_model::id::Id;

use crate::interact::{self, Action, Scope};
use crate::render::{self, view};
use crate::{DiscordConfig, custom_id, parse_custom_id, parse_message_ref};

const CHANNEL: u64 = 1000;
const GUILD: u64 = 2000;
const USER: u64 = 3000;

fn request(min_assurance: Assurance, reason: Option<&str>) -> Request {
    let pending = PendingSubject {
        subject: SubjectRef { backend: "oct".into(), kind: "session".into(), id: "s-1".into() },
        facts: SubjectFacts {
            requester: Requester {
                id: "alice".into(),
                display_name: Some("Alice `@everyone`".into()),
                groups: BTreeSet::new(),
                identities: BTreeSet::new(),
            },
            target: Some("ssh-host".into()),
            requested_ttl: None,
            reason: reason.map(str::to_owned),
            attributes: BTreeMap::new(),
        },
        observed_at: Timestamp::UNIX_EPOCH,
    };
    let reqs = Requirements {
        policy: PolicyName::new("ops"),
        approvers: vec![ApproverSelector::Approver(ApproverId::new("bob"))],
        quorum: 1,
        min_assurance,
        ttl: Duration::from_secs(5400),
        pending_timeout: Duration::from_secs(600),
        allow_self_approval: false,
        grant: countersign_core::GrantMode::Once,
    };
    Request::open(pending, reqs, Timestamp::UNIX_EPOCH).0
}

fn caps() -> ChannelCaps {
    ChannelCaps { update: true, interactive: true, max_assurance: Some(Assurance::Linked) }
}

fn render(r: &Request) -> render::View {
    let event = DomainEvent::Requested { request_id: r.id, at: Timestamp::UNIX_EPOCH };
    view(
        Notification {
            request: r,
            event_id: countersign_core::EventId::new(),
            event: &event,
            web_url: "https://cs.example/requests/x",
        },
        caps(),
    )
}

/// `(label, style, custom_id, url)` of each button.
fn buttons(v: &render::View) -> Vec<(String, ButtonStyle, Option<String>, Option<String>)> {
    v.components
        .iter()
        .flat_map(|c| match c {
            Component::ActionRow(row) => row.components.clone(),
            other => vec![other.clone()],
        })
        .filter_map(|c| match c {
            Component::Button(b) => Some((b.label.unwrap_or_default(), b.style, b.custom_id, b.url)),
            _ => None,
        })
        .collect()
}

#[test]
fn custom_ids_round_trip_and_reject_garbage() {
    let id = countersign_core::RequestId::new();
    for v in [Verdict::Approve, Verdict::Deny] {
        let s = custom_id(v, id);
        assert!(s.len() <= 100);
        assert_eq!(parse_custom_id(&s), Some((v, id)));
    }
    for bad in ["", "cs", "cs:approve", "cs:maybe:x", "xx:approve:00000000-0000-0000-0000-000000000000", "cs:deny:nope"]
    {
        assert_eq!(parse_custom_id(bad), None, "{bad}");
    }
}

#[test]
fn pending_linked_policy_gets_direct_buttons() {
    let r = request(Assurance::Linked, None);
    let b = buttons(&render(&r));
    assert_eq!(b.len(), 3);
    assert_eq!((b[0].0.as_str(), b[0].1), ("Approve", ButtonStyle::Success));
    assert_eq!(b[0].2.as_deref(), Some(custom_id(Verdict::Approve, r.id).as_str()));
    assert_eq!((b[1].0.as_str(), b[1].1), ("Deny", ButtonStyle::Danger));
    assert_eq!(b[2].1, ButtonStyle::Link);
}

#[test]
fn stricter_policy_sends_approvers_to_the_web_but_still_allows_deny() {
    let r = request(Assurance::FreshAuth, None);
    let b = buttons(&render(&r));
    assert_eq!(b.len(), 2);
    assert_eq!((b[0].0.as_str(), b[0].1), ("Approve in web UI", ButtonStyle::Link));
    assert_eq!(b[0].3.as_deref(), Some("https://cs.example/requests/x"));
    assert_eq!(b[0].2, None);
    assert_eq!(b[1].0, "Deny");
}

#[test]
fn finished_requests_have_no_buttons() {
    let mut r = request(Assurance::Linked, None);
    r.state = RequestState::Denied;
    assert_eq!(render(&r).components, []);
}

#[test]
fn untrusted_text_cannot_escape_code_formatting() {
    let r = request(Assurance::Linked, Some("```\n@everyone [click](https://evil)"));
    let v = render(&r);
    let e = &v.embeds[0];
    let desc = e.description.as_deref().unwrap();
    assert_eq!(desc.matches("```").count(), 2, "{desc}");
    let requester = &e.fields.iter().find(|f| f.name == "Requester").unwrap().value;
    assert_eq!(requester, "`alice` (`Alice ˋ@everyoneˋ`)");
    assert_eq!(render::code("a\nb\u{0}"), "`a b`");
    assert_eq!(render::code("  "), "—");
    assert!(render::code(&"x".repeat(500)).ends_with("…`"));
    assert_eq!(e.title.as_deref(), Some("Access request — pending"));
}

#[test]
fn durations_read_naturally() {
    assert_eq!(render::duration(Duration::from_secs(30)), "30s");
    assert_eq!(render::duration(Duration::from_secs(5400)), "1h 30m");
    assert_eq!(render::duration(Duration::from_secs(2 * 86_400 + 60)), "2d 1m");
}

#[test]
fn message_refs_parse() {
    assert_eq!(parse_message_ref("1:2"), Some((Id::new(1), Id::new(2))));
    assert_eq!(parse_message_ref("1"), None);
    assert_eq!(parse_message_ref("0:2"), None);
}

#[test]
fn config_reads_snowflakes_as_strings() {
    let c: DiscordConfig = toml::from_str(
        r#"
        channel_id = "123456789012345678"
        guild_id = "234567890123456789"
        mention_roles = ["345678901234567890"]
        "#,
    )
    .unwrap();
    assert_eq!(c.channel_id.get(), 123_456_789_012_345_678);
    assert_eq!(c.guild_id.map(Id::get), Some(234_567_890_123_456_789));
    assert!(toml::from_str::<DiscordConfig>("channel_id = \"1\"\nbot_token = \"x\"").is_err());
}

// ---- interactions -------------------------------------------------------

#[derive(Default)]
struct FakeSink {
    links: Mutex<BTreeMap<String, ApproverId>>,
    submitted: Mutex<Vec<ActionIntent>>,
}

#[async_trait]
impl ActionSink for FakeSink {
    async fn resolve_account(&self, _: &ChannelName, external_id: &str) -> Result<Option<ApproverId>, String> {
        Ok(self.links.lock().unwrap().get(external_id).cloned())
    }

    async fn link_account(&self, _: &ChannelName, external_id: &str, code: &str) -> Result<ApproverId, String> {
        if code != "GOOD-CODE" {
            return Err("unknown or expired code".into());
        }
        let a = ApproverId::new("bob");
        self.links.lock().unwrap().insert(external_id.to_owned(), a.clone());
        Ok(a)
    }

    async fn submit(&self, intent: ActionIntent) -> Result<Request, String> {
        self.submitted.lock().unwrap().push(intent);
        let mut r = request(Assurance::Linked, None);
        r.state = RequestState::Approved;
        Ok(r)
    }
}

fn scope() -> Scope {
    Scope { name: ChannelName::new("discord"), channel_id: Id::new(CHANNEL), guild_id: Some(Id::new(GUILD)) }
}

fn user() -> serde_json::Value {
    json!({ "id": USER.to_string(), "username": "bob", "discriminator": "0", "avatar": null })
}

fn button_press(custom_id: &str, channel: u64, guild: Option<u64>) -> Interaction {
    let mut v = json!({
        "id": "1", "application_id": "2", "type": 3, "token": "t", "version": 1,
        "attachment_size_limit": 0, "authorizing_integration_owners": {}, "entitlements": [],
        "channel": { "id": channel.to_string(), "type": 0 },
        "data": { "custom_id": custom_id, "component_type": 2 },
        "message": {
            "id": "9", "channel_id": channel.to_string(), "type": 0, "content": "", "author": user(),
            "timestamp": "2026-01-01T00:00:00+00:00", "edited_timestamp": null, "tts": false,
            "mention_everyone": false, "mentions": [], "mention_roles": [], "attachments": [],
            "embeds": [], "pinned": false, "flags": 0, "components": []
        },
    });
    match guild {
        Some(g) => {
            v["guild_id"] = json!(g.to_string());
            v["member"] = json!({ "user": user(), "roles": [], "joined_at": null, "deaf": false, "mute": false,
                                   "flags": 0, "permissions": "0" });
        }
        None => v["user"] = user(),
    }
    serde_json::from_value(v).expect("interaction JSON")
}

fn link_command(code: &str) -> Interaction {
    serde_json::from_value(json!({
        "id": "1", "application_id": "2", "type": 2, "token": "t", "version": 1,
        "attachment_size_limit": 0, "authorizing_integration_owners": {}, "entitlements": [],
        "channel": { "id": "77", "type": 1 },
        "user": user(),
        "data": { "id": "5", "name": interact::LINK_COMMAND, "type": 1,
                  "options": [{ "name": "code", "type": 3, "value": code }] },
    }))
    .expect("interaction JSON")
}

#[tokio::test]
async fn unlinked_users_are_told_how_to_link_and_nothing_is_submitted() {
    let sink = FakeSink::default();
    let rid = countersign_core::RequestId::new();
    let i = button_press(&custom_id(Verdict::Approve, rid), CHANNEL, Some(GUILD));
    let action = interact::action(&i).unwrap();
    assert_eq!(action, Action::Decide { verdict: Verdict::Approve, request_id: rid });
    let reply = interact::perform(&scope(), &sink, &i, action).await;
    assert!(reply.contains("not linked"), "{reply}");
    assert!(sink.submitted.lock().unwrap().is_empty());
}

#[tokio::test]
async fn linking_then_pressing_submits_a_linked_decision() {
    let sink = FakeSink::default();
    let i = link_command(" GOOD-CODE ");
    let action = interact::action(&i).unwrap();
    assert_eq!(action, Action::Link { code: "GOOD-CODE".into() });
    let reply = interact::perform(&scope(), &sink, &i, action).await;
    assert!(reply.contains("`bob`"), "{reply}");

    let rid = countersign_core::RequestId::new();
    let i = button_press(&custom_id(Verdict::Deny, rid), CHANNEL, Some(GUILD));
    let reply = interact::perform(&scope(), &sink, &i, interact::action(&i).unwrap()).await;
    assert!(reply.starts_with("Recorded your denial as `bob`"), "{reply}");
    let submitted = sink.submitted.lock().unwrap();
    assert_eq!(
        submitted.as_slice(),
        [ActionIntent {
            request_id: rid,
            verdict: Verdict::Deny,
            approver: ApproverId::new("bob"),
            assurance: Assurance::Linked,
            via: ChannelName::new("discord"),
            comment: None,
        }]
    );
}

#[tokio::test]
async fn bad_codes_are_refused() {
    let sink = FakeSink::default();
    let i = link_command("WRONG");
    let reply = interact::perform(&scope(), &sink, &i, interact::action(&i).unwrap()).await;
    assert_eq!(reply, "Could not link: unknown or expired code");
    assert!(sink.links.lock().unwrap().is_empty());
}

#[tokio::test]
async fn presses_from_elsewhere_are_ignored() {
    let sink = FakeSink::default();
    sink.links.lock().unwrap().insert(USER.to_string(), ApproverId::new("bob"));
    let id = custom_id(Verdict::Approve, countersign_core::RequestId::new());
    for (channel, guild) in [(4242, Some(GUILD)), (CHANNEL, Some(9999)), (CHANNEL, None)] {
        let i = button_press(&id, channel, guild);
        let reply = interact::perform(&scope(), &sink, &i, interact::action(&i).unwrap()).await;
        assert!(reply.contains("does not accept"), "{reply}");
    }
    assert!(sink.submitted.lock().unwrap().is_empty());
}

#[test]
fn foreign_components_and_commands_are_not_ours() {
    assert_eq!(interact::action(&button_press("other:thing", CHANNEL, Some(GUILD))), None);
}

#[test]
fn commands_are_shown_above_the_reason_and_cannot_escape_the_code_block() {
    let mut r = request(Assurance::Linked, Some("upgrade"));
    r.facts.attributes.insert("command".into(), "apt install ```@everyone".into());
    r.facts.attributes.insert("runas".into(), "root".into());
    r.requirements.grant = countersign_core::GrantMode::Window;
    let e = &render(&r).embeds[0];
    let d = e.description.as_deref().unwrap();
    assert!(d.starts_with("**Command**\n```\napt install ˋˋˋ@everyone\n```"), "{d}");
    assert!(d.contains("**Reason**"), "{d}");
    let field = |n: &str| e.fields.iter().find(|f| f.name == n).map(|f| f.value.clone());
    assert_eq!(field("Run as").as_deref(), Some("`root`"));
    assert!(field("Duration").unwrap().ends_with("(window)"));
}
