use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde_json::json;

use super::*;
use crate::actor::Selector;
use crate::assurance::Assurance;
use crate::policy::{Exclusion, Requirements};
use crate::question::{Asker, Confidentiality, QuestionPolicy};
use crate::request::{Decision, Use};
use crate::subject::{PendingSubject, Requester, SubjectFacts, SubjectRef};

fn t(secs: i64) -> Timestamp {
    Timestamp::from_second(1_800_000_000 + secs).unwrap()
}

fn line(s: &[&str]) -> Vec<String> {
    s.iter().map(|a| (*a).to_owned()).collect()
}

fn sudo(argv: &[&str], grant: GrantMode, scope: &[(&str, &str)]) -> Request {
    let mut facts = SubjectFacts::new(Requester {
        id: "agent".into(),
        display_name: Some("agent@web-1".into()),
        identity: "unix:web-1#agent".into(),
        actor: Some("agent-bot".into()),
        ..Requester::default()
    });
    facts.source = Some(Source::Client("web-1".into()));
    facts.target = Some("web-1".into());
    facts.reason = Some("deploy\u{202e} fix".into());
    facts.action =
        Some(Action::Command { line: line(argv), runas: "root".into(), cwd: Some("/srv/app".into()), notes: vec![] });
    facts.attributes = BTreeMap::from([("command".to_owned(), "id".to_owned())]);
    facts.binding = Some("ab12:nonce".into());
    let pending = PendingSubject {
        subject: SubjectRef { backend: "host".into(), kind: "sudo".into(), id: "u1".into() },
        facts,
        observed_at: t(0),
    };
    let reqs = Requirements {
        policy: "agent-sudo".into(),
        approvers: vec![Selector::Group("ops".into())],
        exclude: BTreeSet::from([Exclusion::Requester]),
        quorum: 1,
        min_assurance: Assurance::Linked,
        ttl: Duration::from_secs(if grant == GrantMode::Window { 900 } else { 60 }),
        pending_timeout: Duration::from_secs(300),
        grant,
        require_initiator: false,
        scope: scope.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect(),
    };
    Request::open(pending, reqs, false, t(0)).0
}

#[test]
fn a_sudo_command_shows_the_raw_line_and_leads_with_the_grant() {
    let r = sudo(&["sudo", "psql", "-c", "DROP TABLE x"], GrantMode::Once, &[]);
    let p = Presentation::approval(&r, Audience::Full);
    assert_eq!(p.headline, "agent-bot wants root on web-1");
    assert_eq!(p.grant, "Runs this command once, as root, within 1 minute");
    assert_eq!(p.action, Some(Shown::Command { line: "sudo psql -c 'DROP TABLE x'".into() }));
    assert_eq!(p.fact("Host"), Some("web-1"));
    assert_eq!(p.fact("Run as"), Some("root"));
    assert_eq!(p.fact("Directory"), Some("/srv/app"));
    assert_eq!(p.claims, vec![Detail::new("Reason", "deploy\\u{202e} fix")]);
    assert_eq!(p.status.label, "Waiting for approval");
    assert_eq!(p.status.time, Some(When { label: "Decide by", at: t(300) }));
    assert_eq!(p.status.needs.as_deref(), Some("1 approval at linked"));
    assert_eq!(p.status.tone, Tone::Waiting);
    // The audit section carries what was dumped before.
    let audit: BTreeMap<_, _> = p.audit.iter().map(|d| (d.label.as_str(), d.value.as_str())).collect();
    assert_eq!(audit["Identity"], "unix:web-1#agent");
    assert_eq!(audit["Attribute command"], "id");
    assert_eq!(audit["Rules"], "once for 1 minute · 1 approval at linked · excluding requester");
    assert_eq!(audit["Bound to"], "ab12:nonce");
    // Chat gets no audit.
    assert_eq!(Presentation::approval(&r, Audience::Chat).audit, Vec::new());
}

#[test]
fn hidden_characters_in_a_command_are_escaped_not_dropped() {
    let r = sudo(&["sudo", "echo", "\u{202e}/ fr- mr"], GrantMode::Once, &[]);
    let p = Presentation::approval(&r, Audience::Full);
    assert_eq!(p.action, Some(Shown::Command { line: r"sudo echo $'\u202E/ fr- mr'".into() }));
}

#[test]
fn a_window_says_what_it_covers() {
    let r = sudo(&["sudo", "apt", "update"], GrantMode::Window, &[("command", "apt*")]);
    let p = Presentation::approval(&r, Audience::Full);
    assert_eq!(p.grant, "Allows agent-bot to run commands matching `apt*`, as any user, on web-1, for 15 minutes");
    let r = sudo(&["sudo", "id"], GrantMode::Window, &[("runas", "root")]);
    assert_eq!(
        Presentation::approval(&r, Audience::Full).grant,
        "Allows agent-bot to run any command, as `root`, on web-1, for 15 minutes"
    );
}

#[test]
fn states_are_worded_the_same_everywhere() {
    let mut r = sudo(&["sudo", "id"], GrantMode::Once, &[]);
    let decision = |verdict| Decision {
        approver: "alice".into(),
        verdict,
        assurance: Assurance::Linked,
        via: "discord".into(),
        at: t(10),
        comment: Some("ok".into()),
    };
    r.decisions.push(decision(Verdict::Approve));
    r.state = RequestState::Active { until: t(70) };
    let s = Presentation::approval(&r, Audience::Full).status;
    assert_eq!((s.label.as_str(), s.detail.as_deref()), ("Approved", Some("Ready to run once")));
    assert_eq!(s.time, Some(When { label: "Use by", at: t(70) }));
    assert_eq!(s.decisions[0].verdict(), "Approved");

    r.state = RequestState::Ended;
    r.collected_at = Some(t(20));
    let s = Presentation::approval(&r, Audience::Full).status;
    assert_eq!((s.label.as_str(), s.time), ("Approved, used", Some(When { label: "Ran at", at: t(20) })));
    assert_eq!(s.tone, Tone::Done);
    r.collected_at = None;
    assert_eq!(Presentation::approval(&r, Audience::Full).status.label, "Approved, not used");

    r.decisions = vec![decision(Verdict::Deny)];
    r.state = RequestState::Denied;
    let s = Presentation::approval(&r, Audience::Full).status;
    assert_eq!((s.label.as_str(), s.detail.as_deref()), ("Denied", Some("by alice via discord")));
    assert_eq!(s.tone, Tone::Bad);

    for (state, label) in [
        (RequestState::Expired, "No decision"),
        (RequestState::Withdrawn, "Withdrawn"),
        (RequestState::Revoked, "Revoked"),
        (RequestState::Failed { error: "boom".into() }, "Failed"),
    ] {
        r.state = state;
        assert_eq!(Presentation::approval(&r, Audience::Full).status.label, label);
    }

    let mut w = sudo(&["sudo", "apt", "update"], GrantMode::Window, &[("command", "apt*")]);
    w.state = RequestState::Active { until: t(900) };
    w.uses.push(Use {
        subject: SubjectRef { backend: "host".into(), kind: "sudo".into(), id: "u2".into() },
        at: t(30),
        attributes: BTreeMap::new(),
        action: Some(Action::Command {
            line: line(&["sudo", "apt", "install", "jq"]),
            runas: "root".into(),
            cwd: None,
            notes: vec![],
        }),
    });
    let s = Presentation::approval(&w, Audience::Full).status;
    assert_eq!(s.detail.as_deref(), Some("Window open · 1 more command used it"));
    assert_eq!(s.uses[0].what, "sudo apt install jq");
}

#[test]
fn sensitive_approvals_are_withheld_from_chat() {
    let mut r = sudo(&["sudo", "cat", "/etc/shadow"], GrantMode::Once, &[]);
    r.sensitive = true;
    let p = Presentation::approval(&r, Audience::Chat);
    assert!(p.withheld);
    assert_eq!(p.headline, "Sensitive approval request from web-1 (agent-sudo)");
    assert!(p.action.is_none() && p.claims.is_empty() && p.audit.is_empty() && p.notes.is_empty());
    assert_eq!(p.facts, vec![Detail::new("From", "web-1"), Detail::new("Policy", "agent-sudo")]);
    let json = serde_json::to_string(&p).unwrap();
    assert!(!json.contains("shadow") && !json.contains("deploy"), "{json}");
    // Approvers in the web UI see everything.
    assert!(!Presentation::approval(&r, Audience::Full).withheld);
}

#[test]
fn sessions_and_other_backends() {
    let mut r = sudo(&["x"], GrantMode::Once, &[]);
    r.facts.source = Some(Source::Backend("oct".into()));
    r.subject.backend = "oct".into();
    r.facts.target = None;
    r.facts.action = Some(Action::Session {
        kind: Some("client".into()),
        device: Some("laptop-7".into()),
        client: Some("octelium-cli/0.21".into()),
        credential: None,
        browser: false,
    });
    let p = Presentation::approval(&r, Audience::Full);
    assert_eq!(p.headline, "agent-bot wants a session");
    assert_eq!(p.grant, "Lets this session through for up to 1 minute");
    let Some(Shown::Lines { title, lines }) = p.action else { panic!() };
    assert_eq!(title, "Session on oct");
    assert_eq!(lines[1], Detail::new("Device", "laptop-7"));

    r.facts.action = Some(Action::Generic { title: "a deploy of app".into(), lines: vec![Detail::new("Env", "prod")] });
    r.facts.target = Some("prod".into());
    let p = Presentation::approval(&r, Audience::Full);
    assert_eq!(p.headline, "agent-bot requests a deploy of app");
    assert_eq!(p.fact("Target"), Some("prod"));
}

fn question(conf: Confidentiality) -> Question {
    let policy: QuestionPolicy = toml::from_str(
        r#"
        name = "agents"
        responders = ["group:ops"]
        min_assurance = "linked"
        confidential = "allow"
        "#,
    )
    .unwrap();
    let asker = Asker { client: "agent-1".into(), actor: Some("alice-bot".into()) };
    let schema = json!({
        "type": "object",
        "properties": {
            "env": { "type": "string", "title": "Environment", "enum": ["staging", "production"] },
            "note": { "type": "string" }
        },
        "required": ["env"]
    });
    let ctx = BTreeMap::from([("repo".to_owned(), "app".to_owned())]);
    Question::ask(asker, "Where to deploy?".into(), schema, ctx, &policy, conf, t(0)).0
}

#[test]
fn questions_show_the_message_and_a_form_summary() {
    let q = question(Confidentiality::default());
    let p = Presentation::question(&q, Audience::Chat);
    assert_eq!(p.headline, "alice-bot (via agent-1) asks a question");
    assert_eq!(p.grant, GRANT_QUESTION);
    let Some(Shown::Question { message, fields }) = &p.action else { panic!() };
    assert_eq!(message, "Where to deploy?");
    assert_eq!(fields[0], Detail::new("Environment", "one of: staging, production"));
    assert_eq!(fields[1], Detail::new("note", "text (optional)"));
    assert_eq!(p.claims, vec![Detail::new("repo", "app")]);
    assert_eq!(p.status.label, "Waiting for an answer");
    assert_eq!(p.status.tone, Tone::Asking);
}

#[test]
fn confidential_questions_are_withheld_from_chat() {
    let q = question(Confidentiality { question: true, answer_may_be: false });
    let p = Presentation::question(&q, Audience::Chat);
    assert!(p.withheld && p.action.is_none() && p.claims.is_empty());
    assert!(!serde_json::to_string(&p).unwrap().contains("deploy"));
    assert!(Presentation::question(&q, Audience::Full).action.is_some());
}

#[test]
fn durations_and_relative_times_in_words() {
    assert_eq!(duration_words(Duration::from_secs(1)), "1 second");
    assert_eq!(duration_words(Duration::from_secs(60)), "1 minute");
    assert_eq!(duration_words(Duration::from_secs(5400)), "1 hour 30 minutes");
    assert_eq!(duration_words(Duration::from_secs(2 * 86_400)), "2 days");
    assert_eq!(relative(t(240), t(0)), "in 4 min");
    assert_eq!(relative(t(0), t(7200)), "2 h ago");
}
