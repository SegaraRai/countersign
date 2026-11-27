use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use countersign_core::{
    ActorId, AdminAction, Asker, Assurance, ChannelName, Confidentiality, Directory, Exclusion, GroupConfig,
    IdpSnapshot, MessageRef, PendingSubject, PersonConfig, Question, QuestionPolicy, Request, RequestFilter, Requester,
    Requirements, Response, Roles, Roster, Selector, Standing, Store, StoreError, SubjectFacts, SubjectRef, Suspension,
    Verdict,
};
use countersign_store_sqlite::SqliteStore;
use jiff::Timestamp;

fn t(secs: i64) -> Timestamp {
    Timestamp::from_second(1_800_000_000 + secs).unwrap()
}

fn open_request(subject_id: &str, now: Timestamp) -> (Request, Vec<countersign_core::DomainEvent>) {
    let pending = PendingSubject {
        subject: SubjectRef { backend: "oct".into(), kind: "session".into(), id: subject_id.into() },
        facts: SubjectFacts {
            reason: Some("deploy".into()),
            ..SubjectFacts::new(Requester {
                id: "agent-1".into(),
                identity: "unix:web-1#agent-1".into(),
                ..Requester::default()
            })
        },
        observed_at: now,
    };
    let reqs = Requirements {
        policy: "p".into(),
        approvers: vec![Selector::Group("ops".into())],
        exclude: BTreeSet::from([Exclusion::Requester]),
        quorum: 1,
        min_assurance: Assurance::Web,
        ttl: Duration::from_secs(600),
        pending_timeout: Duration::from_secs(300),
        grant: countersign_core::GrantMode::Once,
        require_initiator: false,
        scope: std::collections::BTreeMap::default(),
        channels: Vec::new(),
    };
    Request::open(pending, reqs, false, now)
}

fn directory() -> Directory {
    let person = |id: &str| PersonConfig { id: id.into(), display_name: None, identities: vec![] };
    Directory::new(
        vec![person("alice"), person("bob")],
        vec![],
        vec![GroupConfig { name: "ops".into(), members: vec!["bob".into()], from_idp: vec![] }],
        Roles::default(),
    )
    .unwrap()
}

fn bob() -> ActorId {
    "bob".into()
}

fn roster<'a>(dir: &'a Directory, standing: &'a Standing) -> Roster<'a> {
    Roster { directory: dir, standing, now: t(0), idp_max_age: Duration::from_secs(3600) }
}

#[tokio::test]
async fn insert_get_and_one_open_request_per_subject() {
    let store = SqliteStore::in_memory().await.unwrap();
    let (mut r, ev) = open_request("s1", t(0));
    store.insert_request(&r, &ev).await.unwrap();

    assert_eq!(store.get_request(r.id).await.unwrap().as_ref(), Some(&r));
    assert_eq!(store.find_open_by_subject(&r.subject).await.unwrap().map(|x| x.id), Some(r.id));

    let (dup, dup_ev) = open_request("s1", t(1));
    assert!(matches!(store.insert_request(&dup, &dup_ev).await, Err(StoreError::Duplicate)));

    // Once the first request is closed, the subject may be requested again.
    let v = r.version;
    let ev = r.withdraw(t(2)).unwrap();
    store.update_request(&r, v, &ev).await.unwrap();
    assert!(store.find_open_by_subject(&r.subject).await.unwrap().is_none());
    assert_eq!(store.find_latest_by_subject(&r.subject).await.unwrap().map(|x| x.id), Some(r.id));
    store.insert_request(&dup, &dup_ev).await.unwrap();
    assert_eq!(
        store.find_latest_by_subject(&r.subject).await.unwrap().map(|x| x.id),
        Some(dup.id),
        "the newer request wins"
    );
    let other = SubjectRef { id: "nope".into(), ..r.subject.clone() };
    assert!(store.find_latest_by_subject(&other).await.unwrap().is_none());
}

#[tokio::test]
async fn optimistic_concurrency() {
    let store = SqliteStore::in_memory().await.unwrap();
    let (r, ev) = open_request("s1", t(0));
    store.insert_request(&r, &ev).await.unwrap();

    // Two workers load the same version.
    let mut a = store.get_request(r.id).await.unwrap().unwrap();
    let mut b = a.clone();

    let (dir, standing) = (directory(), Standing::default());
    let ev_a =
        a.decide(&roster(&dir, &standing), &bob(), Verdict::Approve, Assurance::Web, "web".into(), None, t(1)).unwrap();
    store.update_request(&a, r.version, &ev_a).await.unwrap();

    let ev_b = b.withdraw(t(1)).unwrap();
    assert!(matches!(store.update_request(&b, r.version, &ev_b).await, Err(StoreError::Conflict(id)) if id == r.id));

    let (ghost, _) = open_request("s2", t(0));
    assert!(matches!(store.update_request(&ghost, 0, &[]).await, Err(StoreError::NotFound(_))));

    let stored = store.get_request(r.id).await.unwrap().unwrap();
    assert_eq!(stored, a, "the losing write left no trace");
}

#[tokio::test]
async fn outbox_lease_retry_and_completion() {
    let store = SqliteStore::in_memory().await.unwrap();
    let (mut r, ev) = open_request("s1", t(0));
    store.insert_request(&r, &ev).await.unwrap();
    let v = r.version;
    let (dir, standing) = (directory(), Standing::default());
    let ev =
        r.decide(&roster(&dir, &standing), &bob(), Verdict::Approve, Assurance::Web, "web".into(), None, t(1)).unwrap();
    store.update_request(&r, v, &ev).await.unwrap();

    let lease = Duration::from_secs(30);
    let claimed = store.claim_outbox(10, lease, t(5)).await.unwrap();
    let kinds: Vec<_> = claimed.iter().map(|i| i.event.kind()).collect();
    assert_eq!(kinds, ["requested", "decision-recorded", "approved"], "delivered in commit order");
    assert!(claimed.iter().all(|i| i.attempts == 1));

    // Leased items are not handed out again until the lease ends.
    assert_eq!(store.claim_outbox(10, lease, t(6)).await.unwrap(), []);

    store.complete_outbox(claimed[0].id).await.unwrap();
    store.fail_outbox(claimed[1].id, t(100), "discord: 502").await.unwrap();

    // At t=35 only the lease-expired, never-reported item comes back.
    let again = store.claim_outbox(10, lease, t(35)).await.unwrap();
    assert_eq!(again.iter().map(|i| i.id).collect::<Vec<_>>(), [claimed[2].id]);
    assert_eq!(again[0].attempts, 2);
    store.complete_outbox(again[0].id).await.unwrap();

    // The failed one returns at its retry time.
    assert_eq!(store.claim_outbox(10, lease, t(99)).await.unwrap(), []);
    let retry = store.claim_outbox(10, lease, t(100)).await.unwrap();
    assert_eq!(retry.len(), 1);
    assert_eq!(retry[0].id, claimed[1].id);
    store.complete_outbox(retry[0].id).await.unwrap();

    assert_eq!(store.claim_outbox(10, lease, t(10_000)).await.unwrap(), []);
}

#[tokio::test]
async fn per_channel_delivery_marks() {
    let store = SqliteStore::in_memory().await.unwrap();
    let (r, ev) = open_request("s1", t(0));
    store.insert_request(&r, &ev).await.unwrap();
    let item = store.claim_outbox(1, Duration::from_secs(30), t(0)).await.unwrap().remove(0);

    assert_eq!(store.delivered_channels(item.id).await.unwrap(), Vec::<ChannelName>::new());
    store.mark_delivered(item.id, &"push".into()).await.unwrap();
    store.mark_delivered(item.id, &"push".into()).await.unwrap(); // idempotent
    store.mark_delivered(item.id, &"chat".into()).await.unwrap();
    assert_eq!(store.delivered_channels(item.id).await.unwrap(), [ChannelName::from("chat"), "push".into()]);
}

#[tokio::test]
async fn claim_respects_limit() {
    let store = SqliteStore::in_memory().await.unwrap();
    for i in 0..5 {
        let (r, ev) = open_request(&format!("s{i}"), t(i));
        store.insert_request(&r, &ev).await.unwrap();
    }
    let first = store.claim_outbox(2, Duration::from_secs(30), t(10)).await.unwrap();
    let rest = store.claim_outbox(10, Duration::from_secs(30), t(10)).await.unwrap();
    assert_eq!((first.len(), rest.len()), (2, 3));
}

#[tokio::test]
async fn list_filters() {
    let store = SqliteStore::in_memory().await.unwrap();
    let mut ids = Vec::new();
    for i in 0..3 {
        let (r, ev) = open_request(&format!("s{i}"), t(i));
        store.insert_request(&r, &ev).await.unwrap();
        ids.push(r.id);
    }
    let mut closed = store.get_request(ids[0]).await.unwrap().unwrap();
    let v = closed.version;
    let ev = closed.withdraw(t(9)).unwrap();
    store.update_request(&closed, v, &ev).await.unwrap();

    let all = store.list_requests(&RequestFilter::default()).await.unwrap();
    assert_eq!(all.iter().map(|r| r.id).collect::<Vec<_>>(), [ids[2], ids[1], ids[0]], "newest first");

    let open = store.list_requests(&RequestFilter { open_only: true, limit: None }).await.unwrap();
    assert_eq!(open.len(), 2);

    let one = store.list_requests(&RequestFilter { open_only: false, limit: Some(1) }).await.unwrap();
    assert_eq!(one.len(), 1);
}

#[tokio::test]
async fn message_refs_and_account_links() {
    let store = SqliteStore::in_memory().await.unwrap();
    let (r, ev) = open_request("s1", t(0));
    store.insert_request(&r, &ev).await.unwrap();

    let discord: ChannelName = "discord".into();
    store.save_message_ref(r.id, &MessageRef { channel: discord.clone(), id: "m1".into() }).await.unwrap();
    store.save_message_ref(r.id, &MessageRef { channel: discord.clone(), id: "m2".into() }).await.unwrap();
    store.save_message_ref(r.id, &MessageRef { channel: "ntfy".into(), id: "n1".into() }).await.unwrap();
    let refs = store.message_refs(r.id).await.unwrap();
    assert_eq!(refs.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(), ["m2", "n1"]);

    assert_eq!(store.resolve_account(&discord, "123").await.unwrap(), None);
    store.link_account(&discord, "123", &"bob".into()).await.unwrap();
    assert_eq!(store.resolve_account(&discord, "123").await.unwrap(), Some("bob".into()));
    assert_eq!(store.resolve_account(&"slack".into(), "123").await.unwrap(), None, "links are per channel");
    store.link_account(&discord, "123", &"carol".into()).await.unwrap();
    assert_eq!(store.resolve_account(&discord, "123").await.unwrap(), Some("carol".into()));

    store.link_account(&"slack".into(), "U1", &"bob".into()).await.unwrap();
    let links = store.list_account_links().await.unwrap();
    let summary: Vec<_> =
        links.iter().map(|l| (l.channel.as_str(), l.external_id.as_str(), l.person.as_str())).collect();
    assert_eq!(summary, [("discord", "123", "carol"), ("slack", "U1", "bob")]);
    assert!(store.unlink_account(&discord, "123").await.unwrap());
    assert!(!store.unlink_account(&discord, "123").await.unwrap(), "already gone");
    assert_eq!(store.resolve_account(&discord, "123").await.unwrap(), None);
    assert_eq!(store.list_account_links().await.unwrap().len(), 1);
}

#[tokio::test]
async fn file_database_persists_across_reopen() {
    let dir = std::env::temp_dir().join(format!("countersign-test-{}", countersign_core::RequestId::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let url = format!("sqlite://{}", dir.join("state.db").display());

    let (r, ev) = open_request("s1", t(0));
    {
        let store = SqliteStore::open(&url).await.unwrap();
        store.insert_request(&r, &ev).await.unwrap();
        store.pool().close().await;
    }
    let store = SqliteStore::open(&url).await.unwrap();
    assert_eq!(store.get_request(r.id).await.unwrap(), Some(r));
    store.pool().close().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

fn question(conf: Confidentiality) -> Question {
    let policy: QuestionPolicy = toml::from_str(
        "name = 'q'\nresponders = ['group:ops']\nmin_assurance = 'linked'\nconfidential = 'allow'\nanswer_retention = '1h'\n",
    )
    .unwrap();
    let schema = serde_json::json!({ "type": "object", "properties": { "pin": { "type": "string" } } });
    Question::ask(
        Asker { client: "agent-1".into(), actor: Some("alice".into()) },
        "What is the PIN?".into(),
        schema,
        BTreeMap::new(),
        &policy,
        conf,
        t(0),
    )
    .0
}

#[tokio::test]
async fn questions_are_kept_apart_from_approvals() {
    let store = SqliteStore::in_memory().await.unwrap();
    let (r, ev) = open_request("s1", t(0));
    store.insert_request(&r, &ev).await.unwrap();
    let q = question(Confidentiality::default());
    store.insert_question(&q, &[]).await.unwrap();

    assert_eq!(store.get_question(q.id).await.unwrap().as_ref(), Some(&q));
    assert_eq!(store.get_request(q.id).await.unwrap(), None, "a question is not an approval");
    assert_eq!(store.get_question(r.id).await.unwrap(), None);
    assert_eq!(store.list_requests(&RequestFilter::default()).await.unwrap().len(), 1);
    assert_eq!(store.list_questions(&RequestFilter::default()).await.unwrap(), std::slice::from_ref(&q));
    assert!(matches!(store.update_request(&r, 7, &[]).await, Err(StoreError::Conflict(_))));
    assert!(matches!(store.update_question(&q, 7, &[]).await, Err(StoreError::Conflict(_))));
}

#[tokio::test]
async fn confidential_content_is_tracked_until_removed() {
    let store = SqliteStore::in_memory().await.unwrap();
    let (dir, standing) = (directory(), Standing::default());
    let mut q = question(Confidentiality { question: false, answer_may_be: true });
    store.insert_question(&q, &[]).await.unwrap();
    assert_eq!(store.questions_holding_content().await.unwrap(), [], "open questions are not swept");

    let v = q.version;
    let content = serde_json::json!({ "pin": "4711" }).as_object().unwrap().clone();
    let ev = q
        .respond(
            &roster(&dir, &standing),
            &bob(),
            Response::Accept { content, confidential: true },
            Assurance::FreshAuth,
            "web".into(),
            t(5),
        )
        .unwrap();
    store.update_question(&q, v, &ev).await.unwrap();
    let held = store.questions_holding_content().await.unwrap();
    assert_eq!(held.iter().map(|x| x.id).collect::<Vec<_>>(), [q.id]);

    let v = q.version;
    assert!(q.mark_read(t(6)));
    store.update_question(&q, v, &[]).await.unwrap();
    assert_eq!(store.questions_holding_content().await.unwrap(), []);
    let body: String = sqlx_body(&store, q.id).await;
    assert!(!body.contains("4711"), "the answer is gone from the row");
}

#[tokio::test]
async fn confidential_content_is_purged_from_wal_on_removal() {
    let dir = std::env::temp_dir().join(format!("countersign-wal-test-{}", countersign_core::RequestId::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("state.db");
    let store = SqliteStore::open(&format!("sqlite://{}", db.display())).await.unwrap();
    let (dir_cfg, standing) = (directory(), Standing::default());
    let mut q = question(Confidentiality { question: false, answer_may_be: true });
    store.insert_question(&q, &[]).await.unwrap();

    let secret = "SUPER-SECRET-CONFIDENTIAL-ANSWER-9999";
    let v = q.version;
    let content = serde_json::json!({ "pin": secret }).as_object().unwrap().clone();
    let ev = q
        .respond(
            &roster(&dir_cfg, &standing),
            &bob(),
            Response::Accept { content, confidential: true },
            Assurance::FreshAuth,
            "web".into(),
            t(5),
        )
        .unwrap();
    store.update_question(&q, v, &ev).await.unwrap();

    let v = q.version;
    assert!(q.mark_read(t(6)));
    store.update_question(&q, v, &[]).await.unwrap();

    let needle = secret.as_bytes();
    let db_bytes = std::fs::read(&db).unwrap();
    assert!(!db_bytes.windows(needle.len()).any(|w| w == needle), "secret remained in main db file");
    let wal = dir.join("state.db-wal");
    if wal.exists() {
        let wal_bytes = std::fs::read(&wal).unwrap();
        assert!(!wal_bytes.windows(needle.len()).any(|w| w == needle), "secret remained in WAL file");
    }

    store.pool().close().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

async fn sqlx_body(store: &SqliteStore, id: countersign_core::RequestId) -> String {
    use sqlx::Row;
    sqlx::query("SELECT body FROM requests WHERE id = ?")
        .bind(id.to_string())
        .fetch_one(store.pool())
        .await
        .unwrap()
        .get("body")
}

#[tokio::test]
async fn suspensions_snapshots_and_admin_actions() {
    let store = SqliteStore::in_memory().await.unwrap();
    let s = Suspension { since: t(1), by: "root".into(), reason: Some("lost laptop".into()) };
    store.suspend(&bob(), &s).await.unwrap();
    store.suspend(&bob(), &s).await.unwrap(); // replaces
    let snap = IdpSnapshot { provider: "oidc:https://id.example".into(), groups: ["ops".to_owned()].into(), at: t(2) };
    store.save_idp_snapshot(&"alice".into(), &snap).await.unwrap();

    let standing = store.standing().await.unwrap();
    assert_eq!(standing.suspended.get(&bob()), Some(&s));
    assert_eq!(standing.idp.get(&ActorId::from("alice")), Some(&snap));

    assert!(store.reinstate(&bob()).await.unwrap());
    assert!(!store.reinstate(&bob()).await.unwrap());
    assert!(store.suspensions().await.unwrap().is_empty());

    for (i, action) in ["suspend", "reinstate"].into_iter().enumerate() {
        let a = AdminAction {
            at: t(i64::try_from(i).unwrap()),
            by: "root".into(),
            action: action.into(),
            target: "bob".into(),
            detail: None,
        };
        store.record_admin_action(&a).await.unwrap();
    }
    let actions = store.admin_actions(10).await.unwrap();
    assert_eq!(actions.iter().map(|a| a.action.as_str()).collect::<Vec<_>>(), ["reinstate", "suspend"]);
}

#[tokio::test]
async fn push_subscriptions_crud() {
    let store = SqliteStore::in_memory().await.unwrap();
    let alice = ActorId::new("alice");
    let sub1 = countersign_core::PushSubscription {
        id: "sub-1".into(),
        person: alice.clone(),
        endpoint: "https://push.example/1".into(),
        p256dh: "pub1".into(),
        auth: "auth1".into(),
        label: Some("Chrome".into()),
        created_at: t(10),
    };
    let sub2 = countersign_core::PushSubscription {
        id: "sub-2".into(),
        person: bob(),
        endpoint: "https://push.example/2".into(),
        p256dh: "pub2".into(),
        auth: "auth2".into(),
        label: None,
        created_at: t(20),
    };
    store.save_push_subscription(&sub1).await.unwrap();
    store.save_push_subscription(&sub2).await.unwrap();

    assert_eq!(store.list_push_subscriptions(None).await.unwrap().len(), 2);
    assert_eq!(store.list_push_subscriptions(Some(&alice)).await.unwrap(), vec![sub1.clone()]);

    // Cannot delete someone else's subscription by person + id.
    assert!(!store.delete_push_subscription_for_person(&bob(), "sub-1").await.unwrap());
    assert!(store.delete_push_subscription_for_person(&alice, "sub-1").await.unwrap());
    assert_eq!(
        store.list_push_subscriptions(Some(&alice)).await.unwrap(),
        [] as [countersign_core::PushSubscription; 0]
    );

    // Delete by endpoint (e.g. 410 Gone).
    assert!(store.delete_push_subscription("https://push.example/2").await.unwrap());
    assert_eq!(store.list_push_subscriptions(None).await.unwrap(), [] as [countersign_core::PushSubscription; 0]);
}

#[tokio::test]
async fn purge_before_removes_only_old_closed_delivered_records() {
    let store = SqliteStore::in_memory().await.unwrap();

    // 1. Old closed request with all outbox events delivered -> should be purged.
    let (mut old_closed, ev1) = open_request("s-old", t(10));
    store.insert_request(&old_closed, &ev1).await.unwrap();
    let v = old_closed.version;
    let expired_old = old_closed.withdraw(t(1000)).unwrap();
    store.update_request(&old_closed, v, &expired_old).await.unwrap();
    for item in store.claim_outbox(10, Duration::from_mins(1), t(1001)).await.unwrap() {
        store.complete_outbox(item.id).await.unwrap();
    }

    // 2. Old open request -> must NOT be purged.
    let (old_open, ev2) = open_request("s-open", t(10));
    store.insert_request(&old_open, &ev2).await.unwrap();
    for item in store.claim_outbox(10, Duration::from_mins(1), t(1002)).await.unwrap() {
        store.complete_outbox(item.id).await.unwrap();
    }

    // 3. Recent closed request -> must NOT be purged.
    let (mut recent_closed, ev3) = open_request("s-recent", t(5000));
    store.insert_request(&recent_closed, &ev3).await.unwrap();
    let v3 = recent_closed.version;
    let withdrawn_recent = recent_closed.withdraw(t(6000)).unwrap();
    store.update_request(&recent_closed, v3, &withdrawn_recent).await.unwrap();
    for item in store.claim_outbox(10, Duration::from_mins(1), t(6001)).await.unwrap() {
        store.complete_outbox(item.id).await.unwrap();
    }

    let purged = store.purge_before(t(3000)).await.unwrap();
    assert_eq!(purged, 1);
    assert!(store.get_request(old_closed.id).await.unwrap().is_none());
    assert!(store.get_request(old_open.id).await.unwrap().is_some());
    assert!(store.get_request(recent_closed.id).await.unwrap().is_some());
}
