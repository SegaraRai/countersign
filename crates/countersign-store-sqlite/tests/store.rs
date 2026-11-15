use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use countersign_core::{
    Approver, ApproverSelector, Assurance, ChannelName, MessageRef, PendingSubject, Request, RequestFilter, Requester,
    Requirements, Store, StoreError, SubjectFacts, SubjectRef, Verdict,
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
            requester: Requester {
                id: "agent-1".into(),
                display_name: None,
                groups: BTreeSet::new(),
                identities: BTreeSet::new(),
            },
            target: None,
            requested_ttl: None,
            reason: Some("deploy".into()),
            attributes: BTreeMap::new(),
        },
        observed_at: now,
    };
    let reqs = Requirements {
        policy: "p".into(),
        approvers: vec![ApproverSelector::Group("ops".into())],
        quorum: 1,
        min_assurance: Assurance::Web,
        ttl: Duration::from_secs(600),
        pending_timeout: Duration::from_secs(300),
        allow_self_approval: false,
        grant: countersign_core::GrantMode::Once,
    };
    Request::open(pending, reqs, now)
}

fn bob() -> Approver {
    Approver { id: "bob".into(), display_name: None, groups: ["ops".to_owned()].into(), identities: BTreeSet::new() }
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

    let ev_a = a.decide(&bob(), Verdict::Approve, Assurance::Web, "web".into(), None, t(1)).unwrap();
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
    let ev = r.decide(&bob(), Verdict::Approve, Assurance::Web, "web".into(), None, t(1)).unwrap();
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
        links.iter().map(|l| (l.channel.as_str(), l.external_id.as_str(), l.approver.as_str())).collect();
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
