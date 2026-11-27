//! Delivers outbox events to channels.
//!
//! - `requested`: every channel posts a message (once; the stored message
//!   reference makes retries idempotent).
//! - Later events: channels that can edit messages update theirs; channels
//!   that cannot are only told about outcomes worth a new message.

use std::sync::Arc;
use std::time::Duration;

use jiff::{SignedDuration, Timestamp};
use tracing::{debug, warn};

use countersign_core::{
    AdminAction, AdminNotice, Channel, ChannelError, DomainEvent, EventId, Item, Notification, OutboxItem, Store,
    StoreError,
};

const BATCH: u32 = 32;
const LEASE: Duration = Duration::from_secs(60);
const MAX_ATTEMPTS: u32 = 12;

pub struct Dispatcher {
    store: Arc<dyn Store>,
    channels: Vec<Arc<dyn Channel>>,
    public_url: String,
}

impl std::fmt::Debug for Dispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dispatcher")
            .field("channels", &self.channels.iter().map(|c| c.name().to_string()).collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// Whether a channel that cannot edit messages should post about `ev`.
fn worth_a_new_message(ev: &DomainEvent) -> bool {
    matches!(
        ev,
        DomainEvent::Requested { .. }
            | DomainEvent::Denied { .. }
            | DomainEvent::Granted { .. }
            | DomainEvent::GrantFailed { .. }
            | DomainEvent::Expired { .. }
            | DomainEvent::Revoked { .. }
            | DomainEvent::Answered { .. }
            | DomainEvent::Declined { .. }
    )
}

/// Delay before attempt `attempts + 1`: 5s, 10s, 20s, … capped at 10 minutes.
fn backoff(attempts: u32) -> SignedDuration {
    let secs = 5u64.saturating_mul(1u64 << attempts.saturating_sub(1).min(7)).min(600);
    SignedDuration::from_secs(i64::try_from(secs).unwrap_or(600))
}

impl Dispatcher {
    pub fn new(store: Arc<dyn Store>, channels: Vec<Arc<dyn Channel>>, public_url: &str) -> Self {
        Self { store, channels, public_url: public_url.trim_end_matches('/').to_owned() }
    }

    /// Deliver one batch of due events. Returns how many were handled.
    pub async fn run_once(&self, now: Timestamp) -> Result<usize, StoreError> {
        let items = self.store.claim_outbox(BATCH, LEASE, now).await?;
        let n = items.len();
        for item in items {
            let retry = self.deliver(&item).await?;
            if retry && item.attempts < MAX_ATTEMPTS {
                let at = now.checked_add(backoff(item.attempts)).unwrap_or(now);
                self.store.fail_outbox(item.id, at, "a channel failed temporarily").await?;
            } else {
                if retry {
                    warn!(event = %item.id, kind = item.event.kind(), "giving up after {MAX_ATTEMPTS} attempts");
                }
                self.store.complete_outbox(item.id).await?;
            }
        }
        Ok(n)
    }

    /// Returns whether a retry is needed.
    async fn deliver(&self, item: &OutboxItem) -> Result<bool, StoreError> {
        let request_id = item.event.request_id();
        let (request, question);
        let subject = if let Some(r) = self.store.get_request(request_id).await? {
            request = r;
            Item::Approval(&request)
        } else if let Some(q) = self.store.get_question(request_id).await? {
            question = q;
            Item::Question(&question)
        } else {
            warn!(request = %request_id, "outbox event for a missing request");
            return Ok(false);
        };
        let refs = self.store.message_refs(request_id).await?;
        let web_url = format!("{}/requests/{}", self.public_url, request_id);
        let n = Notification { item: subject, event_id: item.id, event: &item.event, web_url: &web_url };
        let is_new = matches!(item.event, DomainEvent::Requested { .. });
        let done = self.store.delivered_channels(item.id).await?;

        let allowed = subject.channels();
        let mut retry = false;
        for ch in &self.channels {
            if !allowed.is_empty() && !allowed.contains(ch.name()) {
                continue;
            }
            if done.contains(ch.name()) {
                continue;
            }
            let existing = refs.iter().find(|m| &m.channel == ch.name());
            let result = match existing {
                // Already announced (this is a retry).
                Some(_) if is_new => continue,
                Some(m) if ch.capabilities().update => ch.update(m, n).await.map(|()| None),
                _ if worth_a_new_message(&item.event) => ch.notify(n).await,
                _ => continue,
            };
            match result {
                Ok(msg) => {
                    if let Some(msg) = msg {
                        self.store.save_message_ref(request_id, &msg).await?;
                    }
                    self.store.mark_delivered(item.id, ch.name()).await?;
                }
                Err(e) if e.is_retryable() => {
                    debug!(channel = %ch.name(), error = %e, "delivery failed; will retry");
                    retry = true;
                }
                Err(e) => {
                    // Permanent for this channel: do not retry it.
                    warn!(channel = %ch.name(), event = item.event.kind(), error = %e, "delivery failed");
                    self.store.mark_delivered(item.id, ch.name()).await?;
                }
            }
        }
        Ok(retry)
    }

    /// Announce a high-visibility administrative action (e.g. suspension or
    /// bulk revoke) to every configured channel.
    pub async fn announce_admin(&self, action: &AdminAction) {
        let notice = AdminNotice {
            event_id: EventId::new(),
            action: action.action.clone(),
            by: action.by.clone(),
            target: action.target.clone(),
            detail: action.detail.clone(),
            at: action.at,
            web_url: format!("{}/admin", self.public_url),
        };
        for ch in &self.channels {
            if let Err(e) = ch.announce(&notice).await {
                warn!(channel = %ch.name(), action = %action.action, error = %e, "could not announce admin notice");
            }
        }
    }
}

/// A channel that writes to the daemon log.
#[derive(Debug)]
pub struct LogChannel {
    name: countersign_core::ChannelName,
}

impl LogChannel {
    pub fn new(name: countersign_core::ChannelName) -> Self {
        Self { name }
    }
}

#[async_trait::async_trait]
impl Channel for LogChannel {
    fn name(&self) -> &countersign_core::ChannelName {
        &self.name
    }

    fn capabilities(&self) -> countersign_core::ChannelCaps {
        countersign_core::ChannelCaps::default()
    }

    async fn notify(&self, n: Notification<'_>) -> Result<Option<countersign_core::MessageRef>, ChannelError> {
        // Ids and states only: never question or answer text.
        tracing::info!(
            channel = %self.name,
            event = n.event.kind(),
            request = %n.item.id(),
            state = n.item.state(),
            url = n.web_url,
            "notification"
        );
        Ok(None)
    }

    async fn update(&self, _: &countersign_core::MessageRef, _: Notification<'_>) -> Result<(), ChannelError> {
        Err(ChannelError::Unsupported)
    }

    async fn announce(&self, notice: &AdminNotice) -> Result<(), ChannelError> {
        tracing::warn!(
            channel = %self.name,
            action = %notice.action,
            by = %notice.by,
            target = %notice.target,
            detail = notice.detail.as_deref().unwrap_or(""),
            url = %notice.web_url,
            "admin notice"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use jiff::Timestamp;

    use countersign_core::{
        ActorId, Assurance, Channel, ChannelCaps, ChannelError, ChannelName, Exclusion, GrantMode, MessageRef,
        Notification, PendingSubject, PolicyName, Request, Requester, Requirements, Selector, Store, SubjectFacts,
        SubjectRef,
    };
    use countersign_store_sqlite::SqliteStore;

    use super::{Dispatcher, backoff};

    struct RecordingChannel {
        name: ChannelName,
        seen: Mutex<Vec<countersign_core::RequestId>>,
        notices: Mutex<Vec<countersign_core::AdminNotice>>,
    }

    impl std::fmt::Debug for RecordingChannel {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RecordingChannel").field("name", &self.name).finish_non_exhaustive()
        }
    }

    #[async_trait::async_trait]
    impl Channel for RecordingChannel {
        fn name(&self) -> &ChannelName {
            &self.name
        }

        fn capabilities(&self) -> ChannelCaps {
            ChannelCaps::default()
        }

        async fn notify(&self, n: Notification<'_>) -> Result<Option<MessageRef>, ChannelError> {
            self.seen.lock().unwrap().push(n.item.id());
            Ok(None)
        }

        async fn update(&self, _: &MessageRef, _: Notification<'_>) -> Result<(), ChannelError> {
            Err(ChannelError::Unsupported)
        }

        async fn announce(&self, notice: &countersign_core::AdminNotice) -> Result<(), ChannelError> {
            self.notices.lock().unwrap().push(notice.clone());
            Ok(())
        }
    }

    fn open_request(id: &str, channels: Vec<ChannelName>) -> (Request, Vec<countersign_core::DomainEvent>) {
        let now = Timestamp::from_second(1_700_000_000).unwrap();
        let pending = PendingSubject {
            subject: SubjectRef { backend: "sudo".into(), kind: "sudo".into(), id: id.into() },
            facts: SubjectFacts {
                requester: Requester { id: "agent".into(), ..Requester::default() },
                source: None,
                initiator: None,
                sensitive: false,
                target: Some("web-1".into()),
                action: None,
                reason: None,
                requested_ttl: None,
                attributes: BTreeMap::new(),
                binding: None,
            },
            observed_at: now,
        };
        let reqs = Requirements {
            policy: PolicyName::new("p"),
            approvers: vec![Selector::Person(ActorId::new("alice"))],
            exclude: BTreeSet::from([Exclusion::Requester]),
            quorum: 1,
            min_assurance: Assurance::Linked,
            ttl: Duration::from_secs(60),
            pending_timeout: Duration::from_secs(300),
            grant: GrantMode::Once,
            require_initiator: false,
            scope: BTreeMap::new(),
            channels,
        };
        Request::open(pending, reqs, false, now)
    }

    #[test]
    fn backoff_grows_and_caps() {
        let secs: Vec<i64> = (1..=10).map(|a| backoff(a).as_secs()).collect();
        assert_eq!(secs, [5, 10, 20, 40, 80, 160, 320, 600, 600, 600]);
    }

    #[tokio::test]
    async fn policy_routes_to_selected_channels_only() {
        let store: Arc<dyn Store> = Arc::new(SqliteStore::in_memory().await.unwrap());
        let ch_a = Arc::new(RecordingChannel {
            name: ChannelName::new("slack"),
            seen: Mutex::default(),
            notices: Mutex::default(),
        });
        let ch_b = Arc::new(RecordingChannel {
            name: ChannelName::new("discord"),
            seen: Mutex::default(),
            notices: Mutex::default(),
        });
        let dispatcher = Dispatcher::new(Arc::clone(&store), vec![ch_a.clone(), ch_b.clone()], "https://cs.example");

        let (r_routed, ev1) = open_request("r1", vec![ChannelName::new("slack")]);
        store.insert_request(&r_routed, &ev1).await.unwrap();

        let (r_all, ev2) = open_request("r2", vec![]);
        store.insert_request(&r_all, &ev2).await.unwrap();

        let now = Timestamp::from_second(1_700_000_010).unwrap();
        assert_eq!(dispatcher.run_once(now).await.unwrap(), 2);

        assert_eq!(*ch_a.seen.lock().unwrap(), vec![r_routed.id, r_all.id]);
        assert_eq!(*ch_b.seen.lock().unwrap(), vec![r_all.id]);

        // Admin notices always broadcast to every channel.
        dispatcher
            .announce_admin(&countersign_core::AdminAction {
                at: now,
                by: ActorId::new("alice"),
                action: "suspend".into(),
                target: "bob".into(),
                detail: Some("lost laptop".into()),
            })
            .await;
        assert_eq!(ch_a.notices.lock().unwrap().len(), 1);
        assert_eq!(ch_b.notices.lock().unwrap().len(), 1);
        assert_eq!(ch_a.notices.lock().unwrap()[0].web_url, "https://cs.example/admin");
    }
}
