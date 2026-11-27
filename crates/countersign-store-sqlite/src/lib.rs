//! SQLite implementation of [`countersign_core::Store`].
//!
//! Approvals and questions are stored as JSON next to the indexed columns used
//! for lookups. A partial unique index enforces at most one open request per
//! subject, and changes and their outbox events are written in one
//! transaction. `secure_delete` is on, so overwritten confidential content
//! does not linger in free pages.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use jiff::Timestamp;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Row, SqlitePool, Transaction};

use countersign_core::{
    AccountLink, ActorId, AdminAction, ChannelName, DomainEvent, EventId, IdpSnapshot, MessageRef, OutboxItem,
    Question, Request, RequestFilter, RequestId, Store, StoreError, SubjectRef, Suspension,
};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// A [`Store`] backed by a SQLite database.
#[derive(Debug, Clone)]
pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    /// Open (creating if needed) the database at `url`, e.g.
    /// `sqlite:///var/lib/countersign/state.db`, and apply migrations.
    pub async fn open(url: &str) -> Result<Self, StoreError> {
        let opts = SqliteConnectOptions::from_str(url)
            .map_err(other)?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .foreign_keys(true)
            .pragma("secure_delete", "ON")
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new().max_connections(8).connect_with(opts).await.map_err(other)?;
        Self::from_pool(pool).await
    }

    /// A private in-memory database, mainly for tests.
    pub async fn in_memory() -> Result<Self, StoreError> {
        let opts = SqliteConnectOptions::from_str("sqlite::memory:")
            .map_err(other)?
            .foreign_keys(true)
            .pragma("secure_delete", "ON");
        // Each in-memory connection is its own database: keep exactly one.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect_with(opts)
            .await
            .map_err(other)?;
        Self::from_pool(pool).await
    }

    /// Use an existing pool, applying migrations.
    pub async fn from_pool(pool: SqlitePool) -> Result<Self, StoreError> {
        MIGRATOR.run(&pool).await.map_err(other)?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

fn other(e: impl std::error::Error + Send + Sync + 'static) -> StoreError {
    StoreError::Other(Box::new(e))
}

fn ms(t: Timestamp) -> i64 {
    t.as_millisecond()
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.is_unique_violation())
}

fn decode_request(body: &str) -> Result<Request, StoreError> {
    serde_json::from_str(body).map_err(other)
}

fn decode_question(body: &str) -> Result<Question, StoreError> {
    serde_json::from_str(body).map_err(other)
}

fn at(ms: i64) -> Result<Timestamp, StoreError> {
    Timestamp::from_millisecond(ms).map_err(other)
}

const QUESTION: &str = "question";

async fn enqueue(
    tx: &mut Transaction<'_, sqlx::Sqlite>,
    events: &[DomainEvent],
    now: Timestamp,
) -> Result<(), StoreError> {
    for ev in events {
        sqlx::query(
            "INSERT INTO outbox (id, request_id, kind, event, available_at_ms, created_at_ms)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(EventId::new().to_string())
        .bind(ev.request_id().to_string())
        .bind(ev.kind())
        .bind(serde_json::to_string(ev).map_err(other)?)
        .bind(ms(now))
        .bind(ms(now))
        .execute(&mut **tx)
        .await
        .map_err(other)?;
    }
    Ok(())
}

#[async_trait]
impl Store for SqliteStore {
    async fn insert_request(&self, request: &Request, events: &[DomainEvent]) -> Result<(), StoreError> {
        let body = serde_json::to_string(request).map_err(other)?;
        let mut tx = self.pool.begin().await.map_err(other)?;
        sqlx::query(
            "INSERT INTO requests
               (id, kind, backend, subject_kind, subject_id, state, is_open, version, created_at_ms, updated_at_ms, body)
             VALUES (?, 'approval', ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(request.id.to_string())
        .bind(request.subject.backend.as_str())
        .bind(&request.subject.kind)
        .bind(&request.subject.id)
        .bind(request.state.name())
        .bind(!request.state.is_terminal())
        .bind(version_to_db(request.version)?)
        .bind(ms(request.created_at))
        .bind(ms(request.updated_at))
        .bind(body)
        .execute(&mut *tx)
        .await
        .map_err(|e| if is_unique_violation(&e) { StoreError::Duplicate } else { other(e) })?;
        enqueue(&mut tx, events, request.updated_at).await?;
        tx.commit().await.map_err(other)
    }

    async fn update_request(
        &self,
        request: &Request,
        expected_version: u64,
        events: &[DomainEvent],
    ) -> Result<(), StoreError> {
        let body = serde_json::to_string(request).map_err(other)?;
        let mut tx = self.pool.begin().await.map_err(other)?;
        let res = sqlx::query(
            "UPDATE requests
                SET state = ?, is_open = ?, version = ?, updated_at_ms = ?, body = ?
              WHERE id = ? AND version = ? AND kind = 'approval'",
        )
        .bind(request.state.name())
        .bind(!request.state.is_terminal())
        .bind(version_to_db(request.version)?)
        .bind(ms(request.updated_at))
        .bind(body)
        .bind(request.id.to_string())
        .bind(version_to_db(expected_version)?)
        .execute(&mut *tx)
        .await
        .map_err(other)?;
        if res.rows_affected() == 0 {
            let exists = sqlx::query("SELECT 1 FROM requests WHERE id = ? AND kind = 'approval'")
                .bind(request.id.to_string())
                .fetch_optional(&mut *tx)
                .await
                .map_err(other)?
                .is_some();
            return Err(if exists { StoreError::Conflict(request.id) } else { StoreError::NotFound(request.id) });
        }
        enqueue(&mut tx, events, request.updated_at).await?;
        tx.commit().await.map_err(other)
    }

    async fn get_request(&self, id: RequestId) -> Result<Option<Request>, StoreError> {
        let row = sqlx::query("SELECT body FROM requests WHERE id = ? AND kind = 'approval'")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(other)?;
        row.map(|r| decode_request(r.get("body"))).transpose()
    }

    async fn find_open_by_subject(&self, subject: &SubjectRef) -> Result<Option<Request>, StoreError> {
        let row = sqlx::query(
            "SELECT body FROM requests
              WHERE kind = 'approval' AND backend = ? AND subject_kind = ? AND subject_id = ? AND is_open = 1",
        )
        .bind(subject.backend.as_str())
        .bind(&subject.kind)
        .bind(&subject.id)
        .fetch_optional(&self.pool)
        .await
        .map_err(other)?;
        row.map(|r| decode_request(r.get("body"))).transpose()
    }

    async fn find_latest_by_subject(&self, subject: &SubjectRef) -> Result<Option<Request>, StoreError> {
        let row = sqlx::query(
            "SELECT body FROM requests
              WHERE kind = 'approval' AND backend = ? AND subject_kind = ? AND subject_id = ?
              ORDER BY created_at_ms DESC, id DESC
              LIMIT 1",
        )
        .bind(subject.backend.as_str())
        .bind(&subject.kind)
        .bind(&subject.id)
        .fetch_optional(&self.pool)
        .await
        .map_err(other)?;
        row.map(|r| decode_request(r.get("body"))).transpose()
    }

    async fn list_requests(&self, filter: &RequestFilter) -> Result<Vec<Request>, StoreError> {
        let limit = filter.limit.map_or(-1, i64::from);
        let rows = sqlx::query(
            "SELECT body FROM requests
              WHERE kind = 'approval' AND (? = 0 OR is_open = 1)
              ORDER BY created_at_ms DESC, id DESC
              LIMIT ?",
        )
        .bind(filter.open_only)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(other)?;
        rows.iter().map(|r| decode_request(r.get("body"))).collect()
    }

    async fn insert_question(&self, question: &Question, events: &[DomainEvent]) -> Result<(), StoreError> {
        let body = serde_json::to_string(question).map_err(other)?;
        let mut tx = self.pool.begin().await.map_err(other)?;
        sqlx::query(
            "INSERT INTO requests
               (id, kind, backend, subject_kind, subject_id, state, is_open, holds_content, version,
                created_at_ms, updated_at_ms, body)
             VALUES (?, 'question', ?, 'question', ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(question.id.to_string())
        .bind(question.asker.client.as_str())
        .bind(question.id.to_string())
        .bind(question.state())
        .bind(question.is_pending())
        .bind(question.holds_content())
        .bind(version_to_db(question.version)?)
        .bind(ms(question.created_at))
        .bind(ms(question.updated_at))
        .bind(body)
        .execute(&mut *tx)
        .await
        .map_err(|e| if is_unique_violation(&e) { StoreError::Duplicate } else { other(e) })?;
        enqueue(&mut tx, events, question.updated_at).await?;
        tx.commit().await.map_err(other)
    }

    async fn update_question(
        &self,
        question: &Question,
        expected_version: u64,
        events: &[DomainEvent],
    ) -> Result<(), StoreError> {
        let body = serde_json::to_string(question).map_err(other)?;
        let mut tx = self.pool.begin().await.map_err(other)?;
        let res = sqlx::query(
            "UPDATE requests
                SET state = ?, is_open = ?, holds_content = ?, version = ?, updated_at_ms = ?, body = ?
              WHERE id = ? AND version = ? AND kind = 'question'",
        )
        .bind(question.state())
        .bind(question.is_pending())
        .bind(question.holds_content())
        .bind(version_to_db(question.version)?)
        .bind(ms(question.updated_at))
        .bind(body)
        .bind(question.id.to_string())
        .bind(version_to_db(expected_version)?)
        .execute(&mut *tx)
        .await
        .map_err(other)?;
        if res.rows_affected() == 0 {
            let exists = sqlx::query("SELECT 1 FROM requests WHERE id = ? AND kind = 'question'")
                .bind(question.id.to_string())
                .fetch_optional(&mut *tx)
                .await
                .map_err(other)?
                .is_some();
            return Err(if exists { StoreError::Conflict(question.id) } else { StoreError::NotFound(question.id) });
        }
        enqueue(&mut tx, events, question.updated_at).await?;
        tx.commit().await.map_err(other)?;
        if question.shows_removed() {
            // `secure_delete` zeroes freed pages in the main database file,
            // but in WAL mode prior page images remain in `-wal` until
            // checkpointed and truncated. Best-effort: a concurrent reader
            // may defer truncation to a later checkpoint.
            let _ = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)").execute(&self.pool).await;
        }
        Ok(())
    }

    async fn get_question(&self, id: RequestId) -> Result<Option<Question>, StoreError> {
        let row = sqlx::query("SELECT body FROM requests WHERE id = ? AND kind = ?")
            .bind(id.to_string())
            .bind(QUESTION)
            .fetch_optional(&self.pool)
            .await
            .map_err(other)?;
        row.map(|r| decode_question(r.get("body"))).transpose()
    }

    async fn list_questions(&self, filter: &RequestFilter) -> Result<Vec<Question>, StoreError> {
        let limit = filter.limit.map_or(-1, i64::from);
        let rows = sqlx::query(
            "SELECT body FROM requests
              WHERE kind = 'question' AND (? = 0 OR is_open = 1)
              ORDER BY created_at_ms DESC, id DESC
              LIMIT ?",
        )
        .bind(filter.open_only)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(other)?;
        rows.iter().map(|r| decode_question(r.get("body"))).collect()
    }

    async fn questions_holding_content(&self) -> Result<Vec<Question>, StoreError> {
        let rows = sqlx::query(
            "SELECT body FROM requests WHERE kind = 'question' AND holds_content = 1 AND is_open = 0 ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(other)?;
        rows.iter().map(|r| decode_question(r.get("body"))).collect()
    }

    async fn claim_outbox(&self, limit: u32, lease: Duration, now: Timestamp) -> Result<Vec<OutboxItem>, StoreError> {
        let lease_ms = i64::try_from(lease.as_millis()).unwrap_or(i64::MAX);
        let rows = sqlx::query(
            "UPDATE outbox
                SET available_at_ms = ?1 + ?2, attempts = attempts + 1
              WHERE seq IN (
                    SELECT seq FROM outbox
                     WHERE delivered_at_ms IS NULL AND available_at_ms <= ?1
                     ORDER BY seq
                     LIMIT ?3)
             RETURNING seq, id, event, attempts",
        )
        .bind(ms(now))
        .bind(lease_ms)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(other)?;

        let mut items: Vec<(i64, OutboxItem)> = rows
            .iter()
            .map(|r| {
                let id: String = r.get("id");
                let event: String = r.get("event");
                let attempts: i64 = r.get("attempts");
                Ok((
                    r.get("seq"),
                    OutboxItem {
                        id: id.parse().map_err(other)?,
                        event: serde_json::from_str(&event).map_err(other)?,
                        attempts: u32::try_from(attempts).unwrap_or(u32::MAX),
                    },
                ))
            })
            .collect::<Result<_, StoreError>>()?;
        // RETURNING order is unspecified.
        items.sort_by_key(|(seq, _)| *seq);
        Ok(items.into_iter().map(|(_, item)| item).collect())
    }

    async fn complete_outbox(&self, id: EventId) -> Result<(), StoreError> {
        sqlx::query("UPDATE outbox SET delivered_at_ms = ?, last_error = NULL WHERE id = ?")
            .bind(ms(Timestamp::now()))
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(other)?;
        Ok(())
    }

    async fn mark_delivered(&self, id: EventId, channel: &ChannelName) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO outbox_deliveries (event_id, channel, delivered_at_ms) VALUES (?, ?, ?)
             ON CONFLICT (event_id, channel) DO NOTHING",
        )
        .bind(id.to_string())
        .bind(channel.as_str())
        .bind(ms(Timestamp::now()))
        .execute(&self.pool)
        .await
        .map_err(other)?;
        Ok(())
    }

    async fn delivered_channels(&self, id: EventId) -> Result<Vec<ChannelName>, StoreError> {
        let rows = sqlx::query("SELECT channel FROM outbox_deliveries WHERE event_id = ? ORDER BY channel")
            .bind(id.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(other)?;
        Ok(rows.iter().map(|r| ChannelName::new(r.get::<String, _>("channel"))).collect())
    }

    async fn fail_outbox(&self, id: EventId, retry_at: Timestamp, error: &str) -> Result<(), StoreError> {
        sqlx::query("UPDATE outbox SET available_at_ms = ?, last_error = ? WHERE id = ? AND delivered_at_ms IS NULL")
            .bind(ms(retry_at))
            .bind(error)
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(other)?;
        Ok(())
    }

    async fn save_message_ref(&self, request_id: RequestId, msg: &MessageRef) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO message_refs (request_id, channel, message_id) VALUES (?, ?, ?)
             ON CONFLICT (request_id, channel) DO UPDATE SET message_id = excluded.message_id",
        )
        .bind(request_id.to_string())
        .bind(msg.channel.as_str())
        .bind(&msg.id)
        .execute(&self.pool)
        .await
        .map_err(other)?;
        Ok(())
    }

    async fn message_refs(&self, request_id: RequestId) -> Result<Vec<MessageRef>, StoreError> {
        let rows = sqlx::query("SELECT channel, message_id FROM message_refs WHERE request_id = ? ORDER BY channel")
            .bind(request_id.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(other)?;
        Ok(rows
            .iter()
            .map(|r| MessageRef { channel: ChannelName::new(r.get::<String, _>("channel")), id: r.get("message_id") })
            .collect())
    }

    async fn link_account(&self, channel: &ChannelName, external_id: &str, person: &ActorId) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO account_links (channel, external_id, actor_id, linked_at_ms) VALUES (?, ?, ?, ?)
             ON CONFLICT (channel, external_id)
             DO UPDATE SET actor_id = excluded.actor_id, linked_at_ms = excluded.linked_at_ms",
        )
        .bind(channel.as_str())
        .bind(external_id)
        .bind(person.as_str())
        .bind(ms(Timestamp::now()))
        .execute(&self.pool)
        .await
        .map_err(other)?;
        Ok(())
    }

    async fn resolve_account(&self, channel: &ChannelName, external_id: &str) -> Result<Option<ActorId>, StoreError> {
        let row = sqlx::query("SELECT actor_id FROM account_links WHERE channel = ? AND external_id = ?")
            .bind(channel.as_str())
            .bind(external_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(other)?;
        Ok(row.map(|r| ActorId::new(r.get::<String, _>("actor_id"))))
    }

    async fn list_account_links(&self) -> Result<Vec<AccountLink>, StoreError> {
        let rows = sqlx::query(
            "SELECT channel, external_id, actor_id, linked_at_ms FROM account_links ORDER BY channel, external_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(other)?;
        rows.iter()
            .map(|r| {
                Ok(AccountLink {
                    channel: ChannelName::new(r.get::<String, _>("channel")),
                    external_id: r.get("external_id"),
                    person: ActorId::new(r.get::<String, _>("actor_id")),
                    linked_at: at(r.get("linked_at_ms"))?,
                })
            })
            .collect()
    }

    async fn unlink_account(&self, channel: &ChannelName, external_id: &str) -> Result<bool, StoreError> {
        let done = sqlx::query("DELETE FROM account_links WHERE channel = ? AND external_id = ?")
            .bind(channel.as_str())
            .bind(external_id)
            .execute(&self.pool)
            .await
            .map_err(other)?;
        Ok(done.rows_affected() > 0)
    }

    async fn suspend(&self, actor: &ActorId, suspension: &Suspension) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO suspensions (actor_id, body) VALUES (?, ?)
             ON CONFLICT (actor_id) DO UPDATE SET body = excluded.body",
        )
        .bind(actor.as_str())
        .bind(serde_json::to_string(suspension).map_err(other)?)
        .execute(&self.pool)
        .await
        .map_err(other)?;
        Ok(())
    }

    async fn reinstate(&self, actor: &ActorId) -> Result<bool, StoreError> {
        let done = sqlx::query("DELETE FROM suspensions WHERE actor_id = ?")
            .bind(actor.as_str())
            .execute(&self.pool)
            .await
            .map_err(other)?;
        Ok(done.rows_affected() > 0)
    }

    async fn suspensions(&self) -> Result<BTreeMap<ActorId, Suspension>, StoreError> {
        let rows = sqlx::query("SELECT actor_id, body FROM suspensions").fetch_all(&self.pool).await.map_err(other)?;
        rows.iter()
            .map(|r| {
                let body: String = r.get("body");
                Ok((ActorId::new(r.get::<String, _>("actor_id")), serde_json::from_str(&body).map_err(other)?))
            })
            .collect()
    }

    async fn save_idp_snapshot(&self, person: &ActorId, snapshot: &IdpSnapshot) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO idp_snapshots (person_id, body) VALUES (?, ?)
             ON CONFLICT (person_id) DO UPDATE SET body = excluded.body",
        )
        .bind(person.as_str())
        .bind(serde_json::to_string(snapshot).map_err(other)?)
        .execute(&self.pool)
        .await
        .map_err(other)?;
        Ok(())
    }

    async fn idp_snapshots(&self) -> Result<BTreeMap<ActorId, IdpSnapshot>, StoreError> {
        let rows =
            sqlx::query("SELECT person_id, body FROM idp_snapshots").fetch_all(&self.pool).await.map_err(other)?;
        rows.iter()
            .map(|r| {
                let body: String = r.get("body");
                Ok((ActorId::new(r.get::<String, _>("person_id")), serde_json::from_str(&body).map_err(other)?))
            })
            .collect()
    }

    async fn record_admin_action(&self, action: &AdminAction) -> Result<(), StoreError> {
        sqlx::query("INSERT INTO admin_actions (at_ms, by_id, action, target, detail) VALUES (?, ?, ?, ?, ?)")
            .bind(ms(action.at))
            .bind(action.by.as_str())
            .bind(&action.action)
            .bind(&action.target)
            .bind(action.detail.as_deref())
            .execute(&self.pool)
            .await
            .map_err(other)?;
        Ok(())
    }

    async fn admin_actions(&self, limit: u32) -> Result<Vec<AdminAction>, StoreError> {
        let rows =
            sqlx::query("SELECT at_ms, by_id, action, target, detail FROM admin_actions ORDER BY seq DESC LIMIT ?")
                .bind(i64::from(limit))
                .fetch_all(&self.pool)
                .await
                .map_err(other)?;
        rows.iter()
            .map(|r| {
                Ok(AdminAction {
                    at: at(r.get("at_ms"))?,
                    by: ActorId::new(r.get::<String, _>("by_id")),
                    action: r.get("action"),
                    target: r.get("target"),
                    detail: r.get("detail"),
                })
            })
            .collect()
    }
}

fn version_to_db(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(other)
}
