//! SQLite implementation of [`countersign_core::Store`].
//!
//! Requests are stored as JSON next to the indexed columns used for lookups.
//! A partial unique index enforces at most one open request per subject, and
//! request changes and their outbox events are written in one transaction.

use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use countersign_core::{
    ApproverId, ChannelName, DomainEvent, EventId, MessageRef, OutboxItem, Request, RequestFilter, RequestId, Store,
    StoreError, SubjectRef,
};
use jiff::Timestamp;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Row, SqlitePool, Transaction};

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
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new().max_connections(8).connect_with(opts).await.map_err(other)?;
        Self::from_pool(pool).await
    }

    /// A private in-memory database, mainly for tests.
    pub async fn in_memory() -> Result<Self, StoreError> {
        let opts = SqliteConnectOptions::from_str("sqlite::memory:").map_err(other)?.foreign_keys(true);
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
               (id, backend, subject_kind, subject_id, state, is_open, version, created_at_ms, updated_at_ms, body)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
              WHERE id = ? AND version = ?",
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
            let exists = sqlx::query("SELECT 1 FROM requests WHERE id = ?")
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
        let row = sqlx::query("SELECT body FROM requests WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(other)?;
        row.map(|r| decode_request(r.get("body"))).transpose()
    }

    async fn find_open_by_subject(&self, subject: &SubjectRef) -> Result<Option<Request>, StoreError> {
        let row = sqlx::query(
            "SELECT body FROM requests
              WHERE backend = ? AND subject_kind = ? AND subject_id = ? AND is_open = 1",
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
              WHERE (? = 0 OR is_open = 1)
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

    async fn link_account(
        &self,
        channel: &ChannelName,
        external_id: &str,
        approver: &ApproverId,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO account_links (channel, external_id, approver_id, linked_at_ms) VALUES (?, ?, ?, ?)
             ON CONFLICT (channel, external_id)
             DO UPDATE SET approver_id = excluded.approver_id, linked_at_ms = excluded.linked_at_ms",
        )
        .bind(channel.as_str())
        .bind(external_id)
        .bind(approver.as_str())
        .bind(ms(Timestamp::now()))
        .execute(&self.pool)
        .await
        .map_err(other)?;
        Ok(())
    }

    async fn resolve_account(
        &self,
        channel: &ChannelName,
        external_id: &str,
    ) -> Result<Option<ApproverId>, StoreError> {
        let row = sqlx::query("SELECT approver_id FROM account_links WHERE channel = ? AND external_id = ?")
            .bind(channel.as_str())
            .bind(external_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(other)?;
        Ok(row.map(|r| ApproverId::new(r.get::<String, _>("approver_id"))))
    }
}

fn version_to_db(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(other)
}
