//! Prometheus text-format metrics endpoint (`/metrics`).
//!
//! Served on an optional dedicated listener (`server.metrics_listen`, e.g.
//! `127.0.0.1:2790`) so operational counts are never exposed on the public web
//! UI by accident.

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use countersign_core::{RequestFilter, RequestState, Store, StoreError, Verdict};

const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// In-process monotonic counters incremented by the engine and dispatcher.
#[derive(Debug, Default)]
pub struct Metrics {
    decisions_approve: AtomicU64,
    decisions_deny: AtomicU64,
    break_glass: AtomicU64,
    outbox_ok: AtomicU64,
    outbox_retry: AtomicU64,
    outbox_failed: AtomicU64,
    admin_actions: AtomicU64,
}

impl Metrics {
    pub fn record_decision(&self, verdict: Verdict) {
        match verdict {
            Verdict::Approve => self.decisions_approve.fetch_add(1, Ordering::Relaxed),
            Verdict::Deny => self.decisions_deny.fetch_add(1, Ordering::Relaxed),
        };
    }

    pub fn record_break_glass(&self) {
        self.break_glass.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_outbox_ok(&self) {
        self.outbox_ok.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_outbox_retry(&self) {
        self.outbox_retry.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_outbox_failed(&self) {
        self.outbox_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_admin_action(&self) {
        self.admin_actions.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Clone)]
struct MetricsState {
    store: Arc<dyn Store>,
    metrics: Arc<Metrics>,
}

/// Router exposing `GET /metrics` in Prometheus 0.0.4 text format.
pub fn router(store: Arc<dyn Store>, metrics: Arc<Metrics>) -> Router {
    Router::new().route("/metrics", get(scrape)).with_state(MetricsState { store, metrics })
}

async fn scrape(State(state): State<MetricsState>) -> Response {
    match render(state.store.as_ref(), &state.metrics).await {
        Ok(body) => (StatusCode::OK, [(header::CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)], body).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "scraping metrics failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "metrics scrape failed\n").into_response()
        }
    }
}

/// Render all gauges and counters in Prometheus text exposition format.
pub async fn render(store: &dyn Store, m: &Metrics) -> Result<String, StoreError> {
    let open_approvals = store.list_requests(&RequestFilter { open_only: true, limit: None }).await?;
    let open_questions = store.list_questions(&RequestFilter { open_only: true, limit: None }).await?;

    let mut approval_pending = 0u64;
    let mut approval_approved = 0u64;
    let mut approval_active = 0u64;
    for r in &open_approvals {
        match r.state {
            RequestState::Pending => approval_pending += 1,
            RequestState::Approved => approval_approved += 1,
            RequestState::Active { .. } => approval_active += 1,
            _ => {}
        }
    }
    let question_pending = u64::try_from(open_questions.len()).unwrap_or(u64::MAX);

    let mut out = String::with_capacity(1024);
    let _ = writeln!(out, "# HELP countersign_requests_open Number of open requests and questions by kind and state.");
    let _ = writeln!(out, "# TYPE countersign_requests_open gauge");
    let _ = writeln!(out, "countersign_requests_open{{kind=\"approval\",state=\"pending\"}} {approval_pending}");
    let _ = writeln!(out, "countersign_requests_open{{kind=\"approval\",state=\"approved\"}} {approval_approved}");
    let _ = writeln!(out, "countersign_requests_open{{kind=\"approval\",state=\"active\"}} {approval_active}");
    let _ = writeln!(out, "countersign_requests_open{{kind=\"question\",state=\"pending\"}} {question_pending}");

    let _ = writeln!(out, "# HELP countersign_decisions_total Decisions recorded since startup.");
    let _ = writeln!(out, "# TYPE countersign_decisions_total counter");
    let _ = writeln!(
        out,
        "countersign_decisions_total{{verdict=\"approve\"}} {}",
        m.decisions_approve.load(Ordering::Relaxed)
    );
    let _ =
        writeln!(out, "countersign_decisions_total{{verdict=\"deny\"}} {}", m.decisions_deny.load(Ordering::Relaxed));

    let _ = writeln!(out, "# HELP countersign_break_glass_total Emergency break-glass approvals since startup.");
    let _ = writeln!(out, "# TYPE countersign_break_glass_total counter");
    let _ = writeln!(out, "countersign_break_glass_total {}", m.break_glass.load(Ordering::Relaxed));

    let _ = writeln!(out, "# HELP countersign_outbox_deliveries_total Outbox channel delivery attempts since startup.");
    let _ = writeln!(out, "# TYPE countersign_outbox_deliveries_total counter");
    let _ =
        writeln!(out, "countersign_outbox_deliveries_total{{result=\"ok\"}} {}", m.outbox_ok.load(Ordering::Relaxed));
    let _ = writeln!(
        out,
        "countersign_outbox_deliveries_total{{result=\"retry\"}} {}",
        m.outbox_retry.load(Ordering::Relaxed)
    );
    let _ = writeln!(
        out,
        "countersign_outbox_deliveries_total{{result=\"failed\"}} {}",
        m.outbox_failed.load(Ordering::Relaxed)
    );

    let _ = writeln!(out, "# HELP countersign_admin_actions_total Administrative actions recorded since startup.");
    let _ = writeln!(out, "# TYPE countersign_admin_actions_total counter");
    let _ = writeln!(out, "countersign_admin_actions_total {}", m.admin_actions.load(Ordering::Relaxed));

    Ok(out)
}

#[cfg(test)]
mod tests {
    use countersign_store_sqlite::SqliteStore;

    use super::*;

    #[tokio::test]
    async fn renders_valid_prometheus_text() {
        let store = SqliteStore::in_memory().await.unwrap();
        let m = Metrics::default();
        m.record_decision(Verdict::Approve);
        m.record_decision(Verdict::Deny);
        m.record_break_glass();
        m.record_outbox_ok();
        m.record_admin_action();

        let text = render(&store, &m).await.unwrap();
        assert!(text.contains("countersign_requests_open{kind=\"approval\",state=\"pending\"} 0"));
        assert!(text.contains("countersign_decisions_total{verdict=\"approve\"} 1"));
        assert!(text.contains("countersign_decisions_total{verdict=\"deny\"} 1"));
        assert!(text.contains("countersign_break_glass_total 1"));
        assert!(text.contains("countersign_outbox_deliveries_total{result=\"ok\"} 1"));
        assert!(text.contains("countersign_admin_actions_total 1"));
    }
}
