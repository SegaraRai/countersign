//! Web UI and JSON API for persons.
//!
//! - The pages are a `SvelteKit` application (`web/` in the repository) that
//!   runs inside this process through fetchlet: Rust serves its assets and
//!   hands every other request to its server code ([`pages`]). The pages
//!   read and change state only through the in-process [UI API](ui), which
//!   no browser can reach. Rust tells that API who is asking through a
//!   trusted context that JavaScript can neither read nor forge.
//! - Sign-in, sign-out and the JSON API are Rust routes.
//! - Sessions live in an encrypted, HTTP-only cookie. Every request re-checks
//!   that the sign-in identity still belongs to the person, that the person
//!   is active (not suspended) and holds a role, so a suspension or a config
//!   change ends their access at once.
//! - Every state-changing request must come from this site: page forms by
//!   their origin, the sign-out form and the JSON API by the per-session
//!   CSRF token.
//! - A decision counts as `fresh-auth` only while the identity provider's
//!   `auth_time` is within `server.fresh_auth_window`. When a policy needs
//!   more than the session offers, the user is sent through a fresh login
//!   (`prompt=login`) and back.
//! - Members see what they could decide or answer, what they took part in,
//!   and what they or their workloads asked for; auditors and admins see
//!   everything. Confidential question content is shown only to that
//!   question's responders, and only while it is kept.

mod api;
mod auth;
mod pages;
mod session;
mod ui;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{FromRef, Request as HttpRequest};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum_extra::extract::cookie::Key;
use serde::Serialize;

use countersign_core::{AnswerError, Authenticator, TransitionError};

use crate::engine::{Engine, EngineError};
use crate::link::LinkCodes;

pub use pages::{Pages, PagesError, UI_ORIGIN, built_in as pages_built_in, origin_of, visit_context};
pub use ui::ui_router;

/// Settings for the web layer, derived from `[server]`.
#[derive(Debug, Clone)]
pub struct WebSettings {
    pub secure_cookies: bool,
    pub session_ttl: Duration,
    pub fresh_auth_window: Duration,
    /// `scheme://host[:port]` of `server.public_url`: what browsers send as
    /// `Origin`, and what the pages see as their own.
    pub public_origin: String,
}

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<Engine>,
    pub auth: Option<Arc<dyn Authenticator>>,
    pub links: Arc<LinkCodes>,
    pub key: Key,
    pub settings: Arc<WebSettings>,
    /// The pages, once started ([`Pages::start`]). Without them only
    /// sign-in, the JSON API and `/healthz` answer.
    pub pages: Option<Pages>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("settings", &self.settings)
            .field("pages", &self.pages.is_some())
            .finish_non_exhaustive()
    }
}

impl FromRef<AppState> for Key {
    fn from_ref(s: &AppState) -> Self {
        s.key.clone()
    }
}

pub fn router(state: AppState) -> Router {
    let pages = state.pages.clone();
    let rust = Router::new()
        .route("/login", get(auth::login))
        .route("/auth/callback", get(auth::callback))
        .route("/logout", post(auth::logout))
        .route("/api/me", get(api::me))
        .route("/api/requests", get(api::list))
        .route("/api/requests/{id}", get(api::get))
        .route("/api/requests/{id}/decision", post(api::decide))
        .route("/api/questions", get(api::questions))
        .route("/api/questions/{id}", get(api::question))
        .route("/api/questions/{id}/answer", post(api::answer))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state);
    let app = match pages {
        Some(p) => rust.merge(p.router()),
        None => rust.fallback(|| async {
            (StatusCode::SERVICE_UNAVAILABLE, "The web UI is not built into this countersignd.")
        }),
    };
    app.layer(middleware::from_fn(security_headers))
}

/// The baseline headers. Pages set their own content security policy, with
/// nonces for their scripts, and assets their own caching.
async fn security_headers(req: HttpRequest, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    if !h.contains_key(header::CONTENT_SECURITY_POLICY) {
        h.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
        );
    }
    if !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    // Not `no-referrer`: under it browsers send `Origin: null` with form
    // posts, and the pages accept a post only from their own origin.
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    res
}

/// A message page for what happens outside the pages: sign-in problems.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Notice {
    heading: String,
    body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

/// The notice rendered by the pages, or as plain text without them.
async fn notice(state: &AppState, status: StatusCode, heading: &str, body: &str, detail: Option<String>) -> Response {
    let notice = Notice { heading: heading.into(), body: body.into(), detail };
    if let Some(pages) = &state.pages {
        return pages.notice(status, notice).await;
    }
    let mut text = format!("{}\n\n{}", notice.heading, notice.body);
    if let Some(d) = &notice.detail {
        text.push_str("\n\n");
        text.push_str(d);
    }
    (status, text).into_response()
}

fn human_error(e: &EngineError) -> (StatusCode, String) {
    let status = match e {
        EngineError::UnknownRequest(_) | EngineError::UnknownQuestion(_) => StatusCode::NOT_FOUND,
        EngineError::Forbidden(_)
        | EngineError::Refused(_)
        | EngineError::Transition(
            TransitionError::NotEligible | TransitionError::Inactive | TransitionError::Excluded(_),
        )
        | EngineError::Answer(AnswerError::NotEligible | AnswerError::Inactive | AnswerError::SelfAnswer) => {
            StatusCode::FORBIDDEN
        }
        EngineError::Invalid(_) | EngineError::Answer(AnswerError::Invalid(_) | AnswerError::MustStayConfidential) => {
            StatusCode::BAD_REQUEST
        }
        EngineError::Transition(_) | EngineError::Answer(_) | EngineError::Busy => StatusCode::CONFLICT,
        EngineError::Backend(_) => StatusCode::BAD_GATEWAY,
        EngineError::Store(_) | EngineError::UnknownBackend(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, e.to_string())
}

fn clean_comment(c: Option<String>) -> Option<String> {
    c.map(|c| c.trim().chars().take(500).collect::<String>()).filter(|c| !c.is_empty())
}
