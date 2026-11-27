//! The pages: the `SvelteKit` build in `web/`, run in this process by
//! fetchlet.
//!
//! Rust serves the build's assets and passes every other request to its
//! server code, with a trusted [`Visit`]: the session from the encrypted
//! cookie and whether the request came from the site itself. The server
//! code reaches the [UI API](super::ui) at [`UI_ORIGIN`], and nothing else:
//! it has no network, files or environment.
//!
//! The build is embedded when `web/build` exists as countersignd is
//! compiled (`vp run build` first). Debug builds can serve another
//! build directory instead, named by `COUNTERSIGN_WEB_DIR`.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::PrivateCookieJar;
use axum_extra::extract::cookie::Key;
use fetchlet::{Context, HostServices, Instances, OriginRouter};
use fetchlet_http::{Artifact, ArtifactError, AxumService, artifact_router, router_transport};
use tracing::warn;

use super::session::{SessionData, session_data};
use super::{AppState, Notice, ui};

/// Where the pages' server code reaches the UI API. `.internal` is never
/// delegated in public DNS, and the pages cannot reach anything else.
pub const UI_ORIGIN: &str = "https://countersign.internal";

/// What Rust tells the UI API about a page request.
#[derive(Debug, Clone, Default)]
pub(crate) struct Visit {
    /// From the session cookie; checked by the UI API on every use.
    pub(super) session: Option<SessionData>,
    /// The request came from a page of this site (its `Origin`, or
    /// `Sec-Fetch-Site: same-origin`).
    pub(super) same_origin: bool,
    /// What [`Pages::notice`] asked the pages to show.
    pub(super) notice: Option<Notice>,
}

/// The trusted context for a page request with these headers. The server
/// adds it to every page request; tests use it to call the UI API as a page
/// would.
pub fn visit_context(headers: &HeaderMap, key: &Key, public_origin: &str) -> Context {
    Context::new().with(visit(headers, key, public_origin))
}

fn visit(headers: &HeaderMap, key: &Key, public_origin: &str) -> Visit {
    let jar = PrivateCookieJar::from_headers(headers, key.clone());
    let same_origin = match headers.get(header::ORIGIN) {
        Some(origin) => origin.as_bytes() == public_origin.as_bytes(),
        None => headers.get("sec-fetch-site").is_some_and(|v| v.as_bytes() == b"same-origin"),
    };
    Visit { session: session_data(&jar), same_origin, notice: None }
}

/// `scheme://host[:port]` of a URL, as browsers write it in `Origin`.
pub fn origin_of(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("https", url));
    let scheme = scheme.to_ascii_lowercase();
    let mut host = rest.split(['/', '?', '#']).next().unwrap_or_default().to_ascii_lowercase();
    let default_port = if scheme == "https" { ":443" } else { ":80" };
    if let Some(bare) = host.strip_suffix(default_port) {
        host = bare.to_owned();
    }
    format!("{scheme}://{host}")
}

#[derive(Debug, thiserror::Error)]
pub enum PagesError {
    #[error("web UI build: {0}")]
    Artifact(#[from] ArtifactError),
    #[error("web UI: {0}")]
    Fetchlet(#[from] fetchlet::Error),
    #[error("web UI: {0}")]
    Http(#[from] fetchlet_http::Error),
}

/// Whether this countersignd has pages to serve.
pub fn built_in() -> bool {
    cfg!(countersign_web_ui) || (cfg!(debug_assertions) && std::env::var_os("COUNTERSIGN_WEB_DIR").is_some())
}

fn artifact() -> Result<Option<Artifact>, ArtifactError> {
    #[cfg(debug_assertions)]
    if let Some(dir) = std::env::var_os("COUNTERSIGN_WEB_DIR") {
        return Artifact::open(dir).map(Some);
    }
    #[cfg(countersign_web_ui)]
    return fetchlet_http::include_artifact!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../web/build")).map(Some);
    #[cfg(not(countersign_web_ui))]
    Ok(None)
}

/// The running pages.
#[derive(Clone)]
pub struct Pages {
    artifact: Arc<Artifact>,
    service: AxumService,
}

impl std::fmt::Debug for Pages {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pages").finish_non_exhaustive()
    }
}

impl Pages {
    /// Start the pages' server code, if this countersignd has pages.
    /// `state` is what the UI API serves.
    pub async fn start(state: &AppState) -> Result<Option<Self>, PagesError> {
        let Some(artifact) = artifact()? else {
            return Ok(None);
        };
        let api = OriginRouter::new().internal(UI_ORIGIN, router_transport(ui::ui_router(state.clone())))?;
        let hosts = HostServices::new().outbound(api.into_service());
        let mut options = Artifact::default_worker_options();
        options.instances = Instances {
            min: NonZeroUsize::MIN,
            max: NonZeroUsize::new(2).unwrap_or(NonZeroUsize::MIN),
            idle_timeout: Some(Duration::from_secs(300)),
            max_held_connections: 0,
        };
        let app = artifact.app_builder()?.host_services(hosts).spawn(options).await?;
        let key = state.key.clone();
        let origin = state.settings.public_origin.clone();
        let service = AxumService::new(app, &state.settings.public_origin)?
            .on_error(|e| warn!(error = %e, "rendering a page failed"))
            .trusted_context(move |parts| {
                let mut visit = visit(&parts.headers, &key, &origin);
                visit.notice = parts.extensions.get::<Notice>().cloned();
                Context::new().with(visit)
            });
        Ok(Some(Self { artifact: Arc::new(artifact), service }))
    }

    /// Assets, then the pages.
    pub(super) fn router(&self) -> Router {
        artifact_router(&self.artifact, self.service.clone())
    }

    /// The notice page, with `status`.
    pub(super) async fn notice(&self, status: StatusCode, notice: Notice) -> Response {
        let mut req =
            Request::get("/notice").header(header::ACCEPT, "text/html").body(Body::empty()).unwrap_or_default();
        req.extensions_mut().insert(notice.clone());
        match self.service.fetch(req).await {
            Ok(mut res) => {
                *res.status_mut() = status;
                res
            }
            Err(e) => {
                warn!(error = %e, "rendering a notice failed");
                (status, format!("{}\n\n{}", notice.heading, notice.body)).into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_are_written_as_browsers_do() {
        assert_eq!(origin_of("https://CS.example.test/"), "https://cs.example.test");
        assert_eq!(origin_of("https://cs.example.test:443/x?y"), "https://cs.example.test");
        assert_eq!(origin_of("http://127.0.0.1:8080"), "http://127.0.0.1:8080");
    }

    #[test]
    fn only_this_site_may_change_things() {
        let key = Key::generate();
        let at = |pairs: &[(&'static str, &'static str)]| {
            let mut h = HeaderMap::new();
            for (k, v) in pairs {
                h.insert(*k, v.parse().unwrap());
            }
            visit(&h, &key, "https://cs.example.test").same_origin
        };
        assert!(at(&[("origin", "https://cs.example.test")]));
        assert!(!at(&[("origin", "https://evil.example")]));
        assert!(!at(&[("origin", "null"), ("sec-fetch-site", "same-origin")]), "Origin decides when sent");
        assert!(at(&[("sec-fetch-site", "same-origin")]));
        assert!(!at(&[("sec-fetch-site", "cross-site")]));
        assert!(!at(&[]));
    }
}
