//! Web flows with a fake identity provider and backend: sign-in and the
//! JSON API over HTTP, the UI API as the pages call it, and (when the web
//! UI is built in) the pages themselves.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request as HttpRequest, StatusCode, header};
use countersign_core::{
    AccessBackend, ActionIntent, ActionSink, ActorId, Asker, Assurance, AuthError, Authenticator, BackendCaps,
    BackendError, BackendName, ChannelName, ClientId, Confidentiality, GrantHandle, LoginStart, PendingSubject,
    QuestionOutcome, RequestState, Requester, Store, SubjectFacts, SubjectRef, Verdict, VerifiedLogin,
};
use countersign_store_sqlite::SqliteStore;
use countersignd::Daemon;
use countersignd::config::Config;
use countersignd::engine::Ask;
use countersignd::web;
use http_body_util::BodyExt;
use jiff::Timestamp;
use serde_json::Value;
use tower::ServiceExt;

// ------------------------------------------------------------------ fakes

/// Codes look like `<identity>|<auth_time seconds or "-">`.
#[derive(Debug)]
struct FakeIdp;

#[async_trait]
impl Authenticator for FakeIdp {
    async fn begin(&self, fresh: bool) -> Result<LoginStart, AuthError> {
        Ok(LoginStart { redirect_url: format!("https://idp.test/authorize?fresh={fresh}"), state: "s-123".into() })
    }
    async fn complete(&self, saved: &str, returned: &str, code: &str) -> Result<VerifiedLogin, AuthError> {
        if saved != returned {
            return Err(AuthError::StateMismatch);
        }
        let (identity, at) = code.split_once('|').unwrap();
        Ok(VerifiedLogin {
            identity: identity.into(),
            auth_time: at.parse().ok().map(|s| Timestamp::from_second(s).unwrap()),
            display_name: None,
            groups: None,
        })
    }
}

#[derive(Debug, Default)]
struct OneSession {
    state: Mutex<&'static str>,
}

#[async_trait]
impl AccessBackend for OneSession {
    fn name(&self) -> &BackendName {
        static N: std::sync::OnceLock<BackendName> = std::sync::OnceLock::new();
        N.get_or_init(|| "fake".into())
    }
    fn capabilities(&self) -> BackendCaps {
        BackendCaps { discover: true, revoke: true, native_expiry: true }
    }
    fn identity_scheme(&self) -> &'static str {
        "fake"
    }
    async fn discover_pending(&self) -> Result<Vec<PendingSubject>, BackendError> {
        Ok(if *self.state.lock().unwrap() == "pending" {
            vec![PendingSubject { subject: subject(), facts: facts(), observed_at: Timestamp::now() }]
        } else {
            vec![]
        })
    }
    async fn verify(&self, _: &SubjectRef) -> Result<SubjectFacts, BackendError> {
        Ok(facts())
    }
    async fn grant(&self, s: &SubjectRef, _: Duration) -> Result<GrantHandle, BackendError> {
        *self.state.lock().unwrap() = "active";
        Ok(GrantHandle { subject: s.clone(), backend_ref: None, expires_at: None })
    }
    async fn deny(&self, _: &SubjectRef) -> Result<(), BackendError> {
        *self.state.lock().unwrap() = "rejected";
        Ok(())
    }
    async fn revoke(&self, _: &GrantHandle) -> Result<(), BackendError> {
        *self.state.lock().unwrap() = "revoked";
        Ok(())
    }
}

fn subject() -> SubjectRef {
    SubjectRef { backend: "fake".into(), kind: "session".into(), id: "s1".into() }
}

fn facts() -> SubjectFacts {
    SubjectFacts {
        source: None,
        initiator: None,
        sensitive: false,
        binding: None,
        action: None,
        requester: Requester {
            id: "agent".into(),
            groups: BTreeSet::from(["agents".to_owned()]),
            ..Requester::default()
        },
        target: Some("<script>alert(1)</script>".into()),
        requested_ttl: None,
        reason: Some("deploy \"now\" & <b>fast</b>".into()),
        attributes: BTreeMap::new(),
    }
}

const CONFIG: &str = r#"
    [server]
    public_url = "https://cs.example.test"
    fresh_auth_window = "5m"

    [[person]]
    id = "bob"
    display_name = "Bob"
    identities = ["oidc:idp#bob"]

    [[person]]
    id = "owner"
    identities = ["oidc:idp#agent-owner"]

    [[person]]
    id = "carol"
    identities = ["oidc:idp#carol"]

    [[person]]
    id = "viewer"
    identities = ["oidc:idp#viewer"]

    [[workload]]
    id = "agent"
    owners = ["owner"]
    identities = ["fake:fake#agent"]

    [[group]]
    name = "ops"
    members = ["bob", "owner"]

    [roles]
    member = ["group:ops"]
    auditor = ["person:viewer"]
    admin = ["person:carol"]

    [intake]
    listen = "127.0.0.1:0"
    behind_proxy = true
    signing_key_file = "set by the test"

    [[client]]
    id = "agent-host"
    auth = { host_key = "sha256:1111111111111111111111111111111111111111111111111111111111111111" }
    scopes = ["question"]

    [[question_policy]]
    name = "deploys"
    responders = ["person:bob"]
    min_assurance = "web"
    confidential = "allow"
    confidential_min_assurance = "fresh-auth"

    [[policy]]
    name = "agents"
    match = { backend_group = "agents" }
    approvers = ["group:ops"]
    exclude = ["requester", "owners"]
    max_ttl = "30m"
"#;

const ORIGIN: &str = "https://cs.example.test";

// ------------------------------------------------------------------ client

/// One browser: its cookies, against the whole web router, and against the
/// UI API as the pages call it for this browser's requests.
struct Browser {
    app: Router,
    ui: Router,
    key: axum_extra::extract::cookie::Key,
    cookies: BTreeMap<String, String>,
}

struct Page {
    status: StatusCode,
    location: Option<String>,
    headers: HeaderMap,
    body: String,
}

impl Page {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("{e}: {}", self.body))
    }
}

async fn page(res: axum::response::Response) -> Page {
    let status = res.status();
    let headers = res.headers().clone();
    let location = headers.get(header::LOCATION).map(|l| l.to_str().unwrap().to_owned());
    let body = String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    Page { status, location, headers, body }
}

impl Browser {
    fn new(s: &Setup) -> Self {
        Self {
            app: web::router(s.daemon.web.clone()),
            ui: web::ui_router(s.daemon.web.clone()),
            key: s.daemon.web.key.clone(),
            cookies: BTreeMap::new(),
        }
    }

    fn cookie_header(&self) -> Option<String> {
        (!self.cookies.is_empty())
            .then(|| self.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; "))
    }

    async fn send(&mut self, mut req: HttpRequest<Body>) -> Page {
        if let Some(c) = self.cookie_header() {
            req.headers_mut().insert(header::COOKIE, c.parse().unwrap());
        }
        let res = self.app.clone().oneshot(req).await.unwrap();
        for sc in res.headers().get_all(header::SET_COOKIE) {
            let pair = sc.to_str().unwrap().split(';').next().unwrap();
            let (k, v) = pair.split_once('=').unwrap();
            if v.is_empty() {
                self.cookies.remove(k);
            } else {
                self.cookies.insert(k.into(), v.into());
            }
        }
        page(res).await
    }

    async fn get(&mut self, uri: &str) -> Page {
        self.send(HttpRequest::get(uri).body(Body::empty()).unwrap()).await
    }

    async fn post_form(&mut self, uri: &str, form: &str) -> Page {
        self.send(
            HttpRequest::post(uri)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::ORIGIN, ORIGIN)
                .body(Body::from(form.to_owned()))
                .unwrap(),
        )
        .await
    }

    async fn post_json(&mut self, uri: &str, csrf: &str, json: &str) -> Page {
        self.send(
            HttpRequest::post(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-csrf-token", csrf)
                .body(Body::from(json.to_owned()))
                .unwrap(),
        )
        .await
    }

    /// Call the UI API as the pages do while serving this browser a page
    /// request: with the trusted context Rust derives from that request.
    /// `origin` is the `Origin` the browser sent with it.
    async fn ui(&self, method: Method, path: &str, form: Option<&str>, origin: Option<&str>) -> Page {
        let mut page_headers = HeaderMap::new();
        if let Some(c) = self.cookie_header() {
            page_headers.insert(header::COOKIE, c.parse().unwrap());
        }
        if let Some(o) = origin {
            page_headers.insert(header::ORIGIN, o.parse().unwrap());
        }
        let context = web::visit_context(&page_headers, &self.key, ORIGIN);
        let mut req = HttpRequest::builder().method(method).uri(path);
        if form.is_some() {
            req = req.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        }
        let mut req = req.body(Body::from(form.unwrap_or_default().to_owned())).unwrap();
        req.extensions_mut().insert(context);
        page(self.ui.clone().oneshot(req).await.unwrap()).await
    }

    async fn ui_get(&self, path: &str) -> Page {
        self.ui(Method::GET, path, None, None).await
    }

    /// A page form posted from this site.
    async fn ui_post(&self, path: &str, form: &str) -> Page {
        self.ui(Method::POST, path, Some(form), Some(ORIGIN)).await
    }

    /// Run the whole login dance; `auth_age` is how long ago the identity
    /// provider says the user authenticated (`None`: no `auth_time` claim).
    async fn login(&mut self, identity: &str, auth_age: Option<i64>, next: &str) -> Page {
        let start = self.get(&format!("/login?next={next}")).await;
        assert_eq!(start.status, StatusCode::SEE_OTHER);
        assert!(start.location.unwrap().starts_with("https://idp.test/authorize"));
        let at = auth_age.map_or("-".to_owned(), |a| (Timestamp::now().as_second() - a).to_string());
        self.get(&format!("/auth/callback?state=s-123&code={identity}%7C{at}")).await
    }

    async fn csrf(&mut self) -> String {
        let me = self.get("/api/me").await;
        assert_eq!(me.status, StatusCode::OK, "{}", me.body);
        me.json()["csrf"].as_str().unwrap().to_owned()
    }
}

struct Setup {
    store: Arc<dyn Store>,
    backend: Arc<OneSession>,
    daemon: Daemon,
}

/// A signing key file for the daemon under test (one per test process).
fn signing_key_file() -> std::path::PathBuf {
    static PATH: std::sync::LazyLock<std::path::PathBuf> = std::sync::LazyLock::new(|| {
        let p = std::env::temp_dir().join(format!("countersign-test-signing-{}.key", std::process::id()));
        std::fs::write(&p, countersign_core::approval_signing::ServerKey::generate(&SIGNING_SEED)).unwrap();
        p
    });
    PATH.clone()
}

const SIGNING_SEED: [u8; 32] = [5; 32];

async fn setup(min_assurance: &str) -> Setup {
    let mut config = Config::from_toml(
        &CONFIG.replace("max_ttl = \"30m\"", &format!("max_ttl = \"30m\"\nmin_assurance = \"{min_assurance}\"")),
    )
    .unwrap();
    config.intake.as_mut().unwrap().signing_key_file = signing_key_file();
    let store: Arc<dyn Store> = Arc::new(SqliteStore::in_memory().await.unwrap());
    let backend = Arc::new(OneSession { state: Mutex::new("pending") });
    let mut daemon =
        Daemon::with_parts(&config, Arc::clone(&store), vec![Arc::clone(&backend) as Arc<dyn AccessBackend>], vec![])
            .unwrap();
    daemon.web.auth = Some(Arc::new(FakeIdp));
    daemon.engine.tick(Timestamp::now()).await;
    Setup { store, backend, daemon }
}

impl Setup {
    fn browser(&self) -> Browser {
        Browser::new(self)
    }

    async fn request_id(&self) -> String {
        let all = self.store.list_requests(&countersign_core::RequestFilter::default()).await.unwrap();
        assert_eq!(all.len(), 1);
        all[0].id.to_string()
    }

    async fn ask(&self, message: &str, confidential: bool) -> String {
        let ask = Ask {
            asker: Asker { client: ClientId::new("agent-host"), actor: None },
            message: message.into(),
            schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "env": { "type": "string", "enum": ["staging", "prod"], "title": "Environment" },
                    "note": { "type": "string" }
                },
                "required": ["env"]
            }),
            context: BTreeMap::from([("ticket".to_owned(), "<OPS-1>".to_owned())]),
            confidentiality: Confidentiality { question: confidential, answer_may_be: false },
        };
        self.daemon.engine.ask(ask, Timestamp::now()).await.unwrap().id.to_string()
    }

    async fn state(&self) -> RequestState {
        self.store.list_requests(&countersign_core::RequestFilter::default()).await.unwrap()[0].state.clone()
    }
}

// ------------------------------------------------------------------ sign-in

#[tokio::test]
async fn nobody_is_signed_in_without_a_session() {
    let s = setup("fresh-auth").await;
    let mut b = s.browser();
    assert_eq!(b.get("/api/requests").await.status, StatusCode::UNAUTHORIZED);
    let me = b.ui_get("/me").await;
    assert_eq!((me.status, me.json()["error"].as_str()), (StatusCode::UNAUTHORIZED, Some("unauthenticated")));
    assert_eq!(b.ui_get("/requests").await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_lands_on_next_and_shows_the_request() {
    let s = setup("fresh-auth").await;
    let id = s.request_id().await;
    let mut b = s.browser();
    let p = b.login("oidc:idp%23bob", Some(10), &format!("/requests/{id}")).await;
    assert_eq!(p.status, StatusCode::SEE_OTHER, "{}", p.body);
    assert_eq!(p.location.unwrap(), format!("/requests/{id}"));

    let me = b.ui_get("/me").await.json();
    assert_eq!((me["name"].as_str(), me["member"].as_bool()), (Some("Bob"), Some(true)));
    let item = b.ui_get(&format!("/requests/{id}")).await;
    assert_eq!(item.status, StatusCode::OK);
    let item = item.json();
    assert_eq!(item["kind"], "approval");
    assert_eq!(item["can_decide"], true);
    assert!(item["p"]["claims"].to_string().contains("deploy"), "{item}");
    assert_eq!(item["claims_note"], "from the requester, unverified");

    let index = b.ui_get("/requests").await.json();
    assert_eq!(index["waiting"][0]["id"], id);
    assert_eq!(index["waiting"][0]["tone"], "waiting");
}

#[tokio::test]
async fn open_redirects_are_refused() {
    let s = setup("fresh-auth").await;
    let p = s.browser().login("oidc:idp%23bob", Some(10), "//evil.example/x").await;
    assert_eq!(p.location.as_deref(), Some("/"));
}

#[tokio::test]
async fn non_approvers_and_forged_callbacks_get_no_session() {
    let s = setup("fresh-auth").await;
    let mut b = s.browser();
    let p = b.login("oidc:idp%23stranger", Some(10), "/").await;
    assert_eq!(p.status, StatusCode::FORBIDDEN);
    assert!(p.body.contains("oidc:idp#stranger"), "shows the identity to add: {}", p.body);
    assert!(!b.cookies.contains_key("cs_session"));

    let _ = b.get("/login?next=/").await;
    let p = b.get("/auth/callback?state=forged&code=oidc:idp%23bob%7C1").await;
    assert_eq!(p.status, StatusCode::UNAUTHORIZED);
    assert!(!b.cookies.contains_key("cs_session"));

    // Without the login cookie the callback is useless.
    let p = b.get("/auth/callback?state=s-123&code=oidc:idp%23bob%7C1").await;
    assert_eq!(p.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn signing_out_needs_the_session_token() {
    let s = setup("web").await;
    let mut b = s.browser();
    b.login("oidc:idp%23bob", None, "/").await;
    let csrf = b.csrf().await;
    assert_eq!(b.post_form("/logout", "csrf=nope").await.status, StatusCode::FORBIDDEN);
    assert!(b.cookies.contains_key("cs_session"));
    let p = b.post_form("/logout", &format!("csrf={csrf}")).await;
    assert_eq!(p.status, StatusCode::OK);
    assert!(p.body.contains("Signed out"), "{}", p.body);
    assert!(!b.cookies.contains_key("cs_session"));
    assert_eq!(b.ui_get("/me").await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn cookies_are_hardened_and_headers_set() {
    let s = setup("fresh-auth").await;
    let b = s.browser();
    let res = b.app.clone().oneshot(HttpRequest::get("/login?next=/").body(Body::empty()).unwrap()).await.unwrap();
    let sc = res.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap().to_owned();
    for attr in ["HttpOnly", "Secure", "SameSite=Lax", "Path=/"] {
        assert!(sc.contains(attr), "{attr} missing in {sc}");
    }
    assert!(!sc.contains("s-123"), "login state is encrypted");
    let h = res.headers();
    assert!(h[header::CONTENT_SECURITY_POLICY].to_str().unwrap().contains("frame-ancestors 'none'"));
    // Not no-referrer: browsers would send `Origin: null` with form posts.
    assert_eq!(h[header::REFERRER_POLICY], "same-origin");
    assert_eq!(h[header::CACHE_CONTROL], "no-store");
    let mut b = s.browser();
    assert_eq!(b.get("/healthz").await.body, "ok");
}

// ------------------------------------------------------------------ deciding

#[tokio::test]
async fn approving_needs_fresh_auth_and_a_form_from_this_site() {
    let s = setup("fresh-auth").await;
    let id = s.request_id().await;
    let mut b = s.browser();
    b.login("oidc:idp%23bob", Some(3600), "/").await; // stale sign-in
    let decision = format!("/requests/{id}/decision");

    // A form from another site, or with no origin at all, changes nothing.
    for origin in [Some("https://evil.example"), None] {
        let p = b.ui(Method::POST, &decision, Some("verdict=approve"), origin).await;
        assert_eq!((p.status, p.json()["error"].as_str()), (StatusCode::FORBIDDEN, Some("cross_site")));
    }

    // Stale session: sent to a fresh login, nothing decided.
    assert_eq!(b.ui_get(&format!("/requests/{id}")).await.json()["approve_needs_reauth"], true);
    let p = b.ui_post(&decision, "verdict=approve").await;
    assert_eq!(p.status, StatusCode::UNAUTHORIZED);
    let p = p.json();
    assert_eq!(p["error"], "fresh_auth_required");
    assert_eq!(p["login"], format!("/login?next=/requests/{id}&fresh=1"));
    assert!(s.state().await.is_pending());

    // After re-authenticating, approval goes through.
    b.login("oidc:idp%23bob", Some(5), &format!("/requests/{id}")).await;
    let item = b.ui_get(&format!("/requests/{id}")).await.json();
    assert_eq!(item["approve_needs_reauth"], false);
    assert!(item["fresh_until"].is_string());
    let p = b.ui_post(&decision, "verdict=approve&comment=lgtm").await;
    assert_eq!(p.status, StatusCode::OK, "{}", p.body);
    let r = &s.store.list_requests(&countersign_core::RequestFilter::default()).await.unwrap()[0];
    assert!(matches!(r.state, RequestState::Active { .. }));
    assert_eq!(r.decisions[0].comment.as_deref(), Some("lgtm"));
    assert_eq!(*s.backend.state.lock().unwrap(), "active");

    // Revoke from the page.
    assert_eq!(b.ui_get(&format!("/requests/{id}")).await.json()["can_revoke"], true);
    let p = b.ui_post(&format!("/requests/{id}/revoke"), "").await;
    assert_eq!(p.status, StatusCode::OK, "{}", p.body);
    assert_eq!(*s.backend.state.lock().unwrap(), "revoked");
}

#[tokio::test]
async fn deny_works_without_fresh_auth_and_self_approval_is_refused() {
    let s = setup("fresh-auth").await;
    let id = s.request_id().await;

    let mut owner = s.browser();
    owner.login("oidc:idp%23agent-owner", Some(1), "/").await;
    let item = owner.ui_get(&format!("/requests/{id}")).await.json();
    assert_eq!(item["can_decide"], false);
    assert!(item["cannot_decide"].as_str().unwrap().contains("cannot decide"), "own request shows why");
    let p = owner.ui_post(&format!("/requests/{id}/decision"), "verdict=approve").await;
    assert_eq!(p.status, StatusCode::FORBIDDEN);

    let mut bob = s.browser();
    bob.login("oidc:idp%23bob", None, "/").await; // no auth_time claim at all
    let p = bob.ui_post(&format!("/requests/{id}/decision"), "verdict=deny").await;
    assert_eq!(p.status, StatusCode::OK, "{}", p.body);
    assert_eq!(s.state().await, RequestState::Denied);
    assert_eq!(*s.backend.state.lock().unwrap(), "rejected");
}

#[tokio::test]
async fn sensitive_approvals_still_show_everything_on_the_web() {
    let s = setup("web").await;
    let id = s.request_id().await;
    let mut r = s.store.get_request(id.parse().unwrap()).await.unwrap().unwrap();
    let v = r.version;
    r.sensitive = true;
    r.version += 1;
    s.store.update_request(&r, v, &[]).await.unwrap();
    let mut b = s.browser();
    b.login("oidc:idp%23bob", None, "/").await;
    let item = b.ui_get(&format!("/requests/{id}")).await.json();
    assert_eq!(item["sensitive"], true);
    assert!(item["p"]["claims"].to_string().contains("deploy"), "{item}");
    let index = b.ui_get("/requests").await.json();
    assert!(index["waiting"][0].get("summary").is_none(), "lists leave a sensitive command out");
}

// ------------------------------------------------------------------ JSON API

#[tokio::test]
async fn json_api_flow() {
    let s = setup("web").await;
    let id = s.request_id().await;
    let mut b = s.browser();
    b.login("oidc:idp%23bob", None, "/").await;

    let list = b.get("/api/requests?open=1").await;
    assert_eq!(list.json().as_array().unwrap().len(), 1);

    let p = b.post_json(&format!("/api/requests/{id}/decision"), "wrong", r#"{"verdict":"approve"}"#).await;
    assert_eq!(p.status, StatusCode::FORBIDDEN);

    let csrf = b.csrf().await;
    let p = b.post_json(&format!("/api/requests/{id}/decision"), &csrf, r#"{"verdict":"approve"}"#).await;
    assert_eq!(p.status, StatusCode::OK, "{}", p.body);
    assert_eq!(p.json()["state"]["state"], "active");
}

#[tokio::test]
async fn json_api_reports_fresh_auth_requirement() {
    let s = setup("fresh-auth").await;
    let id = s.request_id().await;
    let mut b = s.browser();
    b.login("oidc:idp%23bob", Some(3600), "/").await;
    let csrf = b.csrf().await;
    let p = b.post_json(&format!("/api/requests/{id}/decision"), &csrf, r#"{"verdict":"approve"}"#).await;
    assert_eq!(p.status, StatusCode::UNAUTHORIZED);
    let v = p.json();
    assert_eq!(v["error"], "fresh_auth_required");
    assert_eq!(v["login"], format!("/login?next=/requests/{id}&fresh=1"));
}

// ------------------------------------------------------------------ admin

#[tokio::test]
async fn suspending_a_person_ends_their_session_at_once() {
    let s = setup("fresh-auth").await;
    let mut bob = s.browser();
    bob.login("oidc:idp%23bob", Some(1), "/").await;
    assert_eq!(bob.ui_get("/requests").await.status, StatusCode::OK);
    assert_eq!(bob.ui_get("/me").await.json()["oversees"], false);
    assert_eq!(bob.ui_get("/admin").await.status, StatusCode::FORBIDDEN, "members do not oversee");

    let mut auditor = s.browser();
    auditor.login("oidc:idp%23viewer", Some(1), "/admin").await;
    let page = auditor.ui_get("/admin").await;
    assert_eq!(page.status, StatusCode::OK, "auditors see the directory");
    assert_eq!(page.json()["admin"], false);
    let p = auditor.ui_post("/admin/action", "action=suspend&actor=owner").await;
    assert_eq!(p.status, StatusCode::FORBIDDEN, "only admins act");

    let mut admin = s.browser();
    admin.login("oidc:idp%23carol", Some(1), "/admin").await;
    let p =
        admin.ui(Method::POST, "/admin/action", Some("action=suspend&actor=bob"), Some("https://evil.example")).await;
    assert_eq!(p.status, StatusCode::FORBIDDEN, "not from another site");
    let p = admin.ui_post("/admin/action", "action=suspend&actor=bob&reason=lost+phone").await;
    assert_eq!(p.status, StatusCode::OK, "{}", p.body);
    assert_eq!(bob.ui_get("/requests").await.status, StatusCode::UNAUTHORIZED, "bob is signed out");
    let page = admin.ui_get("/admin").await.json();
    let bob_row = page["actors"].as_array().unwrap().iter().find(|a| a["id"] == "bob").unwrap().clone();
    assert_eq!(bob_row["suspension"]["by"], "carol");
    assert_eq!(bob_row["suspension"]["reason"], "lost phone");

    // Lifting it needs a fresh sign-in.
    let mut stale = s.browser();
    stale.login("oidc:idp%23carol", Some(3600), "/admin").await;
    let p = stale.ui_post("/admin/action", "action=reinstate&actor=bob").await;
    assert_eq!(p.status, StatusCode::UNAUTHORIZED);
    assert_eq!(p.json()["login"], "/login?next=/admin&fresh=1");
    let p = admin.ui_post("/admin/action", "action=reinstate&actor=bob").await;
    assert_eq!(p.status, StatusCode::OK, "{}", p.body);
    bob.login("oidc:idp%23bob", Some(1), "/").await;
    assert_eq!(bob.ui_get("/requests").await.status, StatusCode::OK);
}

// ------------------------------------------------------------------ questions

#[tokio::test]
async fn questions_are_answered_from_the_web_form() {
    let s = setup("web").await;
    let id = s.ask("Deploy <b>now</b>?", false).await;
    let mut b = s.browser();
    b.login("oidc:idp%23bob", None, "/").await;
    let index = b.ui_get("/requests").await.json();
    assert_eq!(
        (index["waiting"][0]["id"].as_str(), index["waiting"][0]["kind"].as_str()),
        (Some(id.as_str()), Some("question"))
    );

    let item = b.ui_get(&format!("/requests/{id}")).await.json();
    assert_eq!(item["kind"], "question");
    assert_eq!(item["can_answer"], true);
    assert_eq!(item["q"]["message"], "Deploy <b>now</b>?", "raw: the page escapes it");
    assert_eq!(item["q"]["context"][0], serde_json::json!(["ticket", "<OPS-1>"]));
    let env = &item["q"]["fields"][0];
    assert_eq!(
        (env["input"].as_str(), env["label"].as_str(), env["kind"].as_str()),
        (Some("f.env"), Some("Environment"), Some("choice"))
    );

    let answer = format!("/requests/{id}/answer");
    let p = b.ui_post(&answer, "action=answer&f.env=").await;
    assert_eq!(p.status, StatusCode::BAD_REQUEST, "env is required: {}", p.body);
    let p = b.ui_post(&answer, "action=answer&f.env=prod&f.note=go").await;
    assert_eq!(p.status, StatusCode::OK, "{}", p.body);
    let question = s.store.get_question(id.parse().unwrap()).await.unwrap().unwrap();
    let Some(QuestionOutcome::Accepted { content: Some(content), by, confidential, .. }) = question.outcome else {
        panic!("{question:?}")
    };
    assert_eq!(
        (content["env"].as_str(), content["note"].as_str(), by.as_str(), confidential),
        (Some("prod"), Some("go"), "bob", false)
    );
    let item = b.ui_get(&format!("/requests/{id}")).await.json();
    assert_eq!(item["q"]["outcome"]["kind"], "answered");
    assert_eq!(item["q"]["answer"][0], serde_json::json!(["Environment", "prod"]));
}

#[tokio::test]
async fn questions_can_be_declined_with_a_note() {
    let s = setup("web").await;
    let id = s.ask("Deploy?", false).await;
    let mut b = s.browser();
    b.login("oidc:idp%23bob", None, "/").await;
    let p = b.ui_post(&format!("/requests/{id}/answer"), "action=decline&note=not+today").await;
    assert_eq!(p.status, StatusCode::OK, "{}", p.body);
    let item = b.ui_get(&format!("/requests/{id}")).await.json();
    assert_eq!(
        (item["q"]["outcome"]["kind"].as_str(), item["q"]["note"].as_str()),
        (Some("declined"), Some("not today"))
    );
}

#[tokio::test]
async fn confidential_questions_are_only_for_their_responders() {
    let s = setup("web").await;
    let id = s.ask("Which vault key?", true).await;

    // An auditor sees that it exists, not what it says.
    let mut viewer = s.browser();
    viewer.login("oidc:idp%23viewer", Some(1), "/").await;
    let page = viewer.ui_get(&format!("/requests/{id}")).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(!page.body.contains("vault") && !page.body.contains("OPS-1"), "{}", page.body);
    let api = viewer.get(&format!("/api/questions/{id}")).await;
    assert!(!api.body.contains("vault"), "{}", api.body);

    // The responder needs a fresh sign-in to read it.
    let mut bob = s.browser();
    bob.login("oidc:idp%23bob", Some(3600), "/").await;
    let page = bob.ui_get(&format!("/requests/{id}")).await;
    assert!(!page.body.contains("vault"), "{}", page.body);
    assert_eq!(page.json()["read_needs_reauth"], true);
    bob.login("oidc:idp%23bob", Some(1), "/").await;
    let page = bob.ui_get(&format!("/requests/{id}")).await.json();
    assert_eq!(page["q"]["message"], "Which vault key?");

    let p = bob.ui_post(&format!("/requests/{id}/answer"), "action=answer&f.env=prod").await;
    assert_eq!(p.status, StatusCode::OK, "{}", p.body);
    let q = s.store.get_question(id.parse().unwrap()).await.unwrap().unwrap();
    assert!(q.message.is_empty() && q.content_removed, "the text goes once the question is closed");
    assert!(matches!(q.outcome, Some(QuestionOutcome::Accepted { confidential: true, .. })));
}

// ------------------------------------------------------------------ chat links

#[tokio::test]
async fn chat_accounts_link_with_one_time_codes_and_decide_at_linked_assurance() {
    let s = setup("linked").await;
    let id: countersign_core::RequestId = s.request_id().await.parse().unwrap();
    let sink: Arc<dyn ActionSink> = s.daemon.sink.clone();
    let discord = ChannelName::new("discord");

    let mut b = s.browser();
    assert_eq!(b.ui_post("/link", "").await.status, StatusCode::UNAUTHORIZED);
    b.login("oidc:idp%23bob", None, "/link").await;
    let p = b.ui(Method::POST, "/link", Some(""), Some("https://evil.example")).await;
    assert_eq!(p.status, StatusCode::FORBIDDEN);
    let p = b.ui_post("/link", "").await;
    assert_eq!(p.status, StatusCode::OK, "{}", p.body);
    let code = p.json()["code"].as_str().unwrap().to_owned();
    assert_eq!(code.len(), 11, "{code}");

    assert_eq!(sink.resolve_account(&discord, "42").await, Ok(None));
    assert!(sink.link_account(&discord, "42", "WRONG-CODE").await.is_err());
    assert_eq!(sink.link_account(&discord, "42", &code.to_lowercase()).await, Ok(ActorId::new("bob")));
    assert!(sink.link_account(&discord, "43", &code).await.is_err(), "codes are single-use");
    assert_eq!(sink.resolve_account(&discord, "42").await, Ok(Some(ActorId::new("bob"))));
    assert_eq!(sink.resolve_account(&ChannelName::new("other"), "42").await, Ok(None), "links are per channel");

    let intent = ActionIntent {
        request_id: id,
        verdict: Verdict::Approve,
        approver: ActorId::new("bob"),
        assurance: Assurance::Linked,
        via: discord,
        comment: None,
    };
    let r = sink.submit(intent).await.unwrap();
    assert!(matches!(r.state, RequestState::Active { .. }), "{:?}", r.state);
    assert_eq!(*s.backend.state.lock().unwrap(), "active");
}

#[tokio::test]
async fn chat_approvals_are_refused_when_the_policy_needs_more_than_linked() {
    let s = setup("web").await;
    let id: countersign_core::RequestId = s.request_id().await.parse().unwrap();
    let sink: Arc<dyn ActionSink> = s.daemon.sink.clone();
    let mut intent = ActionIntent {
        request_id: id,
        verdict: Verdict::Approve,
        approver: ActorId::new("bob"),
        assurance: Assurance::Linked,
        via: ChannelName::new("discord"),
        comment: None,
    };
    let err = sink.submit(intent.clone()).await.unwrap_err();
    assert!(err.contains("assurance"), "{err}");
    intent.verdict = Verdict::Deny;
    assert_eq!(sink.submit(intent).await.unwrap().state, RequestState::Denied, "denials are always accepted");
}

// ------------------------------------------------------------------ the pages

/// Through the real pages, when this countersignd has them (`pnpm build`
/// before building it).
#[tokio::test(flavor = "multi_thread")]
async fn pages_render_escaped_and_decide_through_form_actions() {
    if !web::pages_built_in() {
        eprintln!("skipped: the web UI is not built in");
        return;
    }
    let mut s = setup("web").await;
    s.daemon.web.pages = web::Pages::start(&s.daemon.web).await.unwrap();
    let id = s.request_id().await;
    let mut b = s.browser();

    // Signed out: off to sign in.
    let p = b.get("/").await;
    assert_eq!(p.status, StatusCode::SEE_OTHER, "{}", p.body);
    assert_eq!(p.location.as_deref(), Some("/login?next=%2F"));

    // A sign-in problem is a page too.
    let p = b.login("oidc:idp%23stranger", Some(10), "/").await;
    assert_eq!(p.status, StatusCode::FORBIDDEN);
    assert!(p.headers[header::CONTENT_TYPE].to_str().unwrap().starts_with("text/html"), "{:?}", p.headers);
    assert!(p.body.contains("No access") && p.body.contains("oidc:idp#stranger"), "{}", p.body);

    b.login("oidc:idp%23bob", None, "/").await;
    let index = b.get("/").await;
    assert_eq!(index.status, StatusCode::OK, "{}", index.body);
    assert!(index.body.contains(&format!("/requests/{id}")), "{}", index.body);
    let csp = index.headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
    assert!(csp.contains("script-src 'self' 'nonce-"), "{csp}");

    let page = b.get(&format!("/requests/{id}")).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(page.body.contains("&lt;script>alert(1)&lt;/script>"), "target is escaped: {}", page.body);
    assert!(!page.body.contains("<script>alert"));
    assert!(page.body.contains("unverified"));

    // A form posted from another site is refused before anything happens.
    let p = b
        .send(
            HttpRequest::post(format!("/requests/{id}?/decide"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::ORIGIN, "https://evil.example")
                .body(Body::from("verdict=approve"))
                .unwrap(),
        )
        .await;
    assert_eq!(p.status, StatusCode::FORBIDDEN, "{}", p.body);
    assert!(s.state().await.is_pending());

    // From this site (without JavaScript), the action decides.
    let p = b.post_form(&format!("/requests/{id}?/decide"), "verdict=approve&comment=from+the+page").await;
    assert_eq!(p.status, StatusCode::OK, "{}", p.body);
    assert!(matches!(s.state().await, RequestState::Active { .. }), "{:?}", s.state().await);

    // Static assets are served with their own caching.
    let asset = index.body.split("/_app/immutable/").nth(1).and_then(|r| r.split('"').next()).unwrap();
    let a = b.get(&format!("/_app/immutable/{asset}")).await;
    assert_eq!(a.status, StatusCode::OK);
    assert!(a.headers[header::CACHE_CONTROL].to_str().unwrap().contains("immutable"), "{:?}", a.headers);
}
