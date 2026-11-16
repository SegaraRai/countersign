//! Web UI and API flows with a fake identity provider and backend.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{Request as HttpRequest, StatusCode, header};
use countersign_core::{
    AccessBackend, ActionIntent, ActionSink, ActorId, Asker, Assurance, AuthError, Authenticator, BackendCaps,
    BackendError, BackendName, ChannelName, ClientId, Confidentiality, GrantHandle, LoginStart, PendingSubject,
    QuestionOutcome, RequestState, Requester, Store, SubjectFacts, SubjectRef, Verdict, VerifiedLogin,
};
use countersign_store_sqlite::SqliteStore;
use countersignd::Daemon;
use countersignd::config::Config;
use countersignd::engine::Ask;
use http_body_util::BodyExt;
use jiff::Timestamp;
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

// ------------------------------------------------------------------ client

struct Browser {
    app: Router,
    cookies: BTreeMap<String, String>,
}

struct Page {
    status: StatusCode,
    location: Option<String>,
    body: String,
}

impl Browser {
    async fn send(&mut self, req: HttpRequest<Body>) -> Page {
        let mut req = req;
        if !self.cookies.is_empty() {
            let c = self.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ");
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
        let status = res.status();
        let location = res.headers().get(header::LOCATION).map(|l| l.to_str().unwrap().to_owned());
        let body = String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
        Page { status, location, body }
    }

    async fn get(&mut self, uri: &str) -> Page {
        self.send(HttpRequest::get(uri).body(Body::empty()).unwrap()).await
    }

    async fn post_form(&mut self, uri: &str, form: &str) -> Page {
        self.send(
            HttpRequest::post(uri)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
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
        let v: serde_json::Value = serde_json::from_str(&me.body).unwrap();
        v["csrf"].as_str().unwrap().to_owned()
    }
}

struct Setup {
    browser: Browser,
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
    let browser = Browser { app: countersignd::web::router(daemon.web.clone()), cookies: BTreeMap::new() };
    Setup { browser, store, backend, daemon }
}

impl Setup {
    async fn request_id(&self) -> String {
        let all = self.store.list_requests(&countersign_core::RequestFilter::default()).await.unwrap();
        assert_eq!(all.len(), 1);
        all[0].id.to_string()
    }
}

// ------------------------------------------------------------------ tests

#[tokio::test]
async fn anonymous_users_are_sent_to_login() {
    let mut s = setup("fresh-auth").await;
    let id = s.request_id().await;
    let p = s.browser.get("/").await;
    assert_eq!(p.status, StatusCode::SEE_OTHER);
    assert_eq!(p.location.as_deref(), Some("/login?next=/"));
    let p = s.browser.get(&format!("/requests/{id}")).await;
    assert_eq!(p.location.unwrap(), format!("/login?next=/requests/{id}"));
    assert_eq!(s.browser.get("/api/requests").await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_lands_on_next_and_lists_requests_escaped() {
    let mut s = setup("fresh-auth").await;
    let id = s.request_id().await;
    let p = s.browser.login("oidc:idp%23bob", Some(10), &format!("/requests/{id}")).await;
    assert_eq!(p.status, StatusCode::SEE_OTHER, "{}", p.body);
    assert_eq!(p.location.unwrap(), format!("/requests/{id}"));

    let page = s.browser.get(&format!("/requests/{id}")).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("Bob"));
    assert!(page.body.contains("&#60;script&#62;alert(1)&#60;/script&#62;"), "target is escaped: {}", page.body);
    assert!(!page.body.contains("<script>alert"));
    assert!(page.body.contains("unverified"));

    let index = s.browser.get("/").await;
    assert!(index.body.contains(&id));
}

#[tokio::test]
async fn open_redirects_are_refused() {
    let mut s = setup("fresh-auth").await;
    let p = s.browser.login("oidc:idp%23bob", Some(10), "//evil.example/x").await;
    assert_eq!(p.location.as_deref(), Some("/"));
}

#[tokio::test]
async fn non_approvers_and_forged_callbacks_get_no_session() {
    let mut s = setup("fresh-auth").await;
    let p = s.browser.login("oidc:idp%23stranger", Some(10), "/").await;
    assert_eq!(p.status, StatusCode::FORBIDDEN);
    assert!(p.body.contains("oidc:idp#stranger"), "shows the identity to add");
    assert!(!s.browser.cookies.contains_key("cs_session"));

    let _ = s.browser.get("/login?next=/").await;
    let p = s.browser.get("/auth/callback?state=forged&code=oidc:idp%23bob%7C1").await;
    assert_eq!(p.status, StatusCode::UNAUTHORIZED);
    assert!(!s.browser.cookies.contains_key("cs_session"));

    // Without the login cookie the callback is useless.
    let p = s.browser.get("/auth/callback?state=s-123&code=oidc:idp%23bob%7C1").await;
    assert_eq!(p.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn approving_needs_fresh_auth_and_csrf() {
    let mut s = setup("fresh-auth").await;
    let id = s.request_id().await;
    s.browser.login("oidc:idp%23bob", Some(3600), "/").await; // stale sign-in
    let csrf = s.browser.csrf().await;

    // Wrong CSRF token.
    let p = s.browser.post_form(&format!("/requests/{id}/decision"), "verdict=approve&csrf=nope").await;
    assert_eq!(p.status, StatusCode::FORBIDDEN);

    // Stale session: sent to a fresh login, nothing decided.
    let page = s.browser.get(&format!("/requests/{id}")).await;
    assert!(page.body.contains("Sign in again to approve"));
    let p = s.browser.post_form(&format!("/requests/{id}/decision"), &format!("verdict=approve&csrf={csrf}")).await;
    assert_eq!(p.status, StatusCode::SEE_OTHER);
    assert_eq!(p.location.unwrap(), format!("/login?next=/requests/{id}&fresh=1"));
    assert!(s.store.list_requests(&countersign_core::RequestFilter::default()).await.unwrap()[0].state.is_pending());

    // After re-authenticating, approval goes through.
    s.browser.login("oidc:idp%23bob", Some(5), &format!("/requests/{id}")).await;
    let csrf = s.browser.csrf().await;
    let p = s
        .browser
        .post_form(&format!("/requests/{id}/decision"), &format!("verdict=approve&comment=lgtm&csrf={csrf}"))
        .await;
    assert_eq!(p.status, StatusCode::SEE_OTHER, "{}", p.body);
    let r = &s.store.list_requests(&countersign_core::RequestFilter::default()).await.unwrap()[0];
    assert!(matches!(r.state, RequestState::Active { .. }));
    assert_eq!(r.decisions[0].comment.as_deref(), Some("lgtm"));
    assert_eq!(*s.backend.state.lock().unwrap(), "active");

    // Revoke from the page.
    let p = s.browser.post_form(&format!("/requests/{id}/revoke"), &format!("csrf={csrf}")).await;
    assert_eq!(p.status, StatusCode::SEE_OTHER);
    assert_eq!(*s.backend.state.lock().unwrap(), "revoked");
}

#[tokio::test]
async fn deny_works_without_fresh_auth_and_self_approval_is_refused() {
    let mut s = setup("fresh-auth").await;
    let id = s.request_id().await;

    s.browser.login("oidc:idp%23agent-owner", Some(1), "/").await;
    let csrf = s.browser.csrf().await;
    let page = s.browser.get(&format!("/requests/{id}")).await;
    assert!(page.body.contains("cannot decide"), "own request shows why");
    let p = s.browser.post_form(&format!("/requests/{id}/decision"), &format!("verdict=approve&csrf={csrf}")).await;
    assert_eq!(p.status, StatusCode::FORBIDDEN);

    let mut other = Browser { app: s.browser.app.clone(), cookies: BTreeMap::new() };
    other.login("oidc:idp%23bob", None, "/").await; // no auth_time claim at all
    let csrf = other.csrf().await;
    let p = other.post_form(&format!("/requests/{id}/decision"), &format!("verdict=deny&csrf={csrf}")).await;
    assert_eq!(p.status, StatusCode::SEE_OTHER);
    assert_eq!(
        s.store.list_requests(&countersign_core::RequestFilter::default()).await.unwrap()[0].state,
        RequestState::Denied
    );
    assert_eq!(*s.backend.state.lock().unwrap(), "rejected");
}

#[tokio::test]
async fn json_api_flow() {
    let mut s = setup("web").await;
    let id = s.request_id().await;
    s.browser.login("oidc:idp%23bob", None, "/").await;

    let list = s.browser.get("/api/requests?open=1").await;
    let v: serde_json::Value = serde_json::from_str(&list.body).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 1);

    let p = s.browser.post_json(&format!("/api/requests/{id}/decision"), "wrong", r#"{"verdict":"approve"}"#).await;
    assert_eq!(p.status, StatusCode::FORBIDDEN);

    let csrf = s.browser.csrf().await;
    let p = s.browser.post_json(&format!("/api/requests/{id}/decision"), &csrf, r#"{"verdict":"approve"}"#).await;
    assert_eq!(p.status, StatusCode::OK, "{}", p.body);
    let v: serde_json::Value = serde_json::from_str(&p.body).unwrap();
    assert_eq!(v["state"]["state"], "active");
}

#[tokio::test]
async fn json_api_reports_fresh_auth_requirement() {
    let mut s = setup("fresh-auth").await;
    let id = s.request_id().await;
    s.browser.login("oidc:idp%23bob", Some(3600), "/").await;
    let csrf = s.browser.csrf().await;
    let p = s.browser.post_json(&format!("/api/requests/{id}/decision"), &csrf, r#"{"verdict":"approve"}"#).await;
    assert_eq!(p.status, StatusCode::UNAUTHORIZED);
    let v: serde_json::Value = serde_json::from_str(&p.body).unwrap();
    assert_eq!(v["error"], "fresh_auth_required");
    assert_eq!(v["login"], format!("/login?next=/requests/{id}&fresh=1"));
}

#[tokio::test]
async fn suspending_a_person_ends_their_session_at_once() {
    let mut s = setup("fresh-auth").await;
    s.browser.login("oidc:idp%23bob", Some(1), "/").await;
    assert_eq!(s.browser.get("/").await.status, StatusCode::OK);
    assert_eq!(s.browser.get("/admin").await.status, StatusCode::FORBIDDEN, "members do not oversee");
    let mut auditor = Browser { app: s.browser.app.clone(), cookies: BTreeMap::new() };
    auditor.login("oidc:idp%23viewer", Some(1), "/admin").await;
    assert_eq!(auditor.get("/admin").await.status, StatusCode::OK, "auditors see the directory");
    let csrf = auditor.csrf().await;
    let p = auditor.post_form("/admin/action", &format!("csrf={csrf}&action=suspend&actor=owner")).await;
    assert_eq!(p.status, StatusCode::FORBIDDEN, "only admins act");

    let mut admin = Browser { app: s.browser.app.clone(), cookies: BTreeMap::new() };
    admin.login("oidc:idp%23carol", Some(1), "/admin").await;
    let csrf = admin.csrf().await;
    let p = admin.post_form("/admin/action", &format!("csrf={csrf}&action=suspend&actor=bob&reason=lost+phone")).await;
    assert_eq!(p.status, StatusCode::SEE_OTHER, "{}", p.body);
    assert_eq!(s.browser.get("/").await.status, StatusCode::SEE_OTHER, "bob is signed out");
    let page = admin.get("/admin").await;
    assert!(page.body.contains("lost phone") && page.body.contains("suspended by carol"), "{}", page.body);

    // Lifting it needs a fresh sign-in.
    let mut stale = Browser { app: s.browser.app.clone(), cookies: BTreeMap::new() };
    stale.login("oidc:idp%23carol", Some(3600), "/admin").await;
    let csrf = stale.csrf().await;
    let p = stale.post_form("/admin/action", &format!("csrf={csrf}&action=reinstate&actor=bob")).await;
    assert_eq!(p.location.as_deref(), Some("/login?next=/admin&fresh=1"));
    let p = admin.post_form("/admin/action", &format!("csrf={csrf}&action=reinstate&actor=bob")).await;
    assert_eq!(p.status, StatusCode::FORBIDDEN, "another session's token");
    let csrf = admin.csrf().await;
    let p = admin.post_form("/admin/action", &format!("csrf={csrf}&action=reinstate&actor=bob")).await;
    assert_eq!(p.status, StatusCode::SEE_OTHER);
    s.browser.login("oidc:idp%23bob", Some(1), "/").await;
    assert_eq!(s.browser.get("/").await.status, StatusCode::OK);
}

impl Setup {
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
}

#[tokio::test]
async fn questions_are_answered_from_the_web_form() {
    let mut s = setup("web").await;
    let id = s.ask("Deploy <b>now</b>?", false).await;
    s.browser.login("oidc:idp%23bob", None, "/").await;
    let index = s.browser.get("/").await;
    assert!(index.body.contains(&id) && index.body.contains("question"), "{}", index.body);
    let page = s.browser.get(&format!("/requests/{id}")).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("Deploy &#60;b&#62;now&#60;/b&#62;?"), "escaped: {}", page.body);
    assert!(page.body.contains("Environment") && page.body.contains("f.env"), "{}", page.body);
    assert!(page.body.contains("&#60;OPS-1&#62;"));

    let csrf = s.browser.csrf().await;
    let p = s.browser.post_form(&format!("/requests/{id}/answer"), &format!("csrf={csrf}&action=answer&f.env=")).await;
    assert_eq!(p.status, StatusCode::BAD_REQUEST, "env is required");
    let p = s
        .browser
        .post_form(&format!("/requests/{id}/answer"), &format!("csrf={csrf}&action=answer&f.env=prod&f.note=go"))
        .await;
    assert_eq!(p.status, StatusCode::SEE_OTHER, "{}", p.body);
    let q = s.store.get_question(id.parse().unwrap()).await.unwrap().unwrap();
    let Some(QuestionOutcome::Accepted { content: Some(c), by, confidential, .. }) = q.outcome else { panic!("{q:?}") };
    assert_eq!(
        (c["env"].as_str(), c["note"].as_str(), by.as_str(), confidential),
        (Some("prod"), Some("go"), "bob", false)
    );
}

#[tokio::test]
async fn confidential_questions_are_only_for_their_responders() {
    let mut s = setup("web").await;
    let id = s.ask("Which vault key?", true).await;

    // An auditor sees that it exists, not what it says.
    let mut viewer = Browser { app: s.browser.app.clone(), cookies: BTreeMap::new() };
    viewer.login("oidc:idp%23viewer", Some(1), "/").await;
    let page = viewer.get(&format!("/requests/{id}")).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(!page.body.contains("vault") && !page.body.contains("OPS-1"), "{}", page.body);
    let api = viewer.get(&format!("/api/questions/{id}")).await;
    assert!(!api.body.contains("vault"), "{}", api.body);

    // The responder needs a fresh sign-in to read it.
    s.browser.login("oidc:idp%23bob", Some(3600), "/").await;
    let page = s.browser.get(&format!("/requests/{id}")).await;
    assert!(!page.body.contains("vault") && page.body.contains("fresh sign-in"), "{}", page.body);
    s.browser.login("oidc:idp%23bob", Some(1), "/").await;
    let page = s.browser.get(&format!("/requests/{id}")).await;
    assert!(page.body.contains("Which vault key?"), "{}", page.body);

    let csrf = s.browser.csrf().await;
    let p =
        s.browser.post_form(&format!("/requests/{id}/answer"), &format!("csrf={csrf}&action=answer&f.env=prod")).await;
    assert_eq!(p.status, StatusCode::SEE_OTHER, "{}", p.body);
    let q = s.store.get_question(id.parse().unwrap()).await.unwrap().unwrap();
    assert!(q.message.is_empty() && q.content_removed, "the text goes once the question is closed");
    assert!(matches!(q.outcome, Some(QuestionOutcome::Accepted { confidential: true, .. })));
}

#[tokio::test]
async fn sensitive_approvals_still_show_everything_on_the_web() {
    let mut s = setup("web").await;
    let id = s.request_id().await;
    let mut r = s.store.get_request(id.parse().unwrap()).await.unwrap().unwrap();
    let v = r.version;
    r.sensitive = true;
    r.version += 1;
    s.store.update_request(&r, v, &[]).await.unwrap();
    s.browser.login("oidc:idp%23bob", None, "/").await;
    let page = s.browser.get(&format!("/requests/{id}")).await;
    assert!(page.body.contains("Sensitive") && page.body.contains("deploy"), "{}", page.body);
}

#[tokio::test]
async fn cookies_are_hardened_and_headers_set() {
    let mut s = setup("fresh-auth").await;
    let res =
        s.browser.app.clone().oneshot(HttpRequest::get("/login?next=/").body(Body::empty()).unwrap()).await.unwrap();
    let sc = res.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap().to_owned();
    for attr in ["HttpOnly", "Secure", "SameSite=Lax", "Path=/"] {
        assert!(sc.contains(attr), "{attr} missing in {sc}");
    }
    assert!(!sc.contains("s-123"), "login state is encrypted");
    let csp = res.headers().get(header::CONTENT_SECURITY_POLICY).unwrap().to_str().unwrap();
    assert!(csp.contains("frame-ancestors 'none'"));
    let p = s.browser.get("/healthz").await;
    assert_eq!(p.body, "ok");
}

fn link_code(body: &str) -> String {
    let start = body.find("user-select: all\">").expect("code shown") + "user-select: all\">".len();
    body[start..].split('<').next().unwrap().to_owned()
}

#[tokio::test]
async fn chat_accounts_link_with_one_time_codes_and_decide_at_linked_assurance() {
    let mut s = setup("linked").await;
    let id: countersign_core::RequestId = s.request_id().await.parse().unwrap();
    let sink: Arc<dyn ActionSink> = s.daemon.sink.clone();
    let discord = ChannelName::new("discord");

    let p = s.browser.get("/link").await;
    assert_eq!(p.location.as_deref(), Some("/login?next=/link"));

    s.browser.login("oidc:idp%23bob", None, "/link").await;
    let csrf = s.browser.csrf().await;
    assert!(s.browser.get("/link").await.body.contains("Get a code"));
    assert_eq!(s.browser.post_form("/link", "csrf=nope").await.status, StatusCode::FORBIDDEN);
    let p = s.browser.post_form("/link", &format!("csrf={csrf}")).await;
    assert_eq!(p.status, StatusCode::OK);
    let code = link_code(&p.body);
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
