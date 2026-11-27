//! `OpenID Connect` [`Authenticator`] for the countersign web UI.
//!
//! Uses the authorization-code flow with PKCE and a nonce. Sign-in identities
//! are `oidc:<issuer>#<sub>`. A "fresh" login adds `prompt=login`; whether the
//! provider actually re-authenticated is judged by the caller from
//! [`VerifiedLogin::auth_time`], never assumed.
//!
//! A `groups` claim in the verified ID token (an array of strings) is passed
//! on as [`VerifiedLogin::groups`]; it counts only through `from_idp` mappings
//! in the configuration. Many providers send it only when a `groups` scope
//! is requested.
//!
//! The client secret is read from `client_secret_file` or, failing that, the
//! `COUNTERSIGN_OIDC_CLIENT_SECRET` environment variable. Without either, the
//! client is treated as public (PKCE only).

use std::path::PathBuf;

use async_trait::async_trait;
use openidconnect::core::{CoreAuthPrompt, CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse, reqwest,
};
use serde::{Deserialize, Serialize};
use tokio::sync::OnceCell;

use countersign_core::{AuthError, Authenticator, LoginStart, VerifiedLogin};

/// Environment variable consulted when `client_secret_file` is not set.
pub const SECRET_ENV: &str = "COUNTERSIGN_OIDC_CLIENT_SECRET";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// Issuer URL, exactly as the provider reports it.
    pub issuer: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret_file: Option<PathBuf>,
    /// Extra scopes besides `openid`.
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
}

fn default_scopes() -> Vec<String> {
    vec!["profile".into(), "email".into()]
}

type Client =
    CoreClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointMaybeSet, EndpointMaybeSet>;

/// What must survive between [`Authenticator::begin`] and
/// [`Authenticator::complete`].
#[derive(Debug, Serialize, Deserialize)]
struct Saved {
    csrf: String,
    nonce: String,
    pkce: String,
}

pub struct OidcAuthenticator {
    config: OidcConfig,
    secret: Option<String>,
    redirect_url: RedirectUrl,
    http: reqwest::Client,
    /// Discovered lazily so the daemon can start while the provider is down.
    client: OnceCell<Client>,
}

impl std::fmt::Debug for OidcAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcAuthenticator")
            .field("issuer", &self.config.issuer)
            .field("client_id", &self.config.client_id)
            .field("redirect_url", &self.redirect_url.as_str())
            .finish_non_exhaustive()
    }
}

fn other(e: impl std::fmt::Display) -> AuthError {
    AuthError::Provider(e.to_string())
}

impl OidcAuthenticator {
    /// `redirect_url` is the absolute URL of the web UI's callback route.
    pub fn new(config: OidcConfig, redirect_url: &str) -> Result<Self, AuthError> {
        IssuerUrl::new(config.issuer.clone()).map_err(|e| other(format!("invalid issuer: {e}")))?;
        let redirect_url =
            RedirectUrl::new(redirect_url.to_owned()).map_err(|e| other(format!("invalid redirect URL: {e}")))?;
        let secret = match &config.client_secret_file {
            Some(path) => Some(
                std::fs::read_to_string(path)
                    .map_err(|e| other(format!("cannot read {}: {e}", path.display())))?
                    .trim()
                    .to_owned(),
            ),
            None => std::env::var(SECRET_ENV).ok().filter(|s| !s.is_empty()),
        };
        let http = reqwest::ClientBuilder::new()
            // Following redirects would expose the daemon to SSRF.
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(other)?;
        Ok(Self { config, secret, redirect_url, http, client: OnceCell::new() })
    }

    async fn client(&self) -> Result<&Client, AuthError> {
        self.client
            .get_or_try_init(|| async {
                let issuer = IssuerUrl::new(self.config.issuer.clone()).map_err(other)?;
                let metadata = CoreProviderMetadata::discover_async(issuer, &self.http)
                    .await
                    .map_err(|e| other(format!("discovery failed: {e}")))?;
                Ok(CoreClient::from_provider_metadata(
                    metadata,
                    ClientId::new(self.config.client_id.clone()),
                    self.secret.clone().map(ClientSecret::new),
                )
                .set_redirect_uri(self.redirect_url.clone()))
            })
            .await
    }
}

/// Compare without exiting early on the first differing byte.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[async_trait]
impl Authenticator for OidcAuthenticator {
    async fn begin(&self, fresh: bool) -> Result<LoginStart, AuthError> {
        let client = self.client().await?;
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut req = client
            .authorize_url(CoreAuthenticationFlow::AuthorizationCode, CsrfToken::new_random, Nonce::new_random)
            .set_pkce_challenge(challenge);
        for s in &self.config.scopes {
            req = req.add_scope(Scope::new(s.clone()));
        }
        if fresh {
            req = req.add_prompt(CoreAuthPrompt::Login);
        }
        let (url, csrf, nonce) = req.url();
        let saved =
            Saved { csrf: csrf.secret().clone(), nonce: nonce.secret().clone(), pkce: verifier.secret().clone() };
        Ok(LoginStart { redirect_url: url.to_string(), state: serde_json::to_string(&saved).map_err(other)? })
    }

    async fn complete(&self, saved_state: &str, returned_state: &str, code: &str) -> Result<VerifiedLogin, AuthError> {
        let saved: Saved = serde_json::from_str(saved_state).map_err(|_| AuthError::StateMismatch)?;
        if !same(&saved.csrf, returned_state) {
            return Err(AuthError::StateMismatch);
        }
        let client = self.client().await?;
        let token = client
            .exchange_code(AuthorizationCode::new(code.to_owned()))
            .map_err(other)?
            .set_pkce_verifier(PkceCodeVerifier::new(saved.pkce))
            .request_async(&self.http)
            .await
            .map_err(|e| other(format!("token exchange failed: {e}")))?;
        let id_token = token.id_token().ok_or_else(|| other("no ID token in the token response"))?;
        let verifier = client.id_token_verifier();
        let claims = id_token.claims(&verifier, &Nonce::new(saved.nonce)).map_err(other)?;

        if let Some(expected) = claims.access_token_hash() {
            let actual = AccessTokenHash::from_token(
                token.access_token(),
                id_token.signing_alg().map_err(other)?,
                id_token.signing_key(&verifier).map_err(other)?,
            )
            .map_err(other)?;
            if actual != *expected {
                return Err(other("access token hash mismatch"));
            }
        }

        let auth_time = claims.auth_time().and_then(|t| jiff::Timestamp::from_second(t.timestamp()).ok());
        let display_name = claims
            .preferred_username()
            .map(|u| u.as_str().to_owned())
            .or_else(|| claims.email().map(|e| e.as_str().to_owned()));
        let provider = format!("oidc:{}", claims.issuer().as_str());
        // The signature and claims were verified above; read the one extra
        // claim from the same token.
        let groups = groups_claim(&id_token.to_string()).map(|g| (provider.clone(), g));
        Ok(VerifiedLogin {
            identity: format!("{provider}#{}", claims.subject().as_str()),
            auth_time,
            display_name,
            groups,
        })
    }
}

/// The `groups` claim of a compact JWT, if it is an array of strings. Only
/// call this on a token whose signature has been verified.
fn groups_claim(jwt: &str) -> Option<std::collections::BTreeSet<String>> {
    use base64::Engine as _;
    let payload = jwt.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let groups = value.get("groups")?.as_array()?;
    groups.iter().map(|g| g.as_str().map(str::to_owned)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> OidcAuthenticator {
        let config: OidcConfig = toml::from_str("issuer = \"https://id.example.com\"\nclient_id = \"abc\"\n").unwrap();
        OidcAuthenticator::new(config, "https://cs.example.com/auth/callback").unwrap()
    }

    #[test]
    fn config_defaults() {
        let a = auth();
        assert_eq!(a.config.scopes, ["profile", "email"]);
        assert!(format!("{a:?}").contains("id.example.com"), "debug output names the issuer");
    }

    #[test]
    fn rejects_bad_urls_and_unknown_keys() {
        let bad =
            OidcConfig { issuer: "not a url".into(), client_id: "x".into(), client_secret_file: None, scopes: vec![] };
        assert!(OidcAuthenticator::new(bad, "https://cs.example.com/cb").is_err());
        assert!(toml::from_str::<OidcConfig>("issuer='https://x'\nclient_id='y'\nclient_secret='z'\n").is_err());
    }

    #[test]
    fn missing_secret_file_is_an_error() {
        let c = OidcConfig {
            issuer: "https://id.example.com".into(),
            client_id: "x".into(),
            client_secret_file: Some("/definitely/not/here".into()),
            scopes: vec![],
        };
        assert!(OidcAuthenticator::new(c, "https://cs.example.com/cb").is_err());
    }

    #[tokio::test]
    async fn state_mismatch_is_detected_before_any_network_call() {
        let a = auth();
        let saved =
            serde_json::to_string(&Saved { csrf: "expected".into(), nonce: "n".into(), pkce: "p".into() }).unwrap();
        assert!(matches!(a.complete(&saved, "forged", "code").await, Err(AuthError::StateMismatch)));
        assert!(matches!(a.complete("garbage", "expected", "code").await, Err(AuthError::StateMismatch)));
        assert!(a.client.get().is_none(), "no discovery happened");
    }

    #[test]
    fn reads_groups_claim() {
        use base64::Engine as _;
        let enc = |v: serde_json::Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string());
        let jwt = |claims| format!("{}.{}.sig", enc(serde_json::json!({"alg": "RS256"})), enc(claims));
        let g = groups_claim(&jwt(serde_json::json!({"sub": "x", "groups": ["ops", "dev"]}))).unwrap();
        assert_eq!(g.into_iter().collect::<Vec<_>>(), ["dev", "ops"]);
        assert_eq!(groups_claim(&jwt(serde_json::json!({"sub": "x"}))), None);
        assert_eq!(groups_claim(&jwt(serde_json::json!({"groups": ["ok", 1]}))), None, "all or nothing");
        assert_eq!(groups_claim("garbage"), None);
    }

    #[test]
    fn constant_time_compare() {
        assert!(same("abc", "abc"));
        assert!(!same("abc", "abd"));
        assert!(!same("abc", "ab"));
    }
}
