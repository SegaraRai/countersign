//! CI OIDC JWT verification (RS256 and ES256 via JWKS).
//!
//! Used by `[[client]]` entries with `auth = { oidc = { issuer, audience, ... } }`
//! so CI workflows (GitHub Actions, GitLab CI, etc.) can authenticate to the
//! intake API without static secrets.

use std::collections::BTreeMap;
use std::sync::RwLock;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::Timestamp;
use ring::signature::{ECDSA_P256_SHA256_FIXED, RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents, UnparsedPublicKey};
use serde::Deserialize;
use serde_json::Value;

use crate::config::OidcClientAuth;

const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const JWKS_TTL_SECS: i64 = 600;
const CLOCK_SKEW_SECS: i64 = 30;

/// Verified identity and claims extracted from a CI OIDC token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOidc {
    /// The token's `sub` claim.
    pub subject: String,
    /// Optional initiator recognition identity (e.g. `github:1234567`).
    pub initiator: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct JwkSet {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Jwk {
    pub kty: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default, rename = "use")]
    pub key_use: Option<String>,
    // RSA
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
    // EC P-256
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Discovery {
    jwks_uri: String,
}

#[derive(Debug, Clone)]
struct CachedJwks {
    jwks: JwkSet,
    expires_at: i64,
}

/// Caches JWKS documents per issuer and verifies incoming CI OIDC JWTs.
pub struct OidcVerifier {
    http: reqwest::Client,
    cache: RwLock<BTreeMap<String, CachedJwks>>,
}

impl std::fmt::Debug for OidcVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcVerifier").finish_non_exhaustive()
    }
}

impl Default for OidcVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl OidcVerifier {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("building OIDC HTTP client");
        Self { http, cache: RwLock::new(BTreeMap::new()) }
    }

    /// Peek the unverified `iss` claim from a JWT so we only fetch JWKS for
    /// configured issuers. Returns `None` if `token` is not a 3-part JWT.
    pub fn peek_issuer(token: &str) -> Option<String> {
        let mut parts = token.split('.');
        let _header = parts.next()?;
        let payload = parts.next()?;
        let _sig = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        let bytes = decode_b64url(payload)?;
        let claims: Value = serde_json::from_slice(&bytes).ok()?;
        claims.get("iss")?.as_str().map(str::to_owned)
    }

    /// Cryptographically verify `token` against `config` at `now`.
    pub async fn verify(&self, token: &str, config: &OidcClientAuth, now: Timestamp) -> Result<VerifiedOidc, String> {
        let jwks = self.fetch_jwks(config, now).await?;
        verify_with_jwks(token, config, &jwks, now)
    }

    async fn fetch_jwks(&self, config: &OidcClientAuth, now: Timestamp) -> Result<JwkSet, String> {
        let cache_key = config.jwks_uri.as_deref().unwrap_or(&config.issuer);
        if let Some(entry) =
            self.cache.read().unwrap_or_else(std::sync::PoisonError::into_inner).get(cache_key).cloned()
            && now.as_second() < entry.expires_at
        {
            return Ok(entry.jwks);
        }

        let jwks_uri = if let Some(u) = &config.jwks_uri {
            u.clone()
        } else {
            let disc_url = format!("{}/.well-known/openid-configuration", config.issuer.trim_end_matches('/'));
            let resp = self
                .http
                .get(&disc_url)
                .send()
                .await
                .map_err(|e| format!("OIDC discovery failed: {}", e.without_url()))?;
            if !resp.status().is_success() {
                return Err(format!("OIDC discovery returned {}", resp.status()));
            }
            let disc: Discovery = resp.json().await.map_err(|e| format!("invalid OIDC discovery: {e}"))?;
            if !countersign_core::url::is_secure(&disc.jwks_uri) {
                return Err("OIDC discovery returned non-HTTPS jwks_uri".to_owned());
            }
            disc.jwks_uri
        };

        let resp =
            self.http.get(&jwks_uri).send().await.map_err(|e| format!("fetching JWKS failed: {}", e.without_url()))?;
        if !resp.status().is_success() {
            return Err(format!("JWKS endpoint returned {}", resp.status()));
        }
        let jwks: JwkSet = resp.json().await.map_err(|e| format!("invalid JWKS: {e}"))?;
        let expires_at = now.as_second().saturating_add(JWKS_TTL_SECS);
        self.cache
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(cache_key.to_owned(), CachedJwks { jwks: jwks.clone(), expires_at });
        Ok(jwks)
    }
}

pub(crate) fn verify_with_jwks(
    token: &str,
    config: &OidcClientAuth,
    jwks: &JwkSet,
    now: Timestamp,
) -> Result<VerifiedOidc, String> {
    let mut parts = token.split('.');
    let header_b64 = parts.next().ok_or("malformed JWT")?;
    let payload_b64 = parts.next().ok_or("malformed JWT")?;
    let sig_b64 = parts.next().ok_or("malformed JWT")?;
    if parts.next().is_some() {
        return Err("malformed JWT".to_owned());
    }

    let header: JwtHeader = serde_json::from_slice(&decode_b64url(header_b64).ok_or("invalid JWT header encoding")?)
        .map_err(|_| "invalid JWT header JSON")?;
    if header.alg != "RS256" && header.alg != "ES256" {
        return Err(format!("unsupported JWT algorithm {:?}", header.alg));
    }

    let sig = decode_b64url(sig_b64).ok_or("invalid JWT signature encoding")?;
    let signing_input = format!("{header_b64}.{payload_b64}");

    let verified = jwks.keys.iter().any(|k| {
        if k.key_use.as_deref().is_some_and(|u| u != "sig") {
            return false;
        }
        if header.kid.is_some() && k.kid.is_some() && k.kid != header.kid {
            return false;
        }
        verify_jwk_signature(k, &header.alg, signing_input.as_bytes(), &sig)
    });
    if !verified {
        return Err("JWT signature verification failed".to_owned());
    }

    let claims: Value = serde_json::from_slice(&decode_b64url(payload_b64).ok_or("invalid JWT payload encoding")?)
        .map_err(|_| "invalid JWT payload JSON")?;

    let iss = claims.get("iss").and_then(Value::as_str).ok_or("missing iss claim")?;
    if iss != config.issuer {
        return Err("issuer mismatch".to_owned());
    }

    if !audience_matches(claims.get("aud"), &config.audience) {
        return Err("audience mismatch".to_owned());
    }

    let now_s = now.as_second();
    let exp = claims.get("exp").and_then(Value::as_i64).ok_or("missing exp claim")?;
    if now_s >= exp.saturating_add(CLOCK_SKEW_SECS) {
        return Err("token expired".to_owned());
    }
    if let Some(nbf) = claims.get("nbf").and_then(Value::as_i64)
        && now_s.saturating_add(CLOCK_SKEW_SECS) < nbf
    {
        return Err("token not yet valid".to_owned());
    }

    let subject =
        claims.get("sub").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or("missing sub claim")?.to_owned();

    for (claim_name, pattern) in &config.claims {
        let Some(val) = claim_as_string(claims.get(claim_name)) else {
            return Err(format!("missing required claim {claim_name}"));
        };
        if !countersign_core::glob::matches(pattern, &val) {
            return Err(format!("claim {claim_name} did not match policy"));
        }
    }

    let initiator = config.initiator_claim.as_deref().and_then(|c| {
        let val = claim_as_string(claims.get(c))?;
        let scheme = config.initiator_scheme.as_deref().unwrap_or("oidc");
        let id = format!("{scheme}:{val}");
        countersign_core::actor::is_identity(&id).then_some(id)
    });

    Ok(VerifiedOidc { subject, initiator })
}

fn verify_jwk_signature(k: &Jwk, alg: &str, signing_input: &[u8], sig: &[u8]) -> bool {
    match (alg, k.kty.as_str()) {
        ("RS256", "RSA") => {
            let (Some(n_b64), Some(e_b64)) = (&k.n, &k.e) else { return false };
            let (Some(n), Some(e)) = (decode_b64url(n_b64), decode_b64url(e_b64)) else { return false };
            RsaPublicKeyComponents { n, e }.verify(&RSA_PKCS1_2048_8192_SHA256, signing_input, sig).is_ok()
        }
        ("ES256", "EC") if k.crv.as_deref() == Some("P-256") => {
            let (Some(x_b64), Some(y_b64)) = (&k.x, &k.y) else { return false };
            let (Some(x), Some(y)) = (decode_b64url(x_b64), decode_b64url(y_b64)) else { return false };
            if x.len() != 32 || y.len() != 32 {
                return false;
            }
            let mut pub_bytes = Vec::with_capacity(65);
            pub_bytes.push(0x04);
            pub_bytes.extend_from_slice(&x);
            pub_bytes.extend_from_slice(&y);
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &pub_bytes).verify(signing_input, sig).is_ok()
        }
        _ => false,
    }
}

fn audience_matches(aud: Option<&Value>, expected: &str) -> bool {
    match aud {
        Some(Value::String(s)) => s == expected,
        Some(Value::Array(arr)) => arr.iter().any(|v| v.as_str() == Some(expected)),
        _ => false,
    }
}

fn claim_as_string(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn decode_b64url(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.trim().trim_end_matches('=')).ok()
}

#[cfg(test)]
mod tests {
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
    use serde_json::json;

    use super::*;

    fn sign_es256(kp: &EcdsaKeyPair, header: &Value, claims: &Value) -> String {
        let h = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let p = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let input = format!("{h}.{p}");
        let rng = SystemRandom::new();
        let sig = kp.sign(&rng, input.as_bytes()).unwrap();
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
    }

    fn jwk_for(kp: &EcdsaKeyPair, kid: &str) -> JwkSet {
        let pub_bytes = kp.public_key().as_ref();
        assert_eq!(pub_bytes.len(), 65);
        assert_eq!(pub_bytes[0], 0x04);
        JwkSet {
            keys: vec![Jwk {
                kty: "EC".into(),
                kid: Some(kid.into()),
                key_use: Some("sig".into()),
                n: None,
                e: None,
                crv: Some("P-256".into()),
                x: Some(URL_SAFE_NO_PAD.encode(&pub_bytes[1..33])),
                y: Some(URL_SAFE_NO_PAD.encode(&pub_bytes[33..65])),
            }],
        }
    }

    #[test]
    fn verifies_es256_jwt_claims_and_initiator() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        let jwks = jwk_for(&kp, "k1");

        let now = Timestamp::from_second(1_700_000_000).unwrap();
        let cfg = OidcClientAuth {
            issuer: "https://token.actions.githubusercontent.com".into(),
            audience: "countersign".into(),
            claims: BTreeMap::from([("repository".into(), "org/*".into()), ("environment".into(), "prod".into())]),
            initiator_claim: Some("actor_id".into()),
            initiator_scheme: Some("github".into()),
            jwks_uri: None,
        };

        let header = json!({ "alg": "ES256", "kid": "k1" });
        let claims = json!({
            "iss": "https://token.actions.githubusercontent.com",
            "aud": "countersign",
            "sub": "repo:org/app:environment:prod",
            "exp": 1_700_000_300,
            "repository": "org/app",
            "environment": "prod",
            "actor_id": "1234567"
        });
        let token = sign_es256(&kp, &header, &claims);
        assert_eq!(OidcVerifier::peek_issuer(&token).as_deref(), Some("https://token.actions.githubusercontent.com"));

        let verified = verify_with_jwks(&token, &cfg, &jwks, now).unwrap();
        assert_eq!(verified.subject, "repo:org/app:environment:prod");
        assert_eq!(verified.initiator.as_deref(), Some("github:1234567"));

        // Wrong audience is rejected.
        let bad_aud = sign_es256(
            &kp,
            &header,
            &json!({
                "iss": "https://token.actions.githubusercontent.com",
                "aud": "other",
                "sub": "repo:org/app:environment:prod",
                "exp": 1_700_000_300,
                "repository": "org/app",
                "environment": "prod",
            }),
        );
        assert!(verify_with_jwks(&bad_aud, &cfg, &jwks, now).is_err());

        // Expired token is rejected.
        let expired = sign_es256(
            &kp,
            &header,
            &json!({
                "iss": "https://token.actions.githubusercontent.com",
                "aud": "countersign",
                "sub": "repo:org/app:environment:prod",
                "exp": 1_699_999_000,
                "repository": "org/app",
                "environment": "prod",
            }),
        );
        assert!(verify_with_jwks(&expired, &cfg, &jwks, now).is_err());

        // Non-matching claim glob is rejected.
        let bad_repo = sign_es256(
            &kp,
            &header,
            &json!({
                "iss": "https://token.actions.githubusercontent.com",
                "aud": "countersign",
                "sub": "repo:evil/app:environment:prod",
                "exp": 1_700_000_300,
                "repository": "evil/app",
                "environment": "prod",
            }),
        );
        assert!(verify_with_jwks(&bad_repo, &cfg, &jwks, now).is_err());
    }
}
