//! VAPID (RFC 8292) P-256 keypair and ES256 JWT generation.
//!
//! Secret key format: `csvk_<43-char base64url(32 bytes)><6-char base64url(sha256[..4])>`
//! (same token + checksum convention as `cshk_` and `cssk_`).

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::Timestamp;
use p256::SecretKey;
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use p256::elliptic_curve::sec1::ToSec1Point as _;
use serde_json::json;
use sha2::{Digest as _, Sha256};

const PREFIX: &str = "csvk_";
const BODY_LEN: usize = 43; // 32 bytes base64url without padding
const CHECKSUM_LEN: usize = 6; // 4 bytes base64url without padding
const TOTAL_LEN: usize = PREFIX.len() + BODY_LEN + CHECKSUM_LEN;

/// A VAPID P-256 signing key.
#[derive(Clone)]
pub struct VapidKey {
    secret: SecretKey,
    public_b64: String,
}

impl fmt::Debug for VapidKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VapidKey").field("public", &self.public_b64).finish_non_exhaustive()
    }
}

impl VapidKey {
    /// Generate a fresh random VAPID P-256 key.
    pub fn generate() -> Result<Self, String> {
        for _ in 0..16 {
            let mut bytes = [0u8; 32];
            getrandom::getrandom(&mut bytes).map_err(|e| format!("random bytes: {e}"))?;
            if let Ok(secret) = SecretKey::from_slice(&bytes) {
                return Ok(Self::from_secret(secret));
            }
        }
        Err("could not generate a valid P-256 scalar".to_owned())
    }

    fn from_secret(secret: SecretKey) -> Self {
        let point = secret.public_key().to_sec1_point(false);
        let public_b64 = URL_SAFE_NO_PAD.encode(point.as_bytes());
        Self { secret, public_b64 }
    }

    /// Parse a `csvk_…` key string (ignoring surrounding whitespace).
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.len() != TOTAL_LEN || !s.starts_with(PREFIX) {
            return None;
        }
        let (payload, checksum) = s.split_at(PREFIX.len() + BODY_LEN);
        let expected = URL_SAFE_NO_PAD.encode(&Sha256::digest(payload.as_bytes())[..4]);
        if checksum != expected {
            return None;
        }
        let raw = URL_SAFE_NO_PAD.decode(&payload[PREFIX.len()..]).ok()?;
        let secret = SecretKey::from_slice(&raw).ok()?;
        Some(Self::from_secret(secret))
    }

    /// Encode as a `csvk_…` secret token for storing in `vapid_key_file`.
    pub fn to_token(&self) -> String {
        let raw = self.secret.to_bytes();
        let payload = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(raw));
        let checksum = URL_SAFE_NO_PAD.encode(&Sha256::digest(payload.as_bytes())[..4]);
        format!("{payload}{checksum}")
    }

    /// Uncompressed 65-byte P-256 public key as base64url (no padding).
    /// Passed to browsers as `applicationServerKey` and to Push Services as `k=`.
    pub fn public_key_base64url(&self) -> &str {
        &self.public_b64
    }

    /// Build the RFC 8292 `Authorization: vapid t=<jwt>, k=<pub>` header value.
    pub fn authorization_header(&self, audience: &str, subject: &str, now: Timestamp) -> String {
        let exp = now.as_second().saturating_add(12 * 3600);
        let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
        let claims_json = json!({
            "aud": audience,
            "exp": exp,
            "sub": subject,
        })
        .to_string();
        let claims = URL_SAFE_NO_PAD.encode(claims_json.as_bytes());
        let signing_input = format!("{header}.{claims}");
        let signing_key = SigningKey::from(&self.secret);
        let sig: Signature = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("vapid t={signing_input}.{sig_b64}, k={}", self.public_b64)
    }
}

/// Extract `scheme://host[:port]` from an HTTPS push endpoint URL for VAPID `aud`.
pub fn origin_of(endpoint: &str) -> Option<String> {
    let rest = endpoint.strip_prefix("https://")?;
    let authority = rest.split('/').next()?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    Some(format!("https://{authority}"))
}
