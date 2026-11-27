//! Web Push (RFC 8291 + RFC 8292 VAPID) channel for countersign.
//!
//! Unlike broadcast chat channels, Web Push targets only the active persons who
//! are eligible to decide an approval or answer a question, delivering directly
//! to their subscribed browsers (including installed PWAs on iOS/Android).
//!
//! Clicking a notification opens the request directly in the web UI, where
//! `web` or `fresh-auth` assurance is enforced.
//!
//! ```toml
//! [channel.webpush]
//! type = "webpush"
//! vapid_key_file = "/etc/countersign/vapid.key"  # created with `countersign vapid-key`
//! subject = "mailto:ops@example.com"             # optional; defaults to server.public_url
//! details = false                                # default false: safe title only on lock screens
//! ```

pub mod crypto;
pub mod vapid;

use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use jiff::Timestamp;
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::json;

use countersign_core::present::{Audience, Presentation};
use countersign_core::{
    ActorId, Channel, ChannelCaps, ChannelError, ChannelName, DomainEvent, Item, MessageRef, Notification, Store,
};

pub use crate::vapid::VapidKey;

const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_TTL_SECS: u64 = 300;

/// Resolves which active persons are eligible to receive a notification for `item`.
pub type RecipientResolver =
    Arc<dyn Fn(Item<'_>, Timestamp) -> Pin<Box<dyn Future<Output = BTreeSet<ActorId>> + Send>> + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebPushConfig {
    /// Path to the `csvk_…` VAPID private key file (created with `countersign vapid-key`).
    pub vapid_key_file: PathBuf,
    /// VAPID `sub` claim (`mailto:...` or `https://...`). Defaults to `server.public_url`.
    #[serde(default)]
    pub subject: Option<String>,
    /// Show headline and grant summary in the push notification body.
    /// Sensitive approvals and confidential questions always use the safe title only.
    #[serde(default)]
    pub details: bool,
}

pub struct WebPushChannel {
    name: ChannelName,
    config: WebPushConfig,
    subject: String,
    vapid: VapidKey,
    store: Arc<dyn Store>,
    recipients: RecipientResolver,
    http: reqwest::Client,
}

impl fmt::Debug for WebPushChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebPushChannel")
            .field("name", &self.name)
            .field("subject", &self.subject)
            .field("details", &self.config.details)
            .finish_non_exhaustive()
    }
}

impl WebPushChannel {
    pub fn new(
        name: ChannelName,
        config: WebPushConfig,
        vapid: VapidKey,
        default_subject: &str,
        store: Arc<dyn Store>,
        recipients: RecipientResolver,
    ) -> Result<Self, ChannelError> {
        let subject = config.subject.clone().unwrap_or_else(|| default_subject.to_owned());
        if !(subject.starts_with("mailto:") || subject.starts_with("https://")) {
            return Err(ChannelError::Other("webpush subject must start with mailto: or https://".into()));
        }
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| ChannelError::Other(Box::new(e)))?;
        Ok(Self { name, config, subject, vapid, store, recipients, http })
    }

    pub fn vapid_public_key(&self) -> &str {
        self.vapid.public_key_base64url()
    }

    fn build_payload(&self, n: Notification<'_>) -> Vec<u8> {
        let (title, body) = if n.item.withheld() || !self.config.details {
            (n.item.safe_title(), "Open countersign to review.".to_owned())
        } else {
            let p = match n.item {
                Item::Approval(r) => Presentation::approval(r, Audience::Chat),
                Item::Question(q) => Presentation::question(q, Audience::Chat),
            };
            (p.headline, p.grant)
        };
        json!({
            "title": title,
            "body": body,
            "url": n.web_url,
            "tag": format!("countersign-{}", n.item.id()),
            "kind": n.item.kind(),
        })
        .to_string()
        .into_bytes()
    }
}

#[async_trait]
impl Channel for WebPushChannel {
    fn name(&self) -> &ChannelName {
        &self.name
    }

    fn capabilities(&self) -> ChannelCaps {
        ChannelCaps { update: false, interactive: false, max_assurance: None }
    }

    async fn notify(&self, n: Notification<'_>) -> Result<Option<MessageRef>, ChannelError> {
        // Only push when a new approval or question opens; terminal states are
        // visible when opening the web UI and would otherwise cause double-pings.
        if !matches!(n.event, DomainEvent::Requested { .. }) {
            return Ok(None);
        }
        let now = Timestamp::now();
        let eligible = (self.recipients)(n.item, now).await;
        if eligible.is_empty() {
            return Ok(None);
        }
        let subs = self
            .store
            .list_push_subscriptions(None)
            .await
            .map_err(|e| ChannelError::Unavailable(format!("reading push subscriptions: {e}")))?;
        let targets: Vec<_> = subs.into_iter().filter(|s| eligible.contains(&s.person)).collect();
        if targets.is_empty() {
            return Ok(None);
        }

        let payload = self.build_payload(n);
        let ttl = match n.item {
            Item::Approval(r) => (r.pending_until.as_second() - now.as_second()).clamp(60, 86400).cast_unsigned(),
            Item::Question(q) => (q.pending_until.as_second() - now.as_second()).clamp(60, 86400).cast_unsigned(),
        };
        let ttl = if ttl == 0 { DEFAULT_TTL_SECS } else { ttl };

        let mut any_retryable = false;
        let mut any_sent = false;

        for sub in targets {
            let Some(aud) = vapid::origin_of(&sub.endpoint) else {
                tracing::warn!(channel = %self.name, person = %sub.person, "ignoring non-HTTPS or invalid push endpoint");
                continue;
            };
            let encrypted = match crypto::encrypt(&sub.p256dh, &sub.auth, &payload) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(channel = %self.name, person = %sub.person, error = %e, "invalid push subscription keys");
                    continue;
                }
            };
            let auth_header = self.vapid.authorization_header(&aud, &self.subject, now);
            let resp = self
                .http
                .post(&sub.endpoint)
                .header("Authorization", auth_header)
                .header("Content-Encoding", "aes128gcm")
                .header("Content-Type", "application/octet-stream")
                .header("TTL", ttl.to_string())
                .header("Urgency", "high")
                .body(encrypted)
                .send()
                .await;

            match resp {
                Ok(r) if r.status().is_success() => {
                    any_sent = true;
                }
                Ok(r) if r.status() == StatusCode::GONE || r.status() == StatusCode::NOT_FOUND => {
                    tracing::info!(channel = %self.name, person = %sub.person, "removing expired Web Push subscription");
                    let _ = self.store.delete_push_subscription(&sub.endpoint).await;
                }
                Ok(r) if r.status() == StatusCode::TOO_MANY_REQUESTS || r.status().is_server_error() => {
                    tracing::warn!(channel = %self.name, person = %sub.person, status = %r.status(), "Web Push temporary failure");
                    any_retryable = true;
                }
                Ok(r) => {
                    tracing::warn!(channel = %self.name, person = %sub.person, status = %r.status(), "Web Push rejected");
                }
                Err(e) => {
                    tracing::warn!(channel = %self.name, person = %sub.person, error = %e, "Web Push network error");
                    any_retryable = true;
                }
            }
        }

        if !any_sent && any_retryable {
            return Err(ChannelError::Unavailable("Web Push delivery failed temporarily".to_owned()));
        }
        Ok(None)
    }

    async fn update(&self, _msg: &MessageRef, _n: Notification<'_>) -> Result<(), ChannelError> {
        Err(ChannelError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use aes_gcm::aead::{Aead as _, KeyInit as _};
    use aes_gcm::{Aes128Gcm, Nonce};
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use hkdf::Hkdf;
    use p256::elliptic_curve::sec1::ToSec1Point as _;
    use p256::{PublicKey, SecretKey};
    use sha2::Sha256;

    use crate::crypto::encrypt;
    use crate::vapid::{VapidKey, origin_of};

    #[test]
    fn vapid_key_roundtrip_and_jwt() {
        let key = VapidKey::generate().unwrap();
        let token = key.to_token();
        assert!(token.starts_with("csvk_"));
        let parsed = VapidKey::parse(&token).unwrap();
        assert_eq!(parsed.public_key_base64url(), key.public_key_base64url());

        // Corrupted checksum is rejected.
        let mut bad = token.clone();
        bad.pop();
        bad.push(if token.ends_with('A') { 'B' } else { 'A' });
        assert!(VapidKey::parse(&bad).is_none());

        let header = key.authorization_header(
            "https://fcm.googleapis.com",
            "mailto:ops@example.com",
            jiff::Timestamp::from_second(1_700_000_000).unwrap(),
        );
        assert!(header.starts_with("vapid t="));
        assert!(header.contains(&format!(", k={}", key.public_key_base64url())));
    }

    #[test]
    fn origin_extraction() {
        assert_eq!(origin_of("https://fcm.googleapis.com/fcm/send/abc").as_deref(), Some("https://fcm.googleapis.com"));
        assert_eq!(origin_of("http://fcm.googleapis.com/send"), None);
        assert_eq!(origin_of("https://user@fcm.googleapis.com/send"), None);
    }

    #[test]
    fn rfc8291_encrypt_decrypt_roundtrip() {
        let ua_secret = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let ua_pub_bytes = ua_secret.public_key().to_sec1_point(false);
        let auth_secret = [42u8; 16];

        let plaintext = br#"{"title":"agent wants root on web-1","url":"https://cs.example/requests/1"}"#;
        let body =
            encrypt(&URL_SAFE_NO_PAD.encode(ua_pub_bytes.as_bytes()), &URL_SAFE_NO_PAD.encode(auth_secret), plaintext)
                .unwrap();

        // Parse RFC 8188 header.
        let salt = &body[0..16];
        let rs = u32::from_be_bytes(body[16..20].try_into().unwrap());
        assert_eq!(rs, 4096);
        assert_eq!(body[20], 65);
        let as_pub_bytes = &body[21..86];
        let ciphertext = &body[86..];

        let as_pub = PublicKey::from_sec1_bytes(as_pub_bytes).unwrap();
        let shared = p256::ecdh::diffie_hellman(ua_secret.to_nonzero_scalar(), as_pub.as_affine());

        let mut key_info = Vec::new();
        key_info.extend_from_slice(b"WebPush: info\0");
        key_info.extend_from_slice(ua_pub_bytes.as_bytes());
        key_info.extend_from_slice(as_pub_bytes);
        let hk_key = Hkdf::<Sha256>::new(Some(&auth_secret), shared.raw_secret_bytes());
        let mut ikm = [0u8; 32];
        hk_key.expand(&key_info, &mut ikm).unwrap();

        let hk_content = Hkdf::<Sha256>::new(Some(salt), &ikm);
        let mut cek = [0u8; 16];
        let mut nonce = [0u8; 12];
        hk_content.expand(b"Content-Encoding: aes128gcm\0", &mut cek).unwrap();
        hk_content.expand(b"Content-Encoding: nonce\0", &mut nonce).unwrap();

        let cipher = Aes128Gcm::new_from_slice(&cek).unwrap();
        let decrypted = cipher.decrypt(&Nonce::from(nonce), ciphertext).unwrap();
        assert_eq!(decrypted.last(), Some(&0x02));
        assert_eq!(&decrypted[..decrypted.len() - 1], plaintext);
    }
}
