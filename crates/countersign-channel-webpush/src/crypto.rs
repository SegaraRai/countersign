//! RFC 8291 (`aes128gcm`) message encryption for Web Push.

use aes_gcm::aead::{Aead as _, KeyInit as _};
use aes_gcm::{Aes128Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use p256::elliptic_curve::sec1::ToSec1Point as _;
use p256::{PublicKey, SecretKey};
use sha2::Sha256;

/// RFC 8188 record size (4096 bytes, fits all countersign push payloads in one record).
const RECORD_SIZE: u32 = 4096;
/// Maximum plaintext size that fits in one 4096-byte record (minus 1-byte delimiter + 16-byte GCM tag).
const MAX_PLAINTEXT: usize = (RECORD_SIZE as usize) - 17;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid subscriber p256dh public key")]
    InvalidPublicKey,
    #[error("invalid subscriber auth secret")]
    InvalidAuthSecret,
    #[error("push payload exceeds single-record limit")]
    PayloadTooLarge,
    #[error("encryption failed")]
    Encrypt,
}

/// Encrypt `plaintext` for a browser subscription (`p256dh` and `auth` as base64url).
/// Returns the complete RFC 8188 `aes128gcm` HTTP request body.
pub fn encrypt(ua_p256dh_b64: &str, ua_auth_b64: &str, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let ua_pub_bytes = decode_b64url(ua_p256dh_b64).ok_or(CryptoError::InvalidPublicKey)?;
    let ua_pub = PublicKey::from_sec1_bytes(&ua_pub_bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
    let ua_pub_uncompressed = ua_pub.to_sec1_point(false);

    let auth_secret = decode_b64url(ua_auth_b64).ok_or(CryptoError::InvalidAuthSecret)?;
    if auth_secret.len() != 16 {
        return Err(CryptoError::InvalidAuthSecret);
    }

    let as_secret = random_p256_secret()?;
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt).map_err(|_| CryptoError::Encrypt)?;

    encrypt_with_ephemeral(ua_pub_uncompressed.as_bytes(), &ua_pub, &auth_secret, &as_secret, &salt, plaintext)
}

pub(crate) fn encrypt_with_ephemeral(
    ua_pub_bytes: &[u8],
    ua_pub: &PublicKey,
    auth_secret: &[u8],
    as_secret: &SecretKey,
    salt: &[u8; 16],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(CryptoError::PayloadTooLarge);
    }

    let as_pub_point = as_secret.public_key().to_sec1_point(false);
    let as_pub_bytes = as_pub_point.as_bytes(); // 65 bytes
    debug_assert_eq!(as_pub_bytes.len(), 65);
    debug_assert_eq!(ua_pub_bytes.len(), 65);

    // 1. ECDH shared secret
    let shared = p256::ecdh::diffie_hellman(as_secret.to_nonzero_scalar(), ua_pub.as_affine());

    // 2. IKM = HKDF(salt = auth_secret, ikm = shared, info = "WebPush: info\0" || ua_pub || as_pub, L = 32)
    let mut key_info = Vec::with_capacity(14 + 65 + 65);
    key_info.extend_from_slice(b"WebPush: info\0");
    key_info.extend_from_slice(ua_pub_bytes);
    key_info.extend_from_slice(as_pub_bytes);

    let hk_key = Hkdf::<Sha256>::new(Some(auth_secret), shared.raw_secret_bytes());
    let mut ikm = [0u8; 32];
    hk_key.expand(&key_info, &mut ikm).map_err(|_| CryptoError::Encrypt)?;

    // 3. CEK (16 bytes) and NONCE (12 bytes) from HKDF(salt, IKM)
    let hk_content = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut cek = [0u8; 16];
    let mut nonce = [0u8; 12];
    hk_content.expand(b"Content-Encoding: aes128gcm\0", &mut cek).map_err(|_| CryptoError::Encrypt)?;
    hk_content.expand(b"Content-Encoding: nonce\0", &mut nonce).map_err(|_| CryptoError::Encrypt)?;

    // 4. Encrypt plaintext || 0x02 (final record delimiter)
    let mut padded = Vec::with_capacity(plaintext.len() + 1);
    padded.extend_from_slice(plaintext);
    padded.push(0x02);

    let cipher = Aes128Gcm::new_from_slice(&cek).map_err(|_| CryptoError::Encrypt)?;
    let ciphertext = cipher.encrypt(&Nonce::from(nonce), padded.as_ref()).map_err(|_| CryptoError::Encrypt)?;

    // 5. RFC 8188 header: salt(16) || rs(4 BE) || idlen(1) || keyid(65) || ciphertext
    let mut out = Vec::with_capacity(16 + 4 + 1 + 65 + ciphertext.len());
    out.extend_from_slice(salt);
    out.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    out.push(65);
    out.extend_from_slice(as_pub_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn random_p256_secret() -> Result<SecretKey, CryptoError> {
    for _ in 0..16 {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| CryptoError::Encrypt)?;
        if let Ok(sk) = SecretKey::from_slice(&bytes) {
            return Ok(sk);
        }
    }
    Err(CryptoError::Encrypt)
}

fn decode_b64url(s: &str) -> Option<Vec<u8>> {
    // Accept both unpadded and padded base64url strings from browsers.
    URL_SAFE_NO_PAD.decode(s.trim().trim_end_matches('=')).ok()
}
