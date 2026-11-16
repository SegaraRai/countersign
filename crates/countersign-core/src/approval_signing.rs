//! Signed approvals: how a client knows an approval really comes from
//! countersign, even if TLS between them is terminated by someone else or
//! broken.
//!
//! countersign holds an Ed25519 signing key (`cssk_…`); clients pin its
//! public key (`ed25519:…`). With each submission a client sends a fresh nonce.
//! Every answer that says "approved" carries a signature over
//!
//! ```text
//! countersign-approval-v1
//! request=<request id>
//! client=<hex SHA-256 of the client's key>
//! invocation=<hex SHA-256 of what the client submitted>
//! nonce=<the client's nonce>
//! ```
//!
//! so it is only valid for that client (identified by its key, which both
//! sides know), that submission and that exact command. A forged, replayed
//! or redirected approval fails verification.
//!
//! Secrets and public keys look different on purpose, so one is not pasted
//! where the other belongs. The signing key is a token like the host key
//! (see [`crate::host_key`]): `cssk_`, base64url of 32 bytes, a 4-byte
//! checksum. The public key is `ed25519:` and the base64url of its 32 bytes.
//! Every place that takes a public key refuses a secret with its own error
//! ([`check_public_key`]).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::host_key;

/// Prefix of a signing key (secret).
pub const SECRET_PREFIX: &str = "cssk_";
/// Prefix of a public key (pinned by clients).
pub const PUBLIC_PREFIX: &str = "ed25519:";
const DOMAIN: &str = "countersign-approval-v1";

/// countersign's signing key. Its `Debug` output does not show the key.
pub struct ServerKey(SigningKey);

impl std::fmt::Debug for ServerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ServerKey").field(&self.public()).finish()
    }
}

impl ServerKey {
    /// The text of a new signing key from 32 random bytes (from a CSPRNG).
    #[must_use]
    pub fn generate(seed: &[u8; 32]) -> String {
        host_key::encode(SECRET_PREFIX, seed)
    }

    /// Parse a signing key's text (surrounding whitespace is ignored).
    pub fn parse(text: &str) -> Option<Self> {
        host_key::decode(SECRET_PREFIX, text.trim()).map(|seed| Self(SigningKey::from_bytes(&seed)))
    }

    /// The public key clients pin.
    #[must_use]
    pub fn public(&self) -> String {
        format!("{PUBLIC_PREFIX}{}", B64.encode(self.0.verifying_key().as_bytes()))
    }

    /// Sign an approval (base64url, no padding).
    #[must_use]
    pub fn sign(&self, a: &Approval<'_>) -> String {
        B64.encode(self.0.sign(&a.message()).to_bytes())
    }
}

fn decode_public(public: &str) -> Option<VerifyingKey> {
    let b64 = public.strip_prefix(PUBLIC_PREFIX)?;
    // 32 bytes are exactly 43 characters; decoding rejects other alphabets
    // and non-zero trailing bits, so each key has one spelling.
    if b64.len() != 43 {
        return None;
    }
    let bytes: [u8; 32] = B64.decode(b64).ok()?.try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

/// Whether `s` looks like one of countersign's secrets (`cs` + two letters
/// + `_`, e.g. a host key or a signing key).
#[must_use]
pub fn looks_secret(s: &str) -> bool {
    let b = s.trim().as_bytes();
    b.len() > 5 && b.starts_with(b"cs") && b[2].is_ascii_lowercase() && b[3].is_ascii_lowercase() && b[4] == b'_'
}

/// Check a value given as a public key. A secret gets its own message: it
/// must not be in a configuration that holds public keys, and has been
/// exposed wherever it was pasted.
pub fn check_public_key(public: &str) -> Result<(), String> {
    if looks_secret(public) {
        return Err("this is a secret key, not a public key; remove it from here and treat it as exposed \
                    (`countersign signing-key --public <file>` prints the public key)"
            .into());
    }
    match decode_public(public) {
        Some(_) => Ok(()),
        None => Err(format!("{public:?} is not a countersign public key ({PUBLIC_PREFIX}...)")),
    }
}

/// Whether `public` is a well-formed public key text.
#[must_use]
pub fn is_public_key(public: &str) -> bool {
    decode_public(public).is_some()
}

/// Whether `signature` is valid for `a` under one of `public_keys`.
#[must_use]
pub fn verify(public_keys: &[String], a: &Approval<'_>, signature: &str) -> bool {
    let Some(sig) = B64.decode(signature).ok().and_then(|b| <[u8; 64]>::try_from(b).ok()) else {
        return false;
    };
    let sig = Signature::from_bytes(&sig);
    let message = a.message();
    public_keys.iter().any(|k| decode_public(k).is_some_and(|vk| vk.verify_strict(&message, &sig).is_ok()))
}

/// What an approval signature covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Approval<'a> {
    pub request: &'a str,
    /// Hex SHA-256 of the client's key ([`crate::host_key::digest_hex`]).
    pub client: &'a str,
    /// [`invocation_digest`] of the submission.
    pub invocation: &'a str,
    pub nonce: &'a str,
}

impl Approval<'_> {
    fn message(&self) -> Vec<u8> {
        // No field can contain a newline: the request id is a UUID, the
        // digests are hex and the nonce is base64url.
        format!(
            "{DOMAIN}\nrequest={}\nclient={}\ninvocation={}\nnonce={}\n",
            self.request, self.client, self.invocation, self.nonce
        )
        .into_bytes()
    }
}

/// The hex SHA-256 of a sudo invocation as submitted: the JSON array
/// `[user, cwd, sudo_argv]` (`cwd` is `null` when unknown), where
/// `sudo_argv` is the whole `sudo` command line that approvers see. Client
/// and server compute it from the same raw values.
#[must_use]
pub fn invocation_digest(user: &str, cwd: Option<&str>, sudo_argv: &[String]) -> String {
    let json = serde_json::to_vec(&serde_json::json!([user, cwd, sudo_argv])).unwrap_or_default();
    hex(&Sha256::digest(json))
}

/// Whether `nonce` is acceptable: 22 to 86 base64url characters (16 to 64
/// bytes).
#[must_use]
pub fn is_nonce(nonce: &str) -> bool {
    (22..=86).contains(&nonce.len()) && nonce.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A nonce from 32 random bytes (from a CSPRNG).
#[must_use]
pub fn nonce(random: &[u8; 32]) -> String {
    B64.encode(random)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approval<'a>(invocation: &'a str, nonce: &'a str) -> Approval<'a> {
        Approval { request: "01a1e45e-662b-734f-950f-cd451a032aa3", client: "aa11", invocation, nonce }
    }

    #[test]
    fn signatures_verify_only_for_what_was_signed() {
        let text = ServerKey::generate(&[9; 32]);
        assert!(text.starts_with(SECRET_PREFIX));
        let key = ServerKey::parse(&format!("{text}\n")).unwrap();
        let public = vec![key.public()];
        assert!(is_public_key(&public[0]));
        assert!(!format!("{key:?}").contains(&text[SECRET_PREFIX.len()..]), "Debug hides the secret");

        let inv = invocation_digest("agent", None, &["apt".into(), "upgrade".into()]);
        let n = nonce(&[1; 32]);
        let sig = key.sign(&approval(&inv, &n));
        assert!(verify(&public, &approval(&inv, &n), &sig));

        let other_inv = invocation_digest("agent", None, &["apt".into(), "remove".into()]);
        assert!(!verify(&public, &approval(&other_inv, &n), &sig), "another command");
        assert!(!verify(&public, &approval(&inv, &nonce(&[2; 32])), &sig), "another nonce");
        let mut moved = approval(&inv, &n);
        moved.client = "bb22";
        assert!(!verify(&public, &moved, &sig), "another client");
        let other_key = ServerKey::parse(&ServerKey::generate(&[8; 32])).unwrap();
        assert!(!verify(&[other_key.public()], &approval(&inv, &n), &sig), "another server");
        assert!(verify(&[other_key.public(), key.public()], &approval(&inv, &n), &sig), "any pinned key");
        assert!(!verify(&public, &approval(&inv, &n), "garbage"));
        assert!(!verify(&public, &approval(&inv, &n), ""));
    }

    #[test]
    fn invocation_digest_separates_arguments() {
        let line = |s: &[&str]| s.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>();
        let a = invocation_digest("u", None, &line(&["sudo", "echo", "a b"]));
        assert_ne!(a, invocation_digest("u", None, &line(&["sudo", "echo", "a", "b"])));
        assert_ne!(a, invocation_digest("u", Some("/"), &line(&["sudo", "echo", "a b"])));
        assert_ne!(a, invocation_digest("v", None, &line(&["sudo", "echo", "a b"])));
        assert_ne!(a, invocation_digest("u", None, &line(&["sudo", "-u", "www-data", "echo", "a b"])));
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn key_texts_are_checked() {
        let text = ServerKey::generate(&[3; 32]);
        assert!(ServerKey::parse(&text[..text.len() - 1]).is_none());
        let public = ServerKey::parse(&text).unwrap().public();
        assert!(public.starts_with("ed25519:") && public.len() == 8 + 43, "{public}");
        assert!(ServerKey::parse(&public).is_none(), "a public key is no signing key");
        assert!(check_public_key(&public).is_ok());
        assert!(!is_public_key(&text));
        assert!(!is_public_key(&public.to_uppercase()));
        assert!(!is_public_key(&public[..public.len() - 1]));
        // Secrets pasted where a public key belongs are called out as such.
        for secret in [text.as_str(), &crate::host_key::from_random(&[1; 32])] {
            assert!(looks_secret(secret));
            assert!(check_public_key(secret).unwrap_err().contains("secret key"), "{secret}");
        }
        assert!(!looks_secret(&public));
        assert!(check_public_key("nope").unwrap_err().contains("not a countersign public key"));
        assert!(is_nonce(&nonce(&[0; 32])));
        assert!(!is_nonce("short"));
        assert!(!is_nonce(&"a\n".repeat(20)));
    }
}
