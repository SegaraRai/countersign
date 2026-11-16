//! Host keys: how a target host authenticates to the intake API.
//!
//! A key is `cshk_<43 chars><6 chars>`: the base64url (no padding) of 32
//! random bytes, then the base64url of the first 4 bytes of SHA-256 over
//! everything before it (`cshk_` and the random part). The checksum catches
//! typos and hand-made keys; it is not a secret.
//!
//! countersign stores only the SHA-256 of a key. A single SHA-256 is only safe
//! for high-entropy keys, so the server accepts nothing but this format. That
//! blocks accidents (short keys, reused passwords, keys from other systems),
//! not someone who deliberately builds a weak key in this format.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use sha2::{Digest as _, Sha256};

pub const PREFIX: &str = "cshk_";
const RANDOM_LEN: usize = 43;
const CHECK_LEN: usize = 6;
/// Length of a well-formed key.
pub const LEN: usize = PREFIX.len() + RANDOM_LEN + CHECK_LEN;

/// A key from 32 random bytes (which must come from a CSPRNG).
#[must_use]
pub fn from_random(bytes: &[u8; 32]) -> String {
    let mut key = format!("{PREFIX}{}", B64.encode(bytes));
    let check = checksum(&key);
    key.push_str(&check);
    key
}

fn checksum(body: &str) -> String {
    B64.encode(&Sha256::digest(body.as_bytes())[..4])
}

/// Whether `key` has the prefix, length, alphabet and checksum of a key made
/// by [`from_random`]. Surrounding whitespace is not accepted here.
#[must_use]
pub fn is_well_formed(key: &str) -> bool {
    if key.len() != LEN || !key.is_ascii() || !key.starts_with(PREFIX) {
        return false;
    }
    let (body, check) = key.split_at(LEN - CHECK_LEN);
    // Decoding rejects characters outside the alphabet and non-zero trailing
    // bits, so each key has exactly one spelling.
    B64.decode(&body[PREFIX.len()..]).is_ok_and(|b| b.len() == 32) && checksum(body) == check
}

/// The SHA-256 of a key, as compared by the server.
#[must_use]
pub fn digest(key: &str) -> [u8; 32] {
    Sha256::digest(key.as_bytes()).into()
}

/// The `auth.host_key_sha256` value for a `[[client]]`: 64 lowercase hex digits.
#[must_use]
pub fn digest_hex(key: &str) -> String {
    use std::fmt::Write as _;
    digest(key).iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Parse a configured `host_key_sha256` (64 hex digits, either case).
#[must_use]
pub fn parse_digest_hex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_are_well_formed() {
        let key = from_random(&[7; 32]);
        assert_eq!(key.len(), LEN);
        assert!(key.starts_with("cshk_"));
        assert!(is_well_formed(&key));
        assert_eq!(parse_digest_hex(&digest_hex(&key)), Some(digest(&key)));
        // Computed independently (Python's base64 and hashlib).
        assert_eq!(from_random(&[1; 32]), "cshk_AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEDVuYWg");
    }

    #[test]
    fn anything_else_is_rejected() {
        let key = from_random(&[42; 32]);
        // A typo in the random part or the checksum.
        for i in [PREFIX.len(), LEN / 2, LEN - 1] {
            let mut typo = key.clone().into_bytes();
            typo[i] = if typo[i] == b'A' { b'B' } else { b'A' };
            assert!(!is_well_formed(std::str::from_utf8(&typo).unwrap()), "typo at {i}");
        }
        assert!(!is_well_formed(&key.replacen("cshk_", "cshx_", 1)));
        assert!(!is_well_formed(&format!("{key}\n")));
        assert!(!is_well_formed(&key[..LEN - 1]));
        assert!(!is_well_formed(&"a".repeat(64)), "an old hex key");
        assert!(!is_well_formed("hunter2"));
        assert!(!is_well_formed(""));
        // Same length, outside the alphabet.
        assert!(!is_well_formed(&format!("cshk_{}", "+".repeat(LEN - 5))));
    }

    #[test]
    fn digest_hex_parses_in_either_case_and_nothing_else() {
        let hex = digest_hex("x");
        assert_eq!(parse_digest_hex(&hex.to_uppercase()), parse_digest_hex(&hex));
        assert!(parse_digest_hex(&hex[..63]).is_none());
        assert!(parse_digest_hex(&format!("{}g", &hex[..63])).is_none());
        assert!(parse_digest_hex(&format!("+{}", &hex[1..])).is_none());
    }
}
