//! Linking chat accounts to persons, and the [`ActionSink`] channels use.
//!
//! A person signed in to the web UI asks for a one-time code, then gives it
//! to the chat platform (e.g. `/countersign-link` on Discord). The platform
//! tells us who sent it, so redeeming the code ties that chat account to the
//! person. Codes live only in memory: short-lived, single-use, and at most
//! one outstanding per person.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use jiff::{SignedDuration, Timestamp};
use tracing::info;

use countersign_core::{ActionIntent, ActionSink, ActorId, AnswerIntent, ChannelName, Question, Request};

use crate::engine::Engine;

/// How long a link code stays valid.
pub const CODE_TTL: Duration = Duration::from_secs(10 * 60);
/// Crockford base32: no I, L, O, U, so codes survive being read aloud or retyped.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CODE_LEN: usize = 10;

#[derive(Debug, Default)]
pub struct LinkCodes {
    codes: Mutex<HashMap<String, (ActorId, Timestamp)>>,
}

impl LinkCodes {
    fn lock(&self) -> MutexGuard<'_, HashMap<String, (ActorId, Timestamp)>> {
        // The map stays consistent even if a holder panicked.
        self.codes.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A fresh code for `person`, replacing any earlier one. Shown as
    /// `XXXXX-XXXXX`; dashes, spaces and case are ignored when redeeming.
    ///
    /// # Panics
    ///
    /// If the operating system cannot provide random numbers.
    pub fn issue(&self, person: &ActorId, now: Timestamp) -> (String, Timestamp) {
        let mut bytes = [0u8; CODE_LEN];
        getrandom::getrandom(&mut bytes).expect("the operating system's random number generator failed");
        let raw: String = bytes.iter().map(|b| char::from(ALPHABET[usize::from(b & 31)])).collect();
        let expires =
            now.saturating_add(SignedDuration::from_secs(CODE_TTL.as_secs().cast_signed())).unwrap_or(Timestamp::MAX);
        let mut codes = self.lock();
        codes.retain(|_, (a, exp)| a != person && *exp > now);
        codes.insert(raw.clone(), (person.clone(), expires));
        (format!("{}-{}", &raw[..CODE_LEN / 2], &raw[CODE_LEN / 2..]), expires)
    }

    /// The person a code was issued to, consuming the code.
    pub fn redeem(&self, code: &str, now: Timestamp) -> Option<ActorId> {
        let normalized: String =
            code.chars().filter(|c| !matches!(c, '-' | ' ')).map(|c| c.to_ascii_uppercase()).collect();
        let mut codes = self.lock();
        codes.retain(|_, (_, exp)| *exp > now);
        codes.remove(&normalized).map(|(a, _)| a)
    }
}

/// What interactive channels call into.
#[derive(Debug, Clone)]
pub struct DaemonSink {
    pub engine: Arc<Engine>,
    pub codes: Arc<LinkCodes>,
}

#[async_trait]
impl ActionSink for DaemonSink {
    async fn resolve_account(&self, channel: &ChannelName, external_id: &str) -> Result<Option<ActorId>, String> {
        let linked = self.engine.store().resolve_account(channel, external_id).await.map_err(|e| e.to_string())?;
        // A link outlives config changes; only honour it for active persons.
        let (rules, standing) = self.engine.standing().await.map_err(|e| e.to_string())?;
        let roster = rules.roster(&standing, Timestamp::now());
        Ok(linked.filter(|p| roster.active_person(p).is_some()))
    }

    async fn link_account(&self, channel: &ChannelName, external_id: &str, code: &str) -> Result<ActorId, String> {
        let now = Timestamp::now();
        let person = self.codes.redeem(code, now).ok_or("unknown or expired code")?;
        let (rules, standing) = self.engine.standing().await.map_err(|e| e.to_string())?;
        if rules.roster(&standing, now).active_person(&person).is_none() {
            return Err("that person is no longer active".into());
        }
        self.engine.store().link_account(channel, external_id, &person).await.map_err(|e| e.to_string())?;
        info!(%channel, external_id, %person, "chat account linked");
        Ok(person)
    }

    async fn submit(&self, intent: ActionIntent) -> Result<Request, String> {
        self.engine.decide(intent, Timestamp::now()).await.map_err(|e| e.to_string())
    }

    async fn answer(&self, intent: AnswerIntent) -> Result<Question, String> {
        self.engine.answer(intent, Timestamp::now()).await.map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_single_use_normalized_and_expire() {
        let codes = LinkCodes::default();
        let now = Timestamp::UNIX_EPOCH;
        let alice = ActorId::new("alice");
        let (code, expires) = codes.issue(&alice, now);
        assert_eq!(code.len(), CODE_LEN + 1);
        assert_eq!(expires, now + SignedDuration::from_mins(10));
        let sloppy = code.to_lowercase().replace('-', " ");
        assert_eq!(codes.redeem(&sloppy, now), Some(alice.clone()));
        assert_eq!(codes.redeem(&code, now), None, "single use");

        let (code, _) = codes.issue(&alice, now);
        assert_eq!(codes.redeem(&code, expires + SignedDuration::from_secs(1)), None, "expired");
    }

    #[test]
    fn a_new_code_replaces_the_previous_one() {
        let codes = LinkCodes::default();
        let now = Timestamp::UNIX_EPOCH;
        let alice = ActorId::new("alice");
        let (first, _) = codes.issue(&alice, now);
        let (second, _) = codes.issue(&alice, now);
        let bob_code = codes.issue(&ActorId::new("bob"), now).0;
        assert_eq!(codes.redeem(&first, now), None);
        assert_eq!(codes.redeem(&second, now), Some(alice));
        assert_eq!(codes.redeem(&bob_code, now), Some(ActorId::new("bob")));
    }
}
