use std::time::Duration;

use jiff::{SignedDuration, Timestamp};

/// `ts + d`, saturating at [`Timestamp::MAX`].
pub(crate) fn add(ts: Timestamp, d: Duration) -> Timestamp {
    SignedDuration::try_from(d).ok().and_then(|d| ts.checked_add(d).ok()).unwrap_or(Timestamp::MAX)
}
