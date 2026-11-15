-- Per-channel delivery record, so retrying an event for one channel does not
-- repeat it on channels that already handled it.
CREATE TABLE outbox_deliveries (
    event_id        TEXT    NOT NULL REFERENCES outbox (id),
    channel         TEXT    NOT NULL,
    delivered_at_ms INTEGER NOT NULL,
    PRIMARY KEY (event_id, channel)
) STRICT;
