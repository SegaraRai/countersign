-- Browser Web Push subscriptions belonging to persons.
CREATE TABLE push_subscriptions (
    id            TEXT PRIMARY KEY NOT NULL,
    actor_id      TEXT NOT NULL,
    endpoint      TEXT NOT NULL UNIQUE,
    p256dh        TEXT NOT NULL,
    auth          TEXT NOT NULL,
    label         TEXT,
    created_at_ms INTEGER NOT NULL
) STRICT;

CREATE INDEX push_subscriptions_actor ON push_subscriptions (actor_id);
