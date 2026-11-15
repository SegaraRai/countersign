-- Requests are stored as JSON documents, with the columns needed for lookups
-- and constraints pulled out next to them.
CREATE TABLE requests (
    id            TEXT    PRIMARY KEY NOT NULL,
    backend       TEXT    NOT NULL,
    subject_kind  TEXT    NOT NULL,
    subject_id    TEXT    NOT NULL,
    state         TEXT    NOT NULL,
    is_open       INTEGER NOT NULL CHECK (is_open IN (0, 1)),
    version       INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    body          TEXT    NOT NULL CHECK (json_valid(body))
) STRICT;

-- At most one open request per backend subject.
CREATE UNIQUE INDEX requests_open_subject
    ON requests (backend, subject_kind, subject_id) WHERE is_open = 1;

CREATE INDEX requests_created ON requests (created_at_ms DESC);

-- Transactional outbox. Delivered rows are kept as an audit trail.
CREATE TABLE outbox (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    id              TEXT    NOT NULL UNIQUE,
    request_id      TEXT    NOT NULL REFERENCES requests (id),
    kind            TEXT    NOT NULL,
    event           TEXT    NOT NULL CHECK (json_valid(event)),
    attempts        INTEGER NOT NULL DEFAULT 0,
    available_at_ms INTEGER NOT NULL,
    delivered_at_ms INTEGER,
    last_error      TEXT,
    created_at_ms   INTEGER NOT NULL
) STRICT;

CREATE INDEX outbox_due ON outbox (available_at_ms, seq) WHERE delivered_at_ms IS NULL;
CREATE INDEX outbox_request ON outbox (request_id, seq);

-- Messages posted by channels, so later events can edit them.
CREATE TABLE message_refs (
    request_id TEXT NOT NULL REFERENCES requests (id),
    channel    TEXT NOT NULL,
    message_id TEXT NOT NULL,
    PRIMARY KEY (request_id, channel)
) STRICT;

-- External accounts (chat users, ...) linked to approvers.
CREATE TABLE account_links (
    channel      TEXT    NOT NULL,
    external_id  TEXT    NOT NULL,
    approver_id  TEXT    NOT NULL,
    linked_at_ms INTEGER NOT NULL,
    PRIMARY KEY (channel, external_id)
) STRICT;
