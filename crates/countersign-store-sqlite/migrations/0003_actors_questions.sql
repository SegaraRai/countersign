-- Persons and workloads replace approvers.
ALTER TABLE account_links RENAME COLUMN approver_id TO actor_id;

-- Questions live next to approvals so the outbox and message references
-- work for both. For questions, backend is the asking client's id.
ALTER TABLE requests ADD COLUMN kind TEXT NOT NULL DEFAULT 'approval' CHECK (kind IN ('approval', 'question'));
-- Whether the body may still hold confidential content, for the sweeper.
ALTER TABLE requests ADD COLUMN holds_content INTEGER NOT NULL DEFAULT 0 CHECK (holds_content IN (0, 1));

CREATE INDEX requests_kind_created ON requests (kind, created_at_ms DESC);
CREATE INDEX requests_holding_content ON requests (id) WHERE holds_content = 1;

-- Suspensions take effect immediately and override the configuration.
CREATE TABLE suspensions (
    actor_id TEXT PRIMARY KEY NOT NULL,
    body     TEXT NOT NULL CHECK (json_valid(body))
) STRICT;

-- Identity-provider groups from each person's latest sign-in.
CREATE TABLE idp_snapshots (
    person_id TEXT PRIMARY KEY NOT NULL,
    body      TEXT NOT NULL CHECK (json_valid(body))
) STRICT;

CREATE TABLE admin_actions (
    seq    INTEGER PRIMARY KEY AUTOINCREMENT,
    at_ms  INTEGER NOT NULL,
    by_id  TEXT    NOT NULL,
    action TEXT    NOT NULL,
    target TEXT    NOT NULL,
    detail TEXT
) STRICT;
