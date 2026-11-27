-- Indexes for latest-subject lookup and retention purging.
CREATE INDEX IF NOT EXISTS requests_subject_latest
    ON requests (backend, subject_kind, subject_id, created_at_ms DESC, id DESC)
    WHERE kind = 'approval';

CREATE INDEX IF NOT EXISTS requests_closed_updated
    ON requests (updated_at_ms)
    WHERE is_open = 0;
