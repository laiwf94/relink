-- Links whose edge copy (Workers KV) must be rewritten or deleted. Rows are
-- added in the same transaction as the change, so a committed change always
-- reaches KV eventually, however often the sync itself fails.
CREATE TABLE kv_outbox (
    code             text COLLATE "C" PRIMARY KEY,
    enqueued_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    attempts         integer     NOT NULL DEFAULT 0,
    next_attempt_at  timestamptz NOT NULL DEFAULT now()
);

-- The sync worker's "what is due" scan.
CREATE INDEX kv_outbox_due ON kv_outbox (next_attempt_at);
