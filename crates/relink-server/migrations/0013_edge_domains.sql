-- Custom domains at the edge (docs/DESIGN.md, "Custom domains at the edge").
-- The KV outbox now holds whole KV keys rather than default-domain codes:
-- `link:<code>` for a link on the default domain, `link:<host>/<code>` for
-- a link on a custom domain and `host:<host>` for a verified domain's own
-- record. Entries already queued keep their meaning.
ALTER TABLE kv_outbox RENAME COLUMN code TO key;
UPDATE kv_outbox SET key = 'link:' || key;
ALTER TABLE kv_outbox ADD CONSTRAINT kv_outbox_key_shape
    CHECK (key LIKE 'link:%' OR key LIKE 'host:%');

-- Domains verified before this migration need no backfill here: the sync
-- reconciles KV with the database when it starts and queues what is
-- missing, and without edge publishing nothing should be queued at all.
