-- Link version history and scheduled changes (docs/DESIGN.md, "Versions
-- and schedules").
--
-- Every change to what a link does is kept as a numbered version: the
-- link's settings as one JSON object, built by relink_link_spec below so
-- the server never writes the snapshot itself and a snapshot cannot drift
-- from the row it describes. links.version is the number of the version
-- the row matches. A rollback writes an old version's settings back as a
-- new version, so history only grows; the server keeps the newest 100 per
-- link.
--
-- A schedule is a change (new destinations, enabled or disabled) to apply
-- to one link at a time. The scheduler applies each due change once, in the
-- same transaction that marks it applied, on whichever instance takes its
-- row lock first.

ALTER TABLE links ADD COLUMN version integer NOT NULL DEFAULT 1 CHECK (version > 0);

-- A link's settings, the fields the API's PatchLink can change, in the
-- shape relink_server::schedule::LinkSpec reads. Timestamps are written in
-- UTC whatever the session's time zone, so equal settings always give equal
-- JSON and an unchanged link is recognised as unchanged.
CREATE FUNCTION relink_link_spec(l links) RETURNS jsonb
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$
SELECT jsonb_build_object(
    'destinations', l.destinations,
    'redirect_type', l.redirect_status,
    'expires_at', to_char(l.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'max_clicks', l.max_clicks,
    'geo', CASE WHEN l.geo_mode IS NULL THEN NULL
                ELSE jsonb_build_object('mode', l.geo_mode, 'countries', to_jsonb(l.geo_countries))
           END,
    'fallback_url', l.fallback_url,
    'enabled', l.enabled,
    'health_check', l.health_check,
    'rules', l.rules,
    'app', l.app)
$$;

CREATE TABLE link_schedules (
    id              bigserial   PRIMARY KEY,
    link_id         bigint      NOT NULL REFERENCES links (id) ON DELETE CASCADE,
    run_at          timestamptz NOT NULL,
    -- relink_server::schedule::ScheduledChange, validated by the server.
    change          jsonb       NOT NULL
        CHECK (jsonb_typeof(change) = 'object' AND octet_length(change::text) <= 16384),
    member          text,
    via             text        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    state           text        NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'applied', 'failed', 'canceled')),
    finished_at     timestamptz,
    -- The version the change produced (or the one already current, when it
    -- changed nothing).
    applied_version integer,
    error           text        CHECK (octet_length(error) <= 1024),
    CHECK ((state = 'pending') = (finished_at IS NULL)),
    CHECK ((state = 'applied') = (applied_version IS NOT NULL)),
    CHECK ((state = 'failed') = (error IS NOT NULL))
);

-- The scheduler's "what is due"; finished schedules cost nothing.
CREATE INDEX link_schedules_due ON link_schedules (run_at, id) WHERE state = 'pending';
-- One link's schedules, newest first, with keyset pagination.
CREATE INDEX link_schedules_link ON link_schedules (link_id, id DESC);

CREATE TABLE link_versions (
    link_id       bigint      NOT NULL REFERENCES links (id) ON DELETE CASCADE,
    version       integer     NOT NULL CHECK (version > 0),
    created_at    timestamptz NOT NULL DEFAULT now(),
    member        text,
    via           text        NOT NULL,
    source        text        NOT NULL
        CHECK (source IN ('create', 'update', 'rollback', 'schedule', 'migration')),
    restored_from integer,
    schedule_id   bigint      REFERENCES link_schedules (id) ON DELETE CASCADE,
    spec          jsonb       NOT NULL
        CHECK (jsonb_typeof(spec) = 'object' AND octet_length(spec::text) <= 131072),
    PRIMARY KEY (link_id, version),
    CHECK ((source = 'rollback') = (restored_from IS NOT NULL)),
    CHECK ((source = 'schedule') = (schedule_id IS NOT NULL))
);

-- Links from before this migration start their history at version 1.
INSERT INTO link_versions (link_id, version, created_at, via, source, spec)
SELECT l.id, 1, l.updated_at, 'system', 'migration', relink_link_spec(l) FROM links l;

DO $$
BEGIN
    EXECUTE format('GRANT USAGE ON SEQUENCE %s TO relink_tenant',
                   pg_get_serial_sequence('link_schedules', 'id'));
END
$$;

-- History is written and pruned, never edited; a schedule is cancelled or
-- finished, never erased, so its outcome stays visible.
GRANT SELECT, INSERT, DELETE ON link_versions TO relink_tenant;
GRANT SELECT, INSERT, UPDATE ON link_schedules TO relink_tenant;

-- Both belong to the workspace of their link, like the statistics tables.
ALTER TABLE link_versions  ENABLE ROW LEVEL SECURITY;
ALTER TABLE link_schedules ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant ON link_versions TO relink_tenant
    USING (EXISTS (SELECT 1 FROM links l WHERE l.id = link_versions.link_id
                                         AND l.workspace_id = relink_current_workspace()));
CREATE POLICY tenant ON link_schedules TO relink_tenant
    USING (EXISTS (SELECT 1 FROM links l WHERE l.id = link_schedules.link_id
                                         AND l.workspace_id = relink_current_workspace()));
