-- Background jobs (docs/DESIGN.md, "Bulk jobs").
--
-- A job is a CSV or NDJSON import, an export, or one patch applied to many
-- links. An import's upload is split into chunks of whole records when it
-- arrives, so a worker never holds more than one chunk in memory, and an
-- export writes its result as chunks the API streams back. The job worker
-- (src/jobs.rs) claims a runnable job with SKIP LOCKED and a lease, works
-- through it one step at a time, and commits each step with the job's
-- progress in the same transaction: a worker that dies loses at most the
-- step it was on, which the next worker does again from the stored cursor.

CREATE TABLE jobs (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    workspace_id  bigint      NOT NULL DEFAULT relink_current_workspace()
                              REFERENCES workspaces (id) ON DELETE CASCADE,
    kind          text        NOT NULL CHECK (kind IN ('import', 'export', 'patch')),
    -- The file format of an import or export; NULL for a patch.
    format        text        CHECK (format IN ('csv', 'ndjson')),
    CHECK ((kind = 'patch') = (format IS NULL)),
    -- What the job does: an import's CSV columns, an export's domain, a
    -- patch's filter and change.
    params        jsonb       NOT NULL DEFAULT '{}'
                              CHECK (octet_length(params::text) <= 131072),
    state         text        NOT NULL DEFAULT 'queued'
                              CHECK (state IN ('queued', 'running', 'succeeded', 'failed',
                                               'cancelled')),
    -- Rows (links) the job covers, and how far it is.
    total         bigint      NOT NULL DEFAULT 0 CHECK (total >= 0),
    processed     bigint      NOT NULL DEFAULT 0 CHECK (processed >= 0),
    succeeded     bigint      NOT NULL DEFAULT 0 CHECK (succeeded >= 0),
    failed        bigint      NOT NULL DEFAULT 0 CHECK (failed >= 0),
    CHECK (succeeded + failed = processed),
    -- Where the next step starts: an import's next input chunk, or the
    -- last link ID an export or patch has done.
    cursor        bigint      NOT NULL DEFAULT 0 CHECK (cursor >= 0),
    -- An export's output chunks so far.
    output_chunks integer     NOT NULL DEFAULT 0 CHECK (output_chunks >= 0),
    -- Why the job failed, when it did.
    error         text        CHECK (length(error) <= 300),
    -- Steps that failed in a row; the job fails at a limit.
    failures      integer     NOT NULL DEFAULT 0 CHECK (failures >= 0),
    -- Who started it: new links are theirs, and changes are audited as
    -- theirs (audit_log's actor and via).
    created_by    text        NOT NULL,
    via           text        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    started_at    timestamptz,
    finished_at   timestamptz,
    CHECK ((state IN ('succeeded', 'failed', 'cancelled')) = (finished_at IS NOT NULL)),
    -- When a worker last took the job: runnable jobs are taken least
    -- recently run first, so one big job does not hold up the others.
    last_run_at   timestamptz,
    -- A worker holds the job until then, under its token; a step commits
    -- only while its worker's token is still the job's.
    lease_until   timestamptz NOT NULL DEFAULT now(),
    lease_token   bigint,
    UNIQUE (workspace_id, id)
);

-- The worker's "what can run".
CREATE INDEX jobs_runnable ON jobs (last_run_at NULLS FIRST, id)
    WHERE state IN ('queued', 'running');
-- A workspace's jobs, newest first.
CREATE INDEX jobs_workspace ON jobs (workspace_id, id DESC);
-- Retention.
CREATE INDEX jobs_finished ON jobs (finished_at) WHERE finished_at IS NOT NULL;

CREATE TABLE job_chunks (
    job_id       bigint  NOT NULL,
    workspace_id bigint  NOT NULL DEFAULT relink_current_workspace(),
    part         text    NOT NULL CHECK (part IN ('input', 'output')),
    seq          integer NOT NULL CHECK (seq >= 0),
    -- The number of the chunk's first record in the whole file (1 for the
    -- first record after a CSV header), and how many it holds.
    first_row    bigint  NOT NULL CHECK (first_row >= 1),
    rows         integer NOT NULL CHECK (rows >= 0),
    -- Whole records, each ended by a newline.
    data         bytea   NOT NULL CHECK (octet_length(data) <= 4194304),
    PRIMARY KEY (job_id, part, seq),
    FOREIGN KEY (workspace_id, job_id) REFERENCES jobs (workspace_id, id) ON DELETE CASCADE
);

-- The rows a job could not do, by record number; only the first ones are
-- kept, the rest only counted in jobs.failed.
CREATE TABLE job_errors (
    job_id       bigint NOT NULL,
    workspace_id bigint NOT NULL DEFAULT relink_current_workspace(),
    row          bigint NOT NULL CHECK (row >= 1),
    code         text   NOT NULL CHECK (code ~ '^[a-z_]+$'),
    message      text   NOT NULL CHECK (length(message) <= 300),
    PRIMARY KEY (job_id, row),
    FOREIGN KEY (workspace_id, job_id) REFERENCES jobs (workspace_id, id) ON DELETE CASCADE
);

DO $$
BEGIN
    EXECUTE format('GRANT USAGE ON SEQUENCE %s TO relink_tenant',
                   pg_get_serial_sequence('jobs', 'id'));
END
$$;

GRANT SELECT, INSERT, UPDATE ON jobs TO relink_tenant;
GRANT SELECT, INSERT, DELETE ON job_chunks TO relink_tenant;
GRANT SELECT, INSERT ON job_errors TO relink_tenant;

ALTER TABLE jobs       ENABLE ROW LEVEL SECURITY;
ALTER TABLE job_chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE job_errors ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON jobs TO relink_tenant
    USING (workspace_id = relink_current_workspace());
CREATE POLICY tenant ON job_chunks TO relink_tenant
    USING (workspace_id = relink_current_workspace());
CREATE POLICY tenant ON job_errors TO relink_tenant
    USING (workspace_id = relink_current_workspace());
