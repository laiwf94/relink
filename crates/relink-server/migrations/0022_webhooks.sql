-- Webhooks (docs/DESIGN.md, "Webhooks").
--
-- A workspace registers endpoints for the events it wants. An event is
-- written as one delivery row per subscribed endpoint in the same
-- transaction as the change it describes, so a committed change is always
-- delivered eventually and a rolled-back one never is. The delivery worker
-- (src/webhooks.rs) claims due rows with SKIP LOCKED, posts them signed,
-- and either marks them delivered or schedules a retry; every try is kept
-- in webhook_attempts, the delivery log.

CREATE TABLE webhooks (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    workspace_id bigint      NOT NULL DEFAULT relink_current_workspace()
                             REFERENCES workspaces (id) ON DELETE CASCADE,
    -- Normalised by the server: http or https, a public host, no
    -- credentials.
    url          text        NOT NULL CHECK (length(url) BETWEEN 1 AND 2048),
    -- The HMAC key, as handed to the workspace once ("whsec_" and 64 hex).
    secret       text        NOT NULL CHECK (secret ~ '^whsec_[0-9a-f]{64}$'),
    events       text[]      NOT NULL CHECK (cardinality(events) BETWEEN 1 AND 16),
    description  text        NOT NULL DEFAULT '' CHECK (length(description) <= 200),
    enabled      boolean     NOT NULL DEFAULT true,
    created_by   text        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    -- The target of deliveries' composite foreign key, and the emit
    -- query's index: a workspace's endpoints.
    UNIQUE (workspace_id, id)
);

CREATE TABLE webhook_deliveries (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    webhook_id      bigint      NOT NULL,
    workspace_id    bigint      NOT NULL DEFAULT relink_current_workspace(),
    -- Shared by the deliveries of one event to several endpoints, and the
    -- same on every retry, so receivers can drop duplicates.
    event_id        text        NOT NULL CHECK (event_id ~ '^evt_[0-9a-f]{32}$'),
    event           text        NOT NULL CHECK (event ~ '^[a-z]+\.[a-z_]+$'),
    -- The exact body posted, every time.
    payload         jsonb       NOT NULL CHECK (octet_length(payload::text) <= 262144),
    created_at      timestamptz NOT NULL DEFAULT now(),
    state           text        NOT NULL DEFAULT 'pending'
                                CHECK (state IN ('pending', 'delivered', 'failed')),
    attempts        integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    -- When a pending delivery is next due. A worker that claims it moves
    -- this past its own timeout, so a crashed worker's claim comes back.
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    delivered_at    timestamptz,
    last_status     smallint,
    last_error      text        CHECK (length(last_error) <= 300),
    CHECK ((state = 'delivered') = (delivered_at IS NOT NULL)),
    UNIQUE (webhook_id, event_id),
    -- A delivery belongs to its endpoint's own workspace.
    FOREIGN KEY (workspace_id, webhook_id) REFERENCES webhooks (workspace_id, id)
        ON DELETE CASCADE
);

-- The worker's "what is due"; finished deliveries cost nothing.
CREATE INDEX webhook_deliveries_due ON webhook_deliveries (next_attempt_at)
    WHERE state = 'pending';
-- One endpoint's log, newest first, with keyset pagination.
CREATE INDEX webhook_deliveries_webhook ON webhook_deliveries (webhook_id, id DESC);
-- Retention.
CREATE INDEX webhook_deliveries_created ON webhook_deliveries (created_at);

CREATE TABLE webhook_attempts (
    delivery_id  bigint      NOT NULL REFERENCES webhook_deliveries (id) ON DELETE CASCADE,
    attempt      integer     NOT NULL CHECK (attempt >= 1),
    at           timestamptz NOT NULL DEFAULT now(),
    -- The response status, or NULL when there was no response.
    status       smallint,
    duration_ms  integer     NOT NULL CHECK (duration_ms >= 0),
    -- What went wrong, or the start of the response body.
    error        text        CHECK (length(error) <= 300),
    response     text        CHECK (length(response) <= 512),
    PRIMARY KEY (delivery_id, attempt)
);

-- link.expired is announced once per expiry: the expiry it was announced
-- for is kept, so moving expires_at later announces the new one in turn.
ALTER TABLE links ADD COLUMN expiry_announced timestamptz;
-- Links already expired are not announced after the upgrade.
UPDATE links SET expiry_announced = expires_at WHERE expires_at <= now();
CREATE INDEX links_expiry_due ON links (expires_at)
    WHERE expires_at IS NOT NULL AND expiry_announced IS DISTINCT FROM expires_at;

DO $$
BEGIN
    EXECUTE format('GRANT USAGE ON SEQUENCE %s TO relink_tenant',
                   pg_get_serial_sequence('webhooks', 'id'));
    EXECUTE format('GRANT USAGE ON SEQUENCE %s TO relink_tenant',
                   pg_get_serial_sequence('webhook_deliveries', 'id'));
END
$$;

GRANT SELECT, INSERT, UPDATE, DELETE ON webhooks TO relink_tenant;
GRANT SELECT, INSERT, UPDATE ON webhook_deliveries TO relink_tenant;
GRANT SELECT ON webhook_attempts TO relink_tenant;

ALTER TABLE webhooks           ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_attempts   ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON webhooks TO relink_tenant
    USING (workspace_id = relink_current_workspace());
CREATE POLICY tenant ON webhook_deliveries TO relink_tenant
    USING (workspace_id = relink_current_workspace());
CREATE POLICY tenant ON webhook_attempts TO relink_tenant
    USING (EXISTS (SELECT 1 FROM webhook_deliveries d
                    WHERE d.id = webhook_attempts.delivery_id
                      AND d.workspace_id = relink_current_workspace()));
