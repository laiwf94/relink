-- Plans and quotas (docs/DESIGN.md, "Plans and quotas").
--
-- A plan names a set of limits; every workspace is on exactly one. A NULL
-- limit means "no limit", and the seeded plan `unlimited`, the default for
-- every workspace, has no limits at all, so upgrading changes nothing until
-- an operator defines plans and assigns them (`relink plan-set`,
-- `relink plan-assign`).
--
-- Clicks are metered per workspace and calendar month (UTC) by the click
-- flusher, in the same transaction that adds them to click_daily, so the
-- meter and the statistics never disagree about a flushed batch.

CREATE TABLE plans (
    name            text        PRIMARY KEY CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
    max_links       bigint      CHECK (max_links >= 0),
    monthly_clicks  bigint      CHECK (monthly_clicks >= 0),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

INSERT INTO plans (name) VALUES ('unlimited');

-- ON UPDATE CASCADE: renaming a plan carries its workspaces along. A plan
-- that workspaces are on cannot be deleted.
ALTER TABLE workspaces
    ADD COLUMN plan text NOT NULL DEFAULT 'unlimited'
        REFERENCES plans (name) ON UPDATE CASCADE;

-- One row per workspace and month with clicks; `month` is the first day.
CREATE TABLE workspace_usage (
    workspace_id  bigint NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    month         date   NOT NULL CHECK (extract(day FROM month) = 1),
    clicks        bigint NOT NULL CHECK (clicks >= 0),
    PRIMARY KEY (workspace_id, month)
);

-- A tenant transaction reads limits and its own usage and may rename its
-- workspace, but never moves itself to another plan: UPDATE on workspaces
-- is narrowed to the name column. Locking the workspace row (FOR NO KEY
-- UPDATE, which orders concurrent link creation under a link limit) needs
-- UPDATE on any one column, so that still works.
REVOKE UPDATE ON workspaces FROM relink_tenant;
GRANT UPDATE (name) ON workspaces TO relink_tenant;
-- Limits are not tenant data: every plan is readable.
GRANT SELECT ON plans TO relink_tenant;
GRANT SELECT ON workspace_usage TO relink_tenant;

ALTER TABLE workspace_usage ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant ON workspace_usage TO relink_tenant
    USING (workspace_id = relink_current_workspace());
