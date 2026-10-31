-- Workspaces: the tenant boundary. Every link, API key and statistic belongs
-- to exactly one workspace, and row-level security keeps a transaction that
-- acts for a tenant inside its workspace (docs/DESIGN.md, "Tenancy").
--
-- A tenant transaction runs as the role relink_tenant (SET LOCAL ROLE) with
-- the setting relink.workspace_id set for that transaction only; see
-- Db::begin_tenant in src/store.rs. Policies compare against that setting, so
-- a tenant transaction that forgot to set it sees no rows at all.

CREATE TABLE workspaces (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name            text        NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    -- Set for the workspace created implicitly for an API key owner; other
    -- workspaces leave it NULL.
    personal_owner  text        UNIQUE CHECK (personal_owner ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE workspace_members (
    workspace_id  bigint      NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    member        text        NOT NULL CHECK (member ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
    role          text        NOT NULL CHECK (role IN ('owner', 'admin', 'editor', 'viewer')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, member)
);

-- "Which workspaces is this person in": sign-in and workspace switching.
CREATE INDEX workspace_members_member ON workspace_members (member);

-- The workspace the current transaction acts for, or NULL when none is set.
-- current_setting(.., true) is NULL before the first set_config in a session
-- and '' after a transaction-local value has been reset, so both mean "none".
CREATE FUNCTION relink_current_workspace() RETURNS bigint
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$ SELECT NULLIF(current_setting('relink.workspace_id', true), '')::bigint $$;

-- Backfill: one personal workspace per existing owner, owned by that owner.
INSERT INTO workspaces (name, personal_owner)
SELECT owner, owner
  FROM (SELECT owner FROM api_keys UNION SELECT owner FROM links) o
 ORDER BY owner;

INSERT INTO workspace_members (workspace_id, member, role)
SELECT id, personal_owner, 'owner' FROM workspaces;

ALTER TABLE links ADD COLUMN workspace_id bigint REFERENCES workspaces (id);
UPDATE links l SET workspace_id = w.id FROM workspaces w WHERE w.personal_owner = l.owner;
ALTER TABLE links ALTER COLUMN workspace_id SET NOT NULL,
                  ALTER COLUMN workspace_id SET DEFAULT relink_current_workspace();

ALTER TABLE api_keys ADD COLUMN workspace_id bigint REFERENCES workspaces (id);
UPDATE api_keys k SET workspace_id = w.id FROM workspaces w WHERE w.personal_owner = k.owner;
ALTER TABLE api_keys ALTER COLUMN workspace_id SET NOT NULL,
                     ALTER COLUMN workspace_id SET DEFAULT relink_current_workspace();

-- Workspace listing with keyset pagination, and the policy's own predicate.
CREATE INDEX links_workspace_id ON links (workspace_id, id DESC);
CREATE INDEX api_keys_workspace ON api_keys (workspace_id);

-- The tenant role. Roles are cluster-wide, so another database (or a
-- concurrent migration) may already have created it; a DBA may also create
-- it in advance where the migrating user lacks CREATEROLE.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'relink_tenant') THEN
        BEGIN
            CREATE ROLE relink_tenant NOLOGIN NOINHERIT NOBYPASSRLS;
        EXCEPTION WHEN duplicate_object OR unique_violation THEN
            NULL;
        END;
    END IF;
    IF NOT pg_has_role(current_user, 'relink_tenant', 'MEMBER') THEN
        EXECUTE format('GRANT relink_tenant TO %I', current_user);
    END IF;
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO relink_tenant', current_schema());
    EXECUTE format('GRANT USAGE ON SEQUENCE %s, %s TO relink_tenant',
                   pg_get_serial_sequence('links', 'id'),
                   pg_get_serial_sequence('api_keys', 'id'));
END
$$;

GRANT SELECT, UPDATE ON workspaces TO relink_tenant;
GRANT SELECT, INSERT, UPDATE, DELETE ON workspace_members, links, api_keys TO relink_tenant;
GRANT SELECT ON click_daily, visitor_daily, visitor_rollup TO relink_tenant;
-- Link changes enqueue their code for the edge in the same transaction.
GRANT SELECT, INSERT, UPDATE ON kv_outbox TO relink_tenant;

ALTER TABLE workspaces        ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE links             ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys          ENABLE ROW LEVEL SECURITY;
ALTER TABLE click_daily       ENABLE ROW LEVEL SECURITY;
ALTER TABLE visitor_daily     ENABLE ROW LEVEL SECURITY;
ALTER TABLE visitor_rollup    ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON workspaces TO relink_tenant
    USING (id = relink_current_workspace());
CREATE POLICY tenant ON workspace_members TO relink_tenant
    USING (workspace_id = relink_current_workspace());
CREATE POLICY tenant ON links TO relink_tenant
    USING (workspace_id = relink_current_workspace());
CREATE POLICY tenant ON api_keys TO relink_tenant
    USING (workspace_id = relink_current_workspace());
-- Statistics carry no workspace column of their own: they belong to the
-- workspace of their link; the planner turns each EXISTS into a semi-join on
-- the links primary key.
CREATE POLICY tenant ON click_daily TO relink_tenant
    USING (EXISTS (SELECT 1 FROM links l WHERE l.id = click_daily.link_id
                                         AND l.workspace_id = relink_current_workspace()));
CREATE POLICY tenant ON visitor_daily TO relink_tenant
    USING (EXISTS (SELECT 1 FROM links l WHERE l.id = visitor_daily.link_id
                                         AND l.workspace_id = relink_current_workspace()));
CREATE POLICY tenant ON visitor_rollup TO relink_tenant
    USING (EXISTS (SELECT 1 FROM links l WHERE l.id = visitor_rollup.link_id
                                         AND l.workspace_id = relink_current_workspace()));
