-- Scoped, expiring and rotatable API keys (docs/DESIGN.md, "Roles and API
-- key scopes").
--
-- A key carries a set of scopes; what it can do is that set within the
-- rights of its owner's role in the key's workspace (workspace_members.role),
-- read together with the key at authentication. Keys created before this
-- migration keep every scope, so nothing that worked stops working.
--
-- Rotation inserts a successor with the same owner, name, scopes and
-- lifetime, records it in rotated_to, and shortens the old key's expires_at
-- to the end of an overlap window during which both keys work.

ALTER TABLE api_keys
    ADD COLUMN scopes     text[] NOT NULL
        DEFAULT '{links:read,links:write,stats:read}'
        CHECK (cardinality(scopes) BETWEEN 1 AND 3
               AND scopes <@ '{links:read,links:write,stats:read}'::text[]),
    ADD COLUMN expires_at timestamptz,
    ADD COLUMN rotated_to bigint UNIQUE REFERENCES api_keys (id),
    ADD CHECK (expires_at IS NULL OR expires_at > created_at);
