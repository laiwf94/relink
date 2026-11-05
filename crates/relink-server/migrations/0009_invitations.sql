-- Invitations: how a person joins a workspace (docs/DESIGN.md,
-- "Invitations").
--
-- An admin or owner invites someone by email address or by member name,
-- with a role. The invitation is a one-time link carrying a random token
-- (`rli_` and 64 hex characters); only its SHA-256 is stored, like an API
-- key's. It is accepted at most once, by a signed-in person who is the one
-- invited (a verified address equal to the invited one, or that member
-- name), before it expires; until then it can be revoked.
--
-- Creating, listing and revoking run in tenant transactions, so row-level
-- security keeps them inside the workspace. Accepting cannot: the person is
-- not a member yet, and the token is how the workspace is found. It runs as
-- the server's own role, like key lookups.

-- Whether users.email is an address the provider says it verified. Unknown
-- (false) for people who signed in before this migration, until they sign
-- in again.
ALTER TABLE users ADD COLUMN email_verified boolean NOT NULL DEFAULT false;

CREATE TABLE invitations (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    workspace_id    bigint      NOT NULL DEFAULT relink_current_workspace()
                                REFERENCES workspaces (id) ON DELETE CASCADE,
    token_hash      bytea       NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    -- Exactly one of the two says who is invited. Addresses are stored in
    -- lower case and compared that way.
    email           text        CHECK (length(email) BETWEEN 3 AND 320 AND email = lower(email)),
    member          text        CHECK (member ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
    role            text        NOT NULL CHECK (role IN ('owner', 'admin', 'editor', 'viewer')),
    invited_by      text        NOT NULL CHECK (invited_by ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    accepted_at     timestamptz,
    accepted_by     bigint      REFERENCES users (id) ON DELETE SET NULL,
    accepted_member text        CHECK (accepted_member ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
    revoked_at      timestamptz,
    revoked_by      text        CHECK (revoked_by ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
    CHECK (num_nonnulls(email, member) = 1),
    CHECK (expires_at > created_at),
    CHECK ((accepted_at IS NULL) = (accepted_member IS NULL)),
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL)),
    -- Used or withdrawn, never both.
    CHECK (accepted_at IS NULL OR revoked_at IS NULL)
);

-- Listing, newest first, and the policy's own predicate.
CREATE INDEX invitations_workspace ON invitations (workspace_id, id DESC);

DO $$
BEGIN
    EXECUTE format('GRANT USAGE ON SEQUENCE %s TO relink_tenant',
                   pg_get_serial_sequence('invitations', 'id'));
END
$$;

-- No DELETE: an invitation is revoked, not erased, so the list shows it.
GRANT SELECT, INSERT, UPDATE ON invitations TO relink_tenant;
ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant ON invitations TO relink_tenant
    USING (workspace_id = relink_current_workspace());
