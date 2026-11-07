-- Custom domains (docs/DESIGN.md, "Custom domains").
--
-- A workspace adds a hostname, proves it controls it with a DNS TXT record
-- (src/domains.rs), and can then create links on it. Codes are unique per
-- domain: `abc` on go.example.com and `abc` on the default domain are two
-- links. A link with no domain_id is on the default domain, the one in
-- RELINK_PUBLIC_BASE_URL, exactly as before this migration.

CREATE TABLE domains (
    id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    workspace_id        bigint      NOT NULL DEFAULT relink_current_workspace()
                                    REFERENCES workspaces (id) ON DELETE CASCADE,
    -- Lowercase ASCII (IDNA already applied), no final dot, at least two
    -- labels; src/domains.rs applies the same rules and the public-host ones.
    hostname            text COLLATE "C" NOT NULL
                            CHECK (length(hostname) <= 253 AND hostname ~
                                   '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    -- Published by the workspace at _relink-challenge.<hostname>; not a
    -- secret, since anyone can read it from DNS once it is there.
    verification_token  text        NOT NULL CHECK (verification_token ~ '^[0-9a-f]{32}$'),
    created_by          text        NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    verified_at         timestamptz,
    -- The last verification attempt and, if it failed, why.
    checked_at          timestamptz,
    check_error         text        CHECK (length(check_error) <= 300),
    -- A workspace adds a hostname once.
    UNIQUE (workspace_id, hostname),
    -- The target of links' composite foreign key below.
    UNIQUE (workspace_id, id)
);

-- Many workspaces may claim a hostname, but only one can prove it: the
-- first verification wins and later ones conflict. Unverified claims cannot
-- block the real owner. Also the lookup for Host-based routing.
CREATE UNIQUE INDEX domains_verified_hostname ON domains (hostname) WHERE verified_at IS NOT NULL;

-- A link's domain must belong to the link's own workspace: the foreign key
-- covers both columns, so not even the table owner can attach a link to
-- another workspace's domain. A domain with links cannot be deleted.
ALTER TABLE links ADD COLUMN domain_id bigint;
ALTER TABLE links ADD CONSTRAINT links_domain_fkey
    FOREIGN KEY (workspace_id, domain_id) REFERENCES domains (workspace_id, id);

-- Codes are unique per domain, with 0 standing for the default domain
-- (identity values start at 1). The expression index serves both lookups,
-- `COALESCE(domain_id, 0) = $1 AND code = $2`, and the KV reconciliation's
-- walk of default-domain codes in order.
ALTER TABLE links DROP CONSTRAINT links_code_key;
CREATE UNIQUE INDEX links_domain_code ON links ((COALESCE(domain_id, 0)), code);

-- Plans gain a domain limit, checked when a domain is added.
ALTER TABLE plans ADD COLUMN max_domains bigint CHECK (max_domains >= 0);

-- The default-domain lookup no longer matches links on custom domains,
-- which share its codes.
CREATE OR REPLACE FUNCTION relink_link_by_code(p_code text) RETURNS SETOF links
    LANGUAGE plpgsql STABLE STRICT SECURITY DEFINER PARALLEL SAFE
    AS $$
BEGIN
    RETURN QUERY SELECT * FROM links WHERE COALESCE(domain_id, 0) = 0 AND code = p_code;
END
$$;

-- The link with this code on this verified custom domain. As narrow as the
-- default-domain lookup: one row by unique key, nothing else.
CREATE FUNCTION relink_link_by_domain_code(p_domain bigint, p_code text) RETURNS SETOF links
    LANGUAGE plpgsql STABLE STRICT SECURITY DEFINER PARALLEL SAFE
    AS $$
BEGIN
    RETURN QUERY SELECT l.* FROM links l
                  WHERE COALESCE(l.domain_id, 0) = p_domain AND l.code = p_code
                    AND EXISTS (SELECT 1 FROM domains d
                                 WHERE d.id = p_domain AND d.verified_at IS NOT NULL);
END
$$;

REVOKE ALL ON FUNCTION relink_link_by_domain_code(bigint, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION relink_link_by_domain_code(bigint, text) TO relink_redirect;

DO $$
BEGIN
    EXECUTE format('ALTER FUNCTION relink_link_by_code(text) SET search_path = %I, pg_temp',
                   current_schema());
    EXECUTE format('ALTER FUNCTION relink_link_by_domain_code(bigint, text) SET search_path = %I, pg_temp',
                   current_schema());
    EXECUTE format('GRANT USAGE ON SEQUENCE %s TO relink_tenant',
                   pg_get_serial_sequence('domains', 'id'));
END
$$;

-- Tenants add, list, verify and delete their own domains. Verification
-- only stamps its outcome; the hostname and token never change.
GRANT SELECT, INSERT, DELETE ON domains TO relink_tenant;
GRANT UPDATE (verified_at, checked_at, check_error) ON domains TO relink_tenant;

ALTER TABLE domains ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant ON domains TO relink_tenant
    USING (workspace_id = relink_current_workspace());
