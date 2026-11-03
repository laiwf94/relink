-- The audit log: every change made by a person or an operator, one
-- hash chain per workspace (docs/DESIGN.md, "Audit log").
--
-- Rows are written in the same transaction as the change they describe, so
-- a change is logged exactly when it commits. The chain is computed here, by
-- a trigger, so no writer can get it wrong or skip it; `relink audit-verify`
-- recomputes it independently in Rust (src/audit.rs).
--
-- Entry n of a workspace has
--
--   hash = SHA-256('relink-audit-v1' || prev_hash || be64(workspace_id)
--                  || be64(seq) || be64(at in microseconds since 1970)
--                  || f(actor) || f(via) || f(action) || f(target)
--                  || f(before::text) || f(after::text))
--
-- where prev_hash is entry n-1's hash (32 zero bytes for n = 1), f(NULL) is
-- the byte 0x00 and f(s) is 0x01 || be32(octet length) || the UTF-8 bytes.
-- `before` and `after` are hashed in jsonb's own text form, which Postgres
-- produces deterministically (keys sorted, no insignificant whitespace), so
-- a dump and restore keeps every hash valid.

CREATE TABLE audit_log (
    -- No foreign key: the record of a workspace outlives the workspace.
    workspace_id  bigint      NOT NULL DEFAULT relink_current_workspace(),
    seq           bigint      NOT NULL CHECK (seq >= 1),
    at            timestamptz NOT NULL DEFAULT now(),
    -- The member who acted, or NULL for an operator or the server itself.
    actor         text        CHECK (actor ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
    -- How they acted: key:<id>, session:<user id>, cli or system.
    via           text        NOT NULL CHECK (via ~ '^(key:[1-9][0-9]{0,18}|session:[1-9][0-9]{0,18}|cli|system)$'),
    action        text        NOT NULL CHECK (action ~ '^[a-z]+\.[a-z_]+$'),
    -- What was acted on, like link:<id> or key:<id>.
    target        text        NOT NULL CHECK (length(target) BETWEEN 1 AND 200),
    before        jsonb,
    after         jsonb,
    prev_hash     bytea       NOT NULL CHECK (length(prev_hash) = 32),
    hash          bytea       NOT NULL CHECK (length(hash) = 32),
    PRIMARY KEY (workspace_id, seq)
);

-- The last entry of each chain. Taking the next sequence number locks this
-- row until the writing transaction ends, which orders a workspace's
-- entries; different workspaces never wait for each other. It also lets the
-- verifier notice entries removed from the end of a chain.
CREATE TABLE audit_heads (
    workspace_id  bigint PRIMARY KEY,
    seq           bigint NOT NULL CHECK (seq >= 1),
    hash          bytea  NOT NULL CHECK (length(hash) = 32)
);

-- f() above.
CREATE FUNCTION relink_audit_field(v text) RETURNS bytea
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    AS $$ SELECT CASE WHEN v IS NULL THEN '\x00'::bytea
                      ELSE '\x01'::bytea || int4send(octet_length(convert_to(v, 'UTF8')))
                           || convert_to(v, 'UTF8') END $$;

-- Fills in seq, at, prev_hash and hash, whatever the writer supplied. Runs
-- as the table owner (SECURITY DEFINER), so the tenant role needs no access
-- to audit_heads; its search_path is pinned below, as for
-- relink_link_by_code in migration 0004.
CREATE FUNCTION relink_audit_chain() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    AS $$
DECLARE
    head record;
BEGIN
    IF NEW.workspace_id IS NULL THEN
        RAISE EXCEPTION 'an audit entry needs a workspace' USING ERRCODE = 'not_null_violation';
    END IF;
    -- One statement, so concurrent first entries of a workspace serialise on
    -- the conflict instead of both starting a chain. RETURNING shows the row
    -- after the update, whose hash is still the previous entry's.
    INSERT INTO audit_heads AS h (workspace_id, seq, hash)
         VALUES (NEW.workspace_id, 1, '\x0000000000000000000000000000000000000000000000000000000000000000')
    ON CONFLICT (workspace_id) DO UPDATE SET seq = h.seq + 1
    RETURNING h.seq, h.hash INTO head;
    NEW.seq := head.seq;
    NEW.prev_hash := head.hash;
    NEW.at := now();
    NEW.hash := sha256(
        convert_to('relink-audit-v1', 'UTF8')
        || NEW.prev_hash
        || int8send(NEW.workspace_id)
        || int8send(NEW.seq)
        || int8send((extract(epoch FROM NEW.at) * 1000000)::bigint)
        || relink_audit_field(NEW.actor)
        || relink_audit_field(NEW.via)
        || relink_audit_field(NEW.action)
        || relink_audit_field(NEW.target)
        || relink_audit_field(NEW.before::text)
        || relink_audit_field(NEW.after::text));
    UPDATE audit_heads SET hash = NEW.hash WHERE workspace_id = NEW.workspace_id;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION relink_audit_chain() FROM PUBLIC;

DO $$
BEGIN
    EXECUTE format('ALTER FUNCTION relink_audit_chain() SET search_path = %I, pg_temp',
                   current_schema());
END
$$;

CREATE TRIGGER audit_chain BEFORE INSERT ON audit_log
    FOR EACH ROW EXECUTE FUNCTION relink_audit_chain();

-- Append-only. The owner could drop these triggers; that is what the chain
-- is for.
CREATE FUNCTION relink_audit_append_only() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'the audit log is append-only' USING ERRCODE = 'insufficient_privilege';
END
$$;

CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION relink_audit_append_only();
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION relink_audit_append_only();
CREATE TRIGGER audit_heads_no_truncate BEFORE TRUNCATE ON audit_heads
    FOR EACH STATEMENT EXECUTE FUNCTION relink_audit_append_only();

-- A tenant transaction may append to and read its own workspace's chain.
GRANT SELECT, INSERT ON audit_log TO relink_tenant;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant ON audit_log TO relink_tenant
    USING (workspace_id = relink_current_workspace());
