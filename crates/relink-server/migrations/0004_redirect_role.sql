-- The redirect read role: the redirect path and the edge publisher look links
-- up by code and need nothing else (docs/DESIGN.md, "Tenancy").
--
-- relink_redirect holds no table privileges at all. Its only grant is EXECUTE
-- on relink_link_by_code(text), which returns the one link with that exact
-- code. A connection running as this role cannot list links, read keys or
-- statistics, or write anything, so a bug on the redirect path cannot turn
-- into a dump of every tenant's links.
--
-- The function is SECURITY DEFINER: it runs as its owner (the migrating role,
-- which owns links and is not subject to row-level security), with a fixed
-- search_path so a caller cannot substitute its own objects.

CREATE FUNCTION relink_link_by_code(p_code text) RETURNS SETOF links
    LANGUAGE plpgsql STABLE STRICT SECURITY DEFINER PARALLEL SAFE
    AS $$
BEGIN
    RETURN QUERY SELECT * FROM links WHERE code = p_code;
END
$$;

REVOKE ALL ON FUNCTION relink_link_by_code(text) FROM PUBLIC;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'relink_redirect') THEN
        BEGIN
            CREATE ROLE relink_redirect NOLOGIN NOINHERIT NOBYPASSRLS;
        EXCEPTION WHEN duplicate_object OR unique_violation THEN
            NULL;
        END;
    END IF;
    IF NOT pg_has_role(current_user, 'relink_redirect', 'MEMBER') THEN
        EXECUTE format('GRANT relink_redirect TO %I', current_user);
    END IF;
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO relink_redirect', current_schema());
    EXECUTE format('ALTER FUNCTION relink_link_by_code(text) SET search_path = %I, pg_temp',
                   current_schema());
END
$$;

GRANT EXECUTE ON FUNCTION relink_link_by_code(text) TO relink_redirect;
