-- Click lease reservation as one function call (#76).
--
-- The reservation used to be a single `UPDATE links l ... FROM (SELECT ...
-- FOR NO KEY UPDATE) o`, joining the row to a locked copy of itself so the
-- grant could be returned. Under READ COMMITTED the outer scan and the
-- subquery can reach the row's lock in different ways: the subquery locks
-- the latest version, then the outer update waits again for the tuple while
-- the row's lock is a multixact (click flushes hold key-share locks through
-- their foreign keys), and a second reservation already queued for that
-- tuple waits on the first. Postgres resolves the cycle by aborting one of
-- them, and the redirect answers 503.
--
-- Here the row is locked first, and the update runs as its own statement on
-- the version just locked, so a reservation waits at most once, for the
-- previous holder of the row lock. Still one round trip.
CREATE FUNCTION relink_reserve_clicks(p_link bigint, p_max_lease bigint) RETURNS bigint
    LANGUAGE plpgsql VOLATILE STRICT AS $$
DECLARE
    reserved bigint;
    lim      bigint;
    grant_n  bigint;
BEGIN
    -- NO KEY UPDATE rather than UPDATE, so click flushes holding key-share
    -- locks through their foreign keys never queue behind a reservation.
    SELECT clicks_reserved, max_clicks INTO reserved, lim
      FROM links WHERE id = p_link FOR NO KEY UPDATE;
    IF NOT FOUND OR lim IS NULL OR reserved >= lim THEN
        RETURN 0;
    END IF;
    -- The rule of limiter::grant_size: an eighth of what is left, at least
    -- one, at most the lease size and never more than is left.
    grant_n := LEAST(p_max_lease, GREATEST(1, (lim - reserved) / 8), lim - reserved);
    UPDATE links SET clicks_reserved = reserved + grant_n WHERE id = p_link;
    RETURN grant_n;
END
$$;

DO $$
BEGIN
    EXECUTE format('ALTER FUNCTION relink_reserve_clicks(bigint, bigint) SET search_path = %I, pg_temp',
                   current_schema());
END
$$;
REVOKE ALL ON FUNCTION relink_reserve_clicks(bigint, bigint) FROM PUBLIC;
