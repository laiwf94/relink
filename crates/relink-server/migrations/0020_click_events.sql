-- Raw click events in monthly partitions (docs/DESIGN.md, "Raw events and
-- partitions").
--
-- One row per click, partitioned by calendar month (UTC) of the click's
-- time. Retention is whole months: the partition manager in
-- src/partitions.rs keeps the current month and the months after it ready,
-- and drops a month's partition once it is older than
-- RELINK_CLICK_EVENTS_RETENTION_MONTHS, which frees its space at once with
-- no DELETE, no dead tuples and no vacuum.
--
-- Like the aggregates, events never hold a client address: `visitor` is the
-- same HMAC(daily salt, link, fingerprint) as visitor_daily, and once the
-- day's salt is destroyed (after two days) it cannot be linked back to an
-- address by anyone, the database's owner included.
--
-- There is no foreign key to links: a cascading delete would have to search
-- every partition, and a key would make each insert check links. Events of
-- a deleted link leave with their month.

CREATE TABLE click_events (
    at             timestamptz NOT NULL,
    workspace_id   bigint      NOT NULL,
    link_id        bigint      NOT NULL,
    -- NULL for the default domain.
    domain_id      bigint,
    country        text        NOT NULL CHECK (octet_length(country) = 2),
    device         text        NOT NULL CHECK (octet_length(device) BETWEEN 1 AND 16),
    -- '(direct)' when the request had no usable referrer, as in click_daily.
    referrer_host  text        NOT NULL CHECK (octet_length(referrer_host) BETWEEN 1 AND 253),
    visitor        bytea       CHECK (length(visitor) = 16),
    bot            boolean     NOT NULL DEFAULT false
) PARTITION BY RANGE (at);

-- One link's events over a time range, and the tenant policy's predicate
-- with a range; both exist on every partition.
CREATE INDEX click_events_link ON click_events (link_id, at);
CREATE INDEX click_events_workspace ON click_events (workspace_id, at);

-- Creates the partition for the month that contains p_month, unless it
-- exists. Returns true when it was created. Bounds are written in UTC with
-- an explicit offset, so they do not depend on the session's time zone.
-- Called by this migration and by the partition manager, which holds an
-- advisory lock so instances never race to create the same month.
CREATE FUNCTION relink_click_events_partition(p_month date) RETURNS boolean
    LANGUAGE plpgsql STRICT
    AS $$
DECLARE
    first date := date_trunc('month', p_month)::date;
    name  text := 'click_events_p' || to_char(first, 'YYYYMM');
BEGIN
    IF to_regclass(quote_ident(name)) IS NOT NULL THEN
        RETURN false;
    END IF;
    EXECUTE format('CREATE TABLE %I PARTITION OF click_events FOR VALUES FROM (%L) TO (%L)',
                   name,
                   to_char(first, 'YYYY-MM-DD') || ' 00:00:00+00',
                   to_char((first + interval '1 month')::date, 'YYYY-MM-DD') || ' 00:00:00+00');
    RETURN true;
END
$$;

REVOKE ALL ON FUNCTION relink_click_events_partition(date) FROM PUBLIC;

-- The current month and the two after it, as the partition manager keeps.
SELECT relink_click_events_partition((date_trunc('month', now() AT TIME ZONE 'UTC') + make_interval(months => m))::date)
  FROM generate_series(0, 2) AS m;

-- Tenants read events of their own workspace through the parent table only:
-- grants and policies are not inherited by partitions, and relink_tenant
-- holds no grant on any partition, so it cannot reach one directly.
GRANT SELECT ON click_events TO relink_tenant;
ALTER TABLE click_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant ON click_events TO relink_tenant
    USING (workspace_id = relink_current_workspace());
