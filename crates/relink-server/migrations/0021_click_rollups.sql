-- Hourly and daily rollups fed from the click stream (docs/DESIGN.md,
-- "Rollups").
--
-- The flusher writes each batch of clicks once to every table below and to
-- click_events, in one transaction that first records the batch's random
-- 16-byte key in click_batches. A batch whose commit was lost to a broken
-- connection is retried with the same key; if the first attempt did commit,
-- the key is already there and the retry changes nothing, so counts are
-- never added twice.

CREATE TABLE click_batches (
    id   bytea       PRIMARY KEY CHECK (length(id) = 16),
    at   timestamptz NOT NULL DEFAULT now()
);

-- Housekeeping deletes keys older than a week; a batch is never retried
-- after its flusher has stopped.
CREATE INDEX click_batches_at ON click_batches (at);

-- Click counts per link, UTC hour and dimension: click_daily at hourly
-- resolution. workspace_id is stored so that a workspace's hours can be read
-- through one index, and so the tenant policy needs no join.
CREATE TABLE click_hourly (
    link_id        bigint      NOT NULL REFERENCES links (id) ON DELETE CASCADE,
    workspace_id   bigint      NOT NULL,
    hour           timestamptz NOT NULL CHECK (date_trunc('hour', hour) = hour),
    country        text        NOT NULL CHECK (octet_length(country) = 2),
    device         text        NOT NULL CHECK (octet_length(device) BETWEEN 1 AND 16),
    referrer_host  text        NOT NULL CHECK (octet_length(referrer_host) BETWEEN 1 AND 253),
    clicks         bigint      NOT NULL CHECK (clicks > 0),
    PRIMARY KEY (link_id, hour, country, device, referrer_host)
);

CREATE INDEX click_hourly_workspace ON click_hourly (workspace_id, hour);
-- Retention deletes by hour.
CREATE INDEX click_hourly_hour ON click_hourly (hour);

-- HyperLogLog++ sketches of the visitors of one link in one UTC hour or
-- day (relink-core/src/hll.rs, stored form). They are fed HMAC(day's salt,
-- client fingerprint), the same for every link of the instance, so sketches
-- of several links merge into the visitors of all of them; the salt changes
-- daily, so a visitor who comes back on another day counts again.
CREATE TABLE visitor_sketch_hourly (
    link_id  bigint      NOT NULL REFERENCES links (id) ON DELETE CASCADE,
    hour     timestamptz NOT NULL CHECK (date_trunc('hour', hour) = hour),
    sketch   bytea       NOT NULL CHECK (length(sketch) BETWEEN 3 AND 16384),
    PRIMARY KEY (link_id, hour)
);

CREATE INDEX visitor_sketch_hourly_hour ON visitor_sketch_hourly (hour);

CREATE TABLE visitor_sketch_daily (
    link_id  bigint NOT NULL REFERENCES links (id) ON DELETE CASCADE,
    day      date   NOT NULL,
    sketch   bytea  NOT NULL CHECK (length(sketch) BETWEEN 3 AND 16384),
    PRIMARY KEY (link_id, day)
);

GRANT SELECT ON click_hourly, visitor_sketch_hourly, visitor_sketch_daily TO relink_tenant;
ALTER TABLE click_batches         ENABLE ROW LEVEL SECURITY;
ALTER TABLE click_hourly          ENABLE ROW LEVEL SECURITY;
ALTER TABLE visitor_sketch_hourly ENABLE ROW LEVEL SECURITY;
ALTER TABLE visitor_sketch_daily  ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON click_hourly TO relink_tenant
    USING (workspace_id = relink_current_workspace());
CREATE POLICY tenant ON visitor_sketch_hourly TO relink_tenant
    USING (EXISTS (SELECT 1 FROM links l WHERE l.id = visitor_sketch_hourly.link_id
                                         AND l.workspace_id = relink_current_workspace()));
CREATE POLICY tenant ON visitor_sketch_daily TO relink_tenant
    USING (EXISTS (SELECT 1 FROM links l WHERE l.id = visitor_sketch_daily.link_id
                                         AND l.workspace_id = relink_current_workspace()));
