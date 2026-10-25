-- relink schema, version 1. Applied by the binary at start-up (embedded with
-- sqlx::migrate!). Index choices are explained in docs/DESIGN.md.

CREATE TABLE api_keys (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    owner       text        NOT NULL CHECK (owner ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
    name        text        NOT NULL DEFAULT '' CHECK (length(name) <= 100),
    key_hash    bytea       NOT NULL UNIQUE CHECK (length(key_hash) = 32),
    created_at  timestamptz NOT NULL DEFAULT now(),
    revoked_at  timestamptz
);

CREATE TABLE links (
    id                    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code                  text COLLATE "C" NOT NULL UNIQUE
                              CHECK (code ~ '^[A-Za-z0-9_-]{3,64}$'),
    owner                 text        NOT NULL,
    destinations          jsonb       NOT NULL CHECK (jsonb_typeof(destinations) = 'array'
                                                AND jsonb_array_length(destinations) BETWEEN 1 AND 10),
    destinations_version  integer     NOT NULL DEFAULT 1,
    redirect_status       smallint    NOT NULL DEFAULT 302
                              CHECK (redirect_status IN (301, 302, 307, 308)),
    expires_at            timestamptz,
    max_clicks            bigint      CHECK (max_clicks > 0),
    clicks_reserved       bigint      NOT NULL DEFAULT 0 CHECK (clicks_reserved >= 0),
    geo_mode              text        CHECK (geo_mode IN ('allow', 'deny')),
    geo_countries         text[]      NOT NULL DEFAULT '{}',
    fallback_url          text,
    enabled               boolean     NOT NULL DEFAULT true,
    health_check          boolean     NOT NULL DEFAULT false,
    health_failures       smallint[]  NOT NULL DEFAULT '{}',
    health_checked_at     timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CHECK ((geo_mode IS NULL) = (cardinality(geo_countries) = 0))
);

-- Owner listing with keyset pagination: WHERE owner = $1 AND id < $2 ORDER BY id DESC.
CREATE INDEX links_owner_id ON links (owner, id DESC);

-- Health worker: the next links due for a check, oldest first. Partial, so
-- links without health checks cost nothing.
CREATE INDEX links_health_due ON links (health_checked_at NULLS FIRST)
    WHERE health_check AND enabled;

-- Click counts aggregated per link, UTC day and dimension. One row per
-- distinct combination; the flusher adds to it with ON CONFLICT.
CREATE TABLE click_daily (
    link_id        bigint   NOT NULL REFERENCES links (id) ON DELETE CASCADE,
    day            date     NOT NULL,
    country        text     NOT NULL,
    device         text     NOT NULL,
    referrer_host  text     NOT NULL,
    clicks         bigint   NOT NULL CHECK (clicks >= 0),
    PRIMARY KEY (link_id, day, country, device, referrer_host)
);

-- Visitor hashes for unique counts: HMAC(daily salt, link, client) truncated
-- to 16 bytes. Kept only while the day's salt exists, then rolled up.
CREATE TABLE visitor_daily (
    link_id  bigint NOT NULL REFERENCES links (id) ON DELETE CASCADE,
    day      date   NOT NULL,
    visitor  bytea  NOT NULL CHECK (length(visitor) = 16),
    PRIMARY KEY (link_id, day, visitor)
);

-- Rolled-up unique visitor counts for days whose salt has been destroyed.
CREATE TABLE visitor_rollup (
    link_id   bigint NOT NULL REFERENCES links (id) ON DELETE CASCADE,
    day       date   NOT NULL,
    visitors  bigint NOT NULL CHECK (visitors >= 0),
    PRIMARY KEY (link_id, day)
);

-- Random per-day salts. Deleting a salt makes that day's visitor hashes
-- impossible to link back to an address, even for someone holding the database.
CREATE TABLE visitor_salts (
    day   date  PRIMARY KEY,
    salt  bytea NOT NULL CHECK (length(salt) = 32)
);
