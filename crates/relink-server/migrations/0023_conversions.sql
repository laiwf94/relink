-- Conversion tracking (docs/DESIGN.md, "Conversions").
--
-- A link with conversion_window_days set sends every click on with a
-- signed click id, rl_cid, built by relink_core::conversion. Nothing is
-- written per click: the id itself names the link, the time and what chose
-- the URL. A destination's server posts it back with an event to
-- POST /v1/conversions, and each accepted conversion is one row here,
-- attributed to the click, its destination and its A/B variant.

ALTER TABLE links ADD COLUMN conversion_window_days smallint
    CHECK (conversion_window_days BETWEEN 1 AND 365);

-- The window is part of what a link does, so its versions keep it.
CREATE OR REPLACE FUNCTION relink_link_spec(l links) RETURNS jsonb
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$
SELECT jsonb_build_object(
    'destinations', l.destinations,
    'redirect_type', l.redirect_status,
    'expires_at', to_char(l.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'max_clicks', l.max_clicks,
    'geo', CASE WHEN l.geo_mode IS NULL THEN NULL
                ELSE jsonb_build_object('mode', l.geo_mode, 'countries', to_jsonb(l.geo_countries))
           END,
    'fallback_url', l.fallback_url,
    'enabled', l.enabled,
    'health_check', l.health_check,
    'rules', l.rules,
    'app', l.app,
    'conversion_window_days', l.conversion_window_days)
$$;

-- Versions kept so far had no window, which is what null says; without
-- the key they would differ from relink_link_spec of the same link, and
-- its next change would record a version for nothing.
UPDATE link_versions SET spec = spec || '{"conversion_window_days": null}'::jsonb
 WHERE NOT spec ? 'conversion_window_days';

-- Keys that post conversions: a server holding one can do nothing else.
-- Keys made before keep the scopes they had.
ALTER TABLE api_keys DROP CONSTRAINT api_keys_scopes_check;
ALTER TABLE api_keys ADD CONSTRAINT api_keys_scopes_check
    CHECK (cardinality(scopes) BETWEEN 1 AND 4
           AND scopes <@ '{links:read,links:write,stats:read,conversions:write}'::text[]);

ALTER TABLE links ADD CONSTRAINT links_workspace_id_key UNIQUE (workspace_id, id);

CREATE TABLE conversions (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    workspace_id   bigint      NOT NULL DEFAULT relink_current_workspace(),
    link_id        bigint      NOT NULL,
    -- The rl_cid posted, as handed out.
    click_id       text        NOT NULL CHECK (click_id ~ '^[A-Za-z0-9_-]{48}$'),
    event          text        NOT NULL CHECK (event ~ '^[A-Za-z0-9_.:-]{1,64}$'),
    -- The poster's own id for the conversion (an order number), if any.
    external_id    text        CHECK (char_length(external_id) BETWEEN 1 AND 128),
    -- In minor units of currency (cents), or a plain number without one.
    value          bigint      CHECK (value BETWEEN 0 AND 1000000000000000),
    currency       text        CHECK (currency ~ '^[A-Z]{3}$'),
    -- What chose the URL the click went to, from the click id.
    target         text        NOT NULL
                               CHECK (target IN ('destination', 'rule', 'app', 'fallback')),
    target_index   smallint    NOT NULL CHECK (target_index BETWEEN 0 AND 255),
    -- The URL, when it is still known: the link now or one of its kept
    -- versions holds a URL with the click id's hash.
    destination    text        CHECK (length(destination) <= 4096),
    clicked_at     timestamptz NOT NULL,
    occurred_at    timestamptz NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CHECK (currency IS NULL OR value IS NOT NULL),
    CHECK (target IN ('destination', 'rule') OR target_index = 0),
    -- A conversion is counted once: per event, by the poster's id when it
    -- gives one, otherwise once per click.
    dedup          text        GENERATED ALWAYS AS
                               (COALESCE('x:' || external_id, 'c:' || click_id)) STORED,
    UNIQUE (workspace_id, event, dedup),
    FOREIGN KEY (workspace_id, link_id) REFERENCES links (workspace_id, id)
        ON DELETE CASCADE
);

-- A link's conversions over a time range, for its stats.
CREATE INDEX conversions_link ON conversions (link_id, occurred_at);

DO $$
BEGIN
    EXECUTE format('GRANT USAGE ON SEQUENCE %s TO relink_tenant',
                   pg_get_serial_sequence('conversions', 'id'));
END
$$;

-- Conversions are facts: posted and read, never edited.
GRANT SELECT, INSERT ON conversions TO relink_tenant;
ALTER TABLE conversions ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant ON conversions TO relink_tenant
    USING (workspace_id = relink_current_workspace());
