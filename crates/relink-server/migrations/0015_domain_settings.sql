-- Per-domain behaviour (docs/DESIGN.md, "Per-domain settings"): a custom
-- domain's root redirect, its own 404 and 410 pages, the path prefixes it
-- accepts in front of a code and whether its codes ignore case. The shape
-- is relink_core::site::DomainSettings, validated by the server before it
-- is stored; the checks here only bound what a row can hold. The edge gets
-- the same object inside the domain's `host:` record.
ALTER TABLE domains ADD COLUMN settings jsonb NOT NULL DEFAULT '{}'
    CHECK (jsonb_typeof(settings) = 'object' AND octet_length(settings::text) <= 65536);

-- Tenants change their own domains' settings; nothing else about a domain
-- becomes writable.
GRANT UPDATE (settings) ON domains TO relink_tenant;
