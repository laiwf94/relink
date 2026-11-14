-- Mobile deep links (docs/DESIGN.md, "Deep links"): where a link sends
-- phones instead of its destinations, a relink_core::deeplink::AppLink
-- validated by the server before it is stored. NULL for none. The check
-- here only bounds what a row can hold. The lookup functions return
-- links.*, so the redirect role reads the column with the rest of the row,
-- and the edge gets it inside the link's KV record.
ALTER TABLE links ADD COLUMN app jsonb
    CHECK (jsonb_typeof(app) = 'object' AND octet_length(app::text) <= 8192);
