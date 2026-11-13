-- Targeting rules (docs/DESIGN.md, "Targeting rules"): an ordered list of
-- relink_core::rules_v2::Rule, validated and compiled by the server before
-- it is stored, with each rule's destination normalised. The checks here
-- only bound what a row can hold. The lookup functions return links.*, so
-- the redirect role reads the column with the rest of the row, and the
-- edge gets it inside the link's KV record.
ALTER TABLE links ADD COLUMN rules jsonb NOT NULL DEFAULT '[]'
    CHECK (jsonb_typeof(rules) = 'array' AND octet_length(rules::text) <= 65536);
