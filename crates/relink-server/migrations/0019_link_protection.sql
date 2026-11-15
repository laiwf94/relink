-- Protected links (docs/DESIGN.md, "Protected links"): a password, a
-- consent page, or both, in front of the redirect.
--
-- password_hash is an argon2id hash in PHC form, written by the server
-- (src/protect.rs) and never returned by the API, the audit log or the
-- edge records. password_attempts is how many wrong passwords the link
-- accepts per hour, and is set exactly when there is a password. consent is
-- the text a visitor agrees to, already validated by the server; the check
-- here only bounds what a row can hold. The lookup functions return
-- links.*, so the redirect role reads all three with the rest of the row.
ALTER TABLE links
    ADD COLUMN password_hash text
        CHECK (octet_length(password_hash) <= 256 AND password_hash LIKE '$argon2id$%'),
    ADD COLUMN password_attempts integer
        CHECK (password_attempts BETWEEN 1 AND 1000),
    ADD COLUMN consent text
        CHECK (char_length(consent) BETWEEN 1 AND 1000),
    ADD CONSTRAINT links_password_attempts
        CHECK ((password_hash IS NULL) = (password_attempts IS NULL));

-- Password attempts per link in the current one-hour window, shared by
-- every instance. A row exists once a link has been tried.
CREATE TABLE link_password_attempts (
    link_id      bigint      PRIMARY KEY REFERENCES links (id) ON DELETE CASCADE,
    window_start timestamptz NOT NULL,
    attempts     integer     NOT NULL CHECK (attempts >= 0)
);

-- Takes one attempt for link p_link, whose limit is p_limit an hour:
-- returns 0 when the attempt may go ahead, otherwise the seconds until the
-- window ends and attempts are allowed again. The row is locked for the
-- decision, so instances racing for the last attempt cannot both win, and
-- an attempt is taken before the password is checked, so at most p_limit
-- hashes are computed per link per hour. A right password gives its
-- attempt back (relink_password_refund), so only wrong ones use the limit.
CREATE FUNCTION relink_password_attempt(p_link bigint, p_limit integer) RETURNS integer
    LANGUAGE plpgsql VOLATILE STRICT AS $$
DECLARE
    started timestamptz;
    used    integer;
BEGIN
    INSERT INTO link_password_attempts (link_id, window_start, attempts)
        VALUES (p_link, now(), 0)
        ON CONFLICT (link_id) DO NOTHING;
    SELECT window_start, attempts INTO started, used
      FROM link_password_attempts WHERE link_id = p_link FOR UPDATE;
    IF started <= now() - interval '1 hour' THEN
        started := now();
        used := 0;
    END IF;
    IF used >= p_limit THEN
        RETURN GREATEST(1, ceil(extract(epoch FROM started + interval '1 hour' - now()))::integer);
    END IF;
    UPDATE link_password_attempts SET window_start = started, attempts = used + 1
     WHERE link_id = p_link;
    RETURN 0;
END
$$;

CREATE FUNCTION relink_password_refund(p_link bigint) RETURNS void
    LANGUAGE sql VOLATILE STRICT AS $$
UPDATE link_password_attempts SET attempts = GREATEST(attempts - 1, 0) WHERE link_id = p_link;
$$;

DO $$
BEGIN
    EXECUTE format('ALTER FUNCTION relink_password_attempt(bigint, integer) SET search_path = %I, pg_temp',
                   current_schema());
    EXECUTE format('ALTER FUNCTION relink_password_refund(bigint) SET search_path = %I, pg_temp',
                   current_schema());
END
$$;
REVOKE ALL ON FUNCTION relink_password_attempt(bigint, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION relink_password_refund(bigint) FROM PUBLIC;
