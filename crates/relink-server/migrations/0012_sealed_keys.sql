-- Private keys encrypted at rest (docs/DESIGN.md, "Terminating TLS";
-- src/tls.rs).
--
-- Certificate and ACME account keys are sealed with AES-256-GCM under
-- RELINK_KEY_ENCRYPTION_KEY, which never reaches the database. A sealed key
-- is "rlk" and a version byte, a 96-bit nonce, then the ciphertext and its
-- 128-bit tag; the associated data names the row (the domain's id, the
-- account's directory), so a sealed key copied to another row does not
-- open. The checks below make it impossible to store a key that is not in
-- that form, whatever writes it.
--
-- Keys stored before this migration are plaintext. They are dropped rather
-- than kept: the ACME worker registers a new account and orders every
-- verified domain a new certificate, sealed, at its next round.

DELETE FROM acme_accounts;
DELETE FROM domain_certificates;
UPDATE domains
   SET tls_not_after = NULL, tls_renew_at = NULL, tls_next_attempt_at = NULL,
       tls_failures = 0, tls_error = NULL
 WHERE tls_renew_at IS NOT NULL OR tls_next_attempt_at IS NOT NULL;

ALTER TABLE acme_accounts RENAME COLUMN key_pkcs8 TO key_sealed;
ALTER TABLE domain_certificates RENAME COLUMN key_pkcs8 TO key_sealed;

-- 4 bytes of header, 12 of nonce, at least one of key and 16 of tag.
ALTER TABLE acme_accounts ADD CONSTRAINT acme_accounts_key_sealed
    CHECK (substring(key_sealed FROM 1 FOR 4) = '\x726c6b01'::bytea
           AND length(key_sealed) BETWEEN 33 AND 16384);
ALTER TABLE domain_certificates ADD CONSTRAINT domain_certificates_key_sealed
    CHECK (substring(key_sealed FROM 1 FOR 4) = '\x726c6b01'::bytea
           AND length(key_sealed) BETWEEN 33 AND 16384);
