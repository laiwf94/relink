-- Certificates for custom domains from an ACME certificate authority
-- (docs/DESIGN.md, "Certificates"; src/acme.rs).
--
-- Only the server's own role reads or writes these tables: tenants never
-- see account keys or certificate keys. A domain's certificate state that
-- tenants may see (expiry, renewal, the last error) is in columns on
-- domains, written in the same transaction as the certificate.

-- One account per CA directory, shared by every instance. The key is the
-- one that signs every request to the CA as this account.
CREATE TABLE acme_accounts (
    directory_url text        PRIMARY KEY CHECK (length(directory_url) <= 2048),
    account_url   text        NOT NULL CHECK (length(account_url) <= 2048),
    key_pkcs8     bytea       NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- HTTP-01 challenges being validated. Any instance may be the one the CA
-- reaches, so each one answers from this table (through a copy in memory,
-- refreshed by a change notification). Not secret: the CA fetches the key
-- authorization over plain HTTP.
CREATE TABLE acme_challenges (
    token             text COLLATE "C" PRIMARY KEY CHECK (token ~ '^[A-Za-z0-9_-]{22,128}$'),
    hostname          text COLLATE "C" NOT NULL CHECK (length(hostname) <= 253),
    key_authorization text        NOT NULL CHECK (length(key_authorization) <= 300),
    expires_at        timestamptz NOT NULL
);

-- The current certificate of each domain: the chain as the CA sent it,
-- leaf first, and the leaf's private key. Replaced on renewal.
CREATE TABLE domain_certificates (
    domain_id   bigint      PRIMARY KEY REFERENCES domains (id) ON DELETE CASCADE,
    chain_pem   text        NOT NULL CHECK (length(chain_pem) <= 65536),
    key_pkcs8   bytea       NOT NULL,
    not_before  timestamptz NOT NULL,
    not_after   timestamptz NOT NULL CHECK (not_after > not_before),
    -- Two thirds of the way from not_before to not_after.
    renew_at    timestamptz NOT NULL,
    issued_at   timestamptz NOT NULL DEFAULT now()
);

-- Issuance state per domain. tls_renew_at NULL means no certificate yet;
-- tls_next_attempt_at is both the claim lease while an instance is
-- ordering and the back-off after a failure.
ALTER TABLE domains
    ADD COLUMN tls_not_after       timestamptz,
    ADD COLUMN tls_renew_at        timestamptz,
    ADD COLUMN tls_next_attempt_at timestamptz,
    ADD COLUMN tls_failures        integer NOT NULL DEFAULT 0 CHECK (tls_failures >= 0),
    ADD COLUMN tls_checked_at      timestamptz,
    ADD COLUMN tls_error           text CHECK (length(tls_error) <= 300);

-- The worker's claim: verified domains due for a certificate.
CREATE INDEX domains_tls_due ON domains (tls_next_attempt_at NULLS FIRST, id)
    WHERE verified_at IS NOT NULL;
