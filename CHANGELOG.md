# Changelog

Notable changes to relink, newest first. Each roadmap week is one entry; its
issue has the details of every task.

## Unreleased

### Week 2 (2026-11-09 to 2026-11-15): custom domains, verification, automatic TLS and per-domain behaviour (#23)

Added:

- **Custom domains.** A workspace adds a hostname and proves it with a DNS
  TXT record at `_relink-challenge.<hostname>` (migration 0010). relink asks
  only its configured resolvers (`RELINK_DNS_SERVERS`, or
  `/etc/resolv.conf`) with its own small RFC 1035 client and never connects
  to the domain. The first workspace to prove a hostname gets it. Codes are
  unique per domain, and a verified host routes codes on that domain only,
  on every instance. New routes: `POST/GET /v1/domains`,
  `GET/PATCH/DELETE /v1/domains/{hostname}` and
  `POST /v1/domains/{hostname}/verify`. Links take `domain` on create and
  `?domain=` on the per-link routes. Plans limit domains (`max_domains`,
  `relink plan-set --domains`), and `/v1/usage` reports them.
- **Certificates from relink's own ACME client.** An RFC 8555 client in
  `src/acme.rs` signs with `ring`, answers HTTP-01 on every instance, and
  renews at two thirds of a certificate's lifetime, with back-off after
  failures (migration 0011). Domains show their certificate state. New
  settings: `RELINK_ACME_DIRECTORY`, `RELINK_ACME_EMAIL`,
  `RELINK_ACME_INTERVAL_MS` and `RELINK_ACME_ORDER_TIMEOUT_S`.
- **TLS termination.** `RELINK_TLS_ADDR` serves the public routes over
  rustls, with each domain's certificate chosen by SNI and renewals swapped
  in without a restart. An optional default certificate comes from
  `RELINK_TLS_CERT_FILE` and `RELINK_TLS_KEY_FILE`. Certificate and ACME
  account keys are sealed with AES-256-GCM under
  `RELINK_KEY_ENCRYPTION_KEY`, and Postgres refuses unsealed keys
  (migration 0012).
- **Custom domains at the edge.** The KV sync publishes `host:<hostname>`
  and `link:<hostname>/<code>` records (migration 0013). With
  `RELINK_KV_ZONE_ID` set, it also registers each verified domain as a
  Cloudflare custom hostname. The Worker routes by `Host` the way the
  origin does and forwards the host it routed by in `x-forwarded-host`,
  which the origin trusts only from `RELINK_TRUSTED_PROXIES`.
- **Per-domain settings.** Each domain can have a root redirect, its own
  404 and 410 pages, path prefixes such as `/campaign/<code>` and
  case-insensitive codes (migration 0015). `relink_core::site` decides what
  a path means, for the origin and the Worker alike.
- **End to end.** `tests/custom_domains.rs` walks the whole week on two
  instances: the plan limit, the TXT proof, a certificate from a local ACME
  CA served over TLS and renewed live, the domain's settings over TLS, the
  edge's own logic in front of the origin giving the same answers, and
  deletion. `examples/demo.sh` has a new step for a domain proved against a
  one-record DNS server (`examples/txt-dns.py`), with its own codes and
  pages.
- **Tests and fuzzing.** A property test requires the origin and the edge
  to give the same response to random hosts and paths over random domains,
  settings and links. The new fuzz target `host` checks Host and hostname
  parsing.

Changed:

- The KV outbox holds whole KV keys rather than codes (migration 0013).
- Reserving click leases locks the row before updating it
  (migration 0014).

Fixed:

- Origin and edge disagreed on three requests the property test found. The
  Worker forwarded a listed `Host` raw. `host_part` and `parse_hostname`
  accepted names ending in two dots.
- Concurrent click lease reservations could deadlock against click flushes
  and answer 503 (#76).
- A forwarded hop that did not parse was skipped. relink then trusted the
  client-written entries to its left, when it should stop at that hop (#77).
- The DNS fallback test could fail with `AddrInUse` (#75).
- `cargo audit` flagged `libsqlite3-sys`, which is only in Cargo.lock. The
  advisory is ignored with its reason, and CI now fails if SQLite is ever
  built (#78).

### Week 1 (2026-11-02 to 2026-11-08): workspaces, roles, console sign-in, audit and quotas (#22)

Added:

- **Workspaces.** Every link, API key and statistic belongs to one workspace
  (migration 0003; existing rows moved into one personal workspace per
  owner). Postgres row-level security, keyed on a transaction-local
  `relink.workspace_id`, keeps tenants apart: a query run as `relink_tenant`
  without a workspace sees no rows. Every management query runs in a tenant
  transaction (`src/tenant.rs`), and redirects look links up through
  `relink_redirect`, a role that can only call the code lookup (migration
  0004).
- **Roles and scoped keys.** Members are owners, admins, editors or viewers.
  API keys carry the scopes `links:read`, `links:write` and `stats:read`,
  bounded by their owner's current role, plus an optional expiry. They are
  rotated with an overlap window (migration 0005). New commands:
  `create-key ... --workspace --scopes --expires-in` and
  `rotate-key ID --overlap`.
- **Console sign-in.** Sign-in works with any OpenID Connect provider:
  authorization code with PKCE, and RS256 or ES256 ID tokens checked with
  `ring`. Sessions are stored in Postgres, HttpOnly, with CSRF tokens
  (migration 0006). New routes: `/v1/auth/login`, `/v1/auth/callback`,
  `/v1/auth/session` and `/v1/auth/logout`.
- **Audit log.** One hash-chained, append-only chain per workspace
  (migration 0007). The chain is kept by a database trigger. It records link,
  key, workspace, user, session, plan and invitation changes with before and
  after states. `relink audit-verify [--workspace] [--anchors]` recomputes
  every hash.
- **Plans and quotas.** Plans limit links and monthly clicks (migration
  0008). Clicks are metered in the same transaction that writes the
  statistics. A workspace over a limit gets the stable error
  `quota_exceeded`; redirects are never refused. New: `GET /v1/usage` and
  the commands `plan-set`, `plan-assign` and `plan-list`.
- **Invitations.** Admins and owners invite people by email or member name
  with a role (migration 0009). Each invitation is a one-time link that only
  the person invited can accept, before it expires. Invitations can be
  revoked, every step is audited, and a workspace has at most 100 pending.
- **End to end.** `tests/workspaces.rs` walks the whole week through the
  real sign-in flow, the HTTP API and the binary. `examples/demo.sh` has a
  new step for scoped and rotated keys, workspace isolation, a plan limit and
  audit verification.

Changed:

- Links belong to their workspace rather than to the key owner who created
  them; `links.owner` still records the creator.
- The plan's domain limit moved to week 2 (#23), where domains are created.

Fixed:

- The limiter property test now allows the escrow undershoot the design
  permits across instances (#74).
