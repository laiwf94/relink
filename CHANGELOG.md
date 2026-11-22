# Changelog

Notable changes to relink, newest first. Each roadmap week is one entry; its
issue has the details of every task.

## Unreleased

### Week 4 (2026-11-23 to 2026-11-29): raw events, HyperLogLog++, the query API, bots and live clicks (#25)

Added:

- **Raw click events.** Every click is one row of `click_events`: time,
  workspace, link, domain, country, device class, referrer host, the
  day-salted visitor hash and a bot flag. No column holds an address. The
  table is partitioned by UTC calendar month (`click_events_pYYYYMM`,
  migration 0020). The partition manager in `src/partitions.rs` keeps the
  current month and the two after it created and drops months past
  `RELINK_CLICK_EVENTS_RETENTION_MONTHS` (default 13) whole. It runs once a
  minute on one instance at a time and gives way after a second to a long
  query.
- **HyperLogLog++ sketches** in `relink_core::hll`: a sparse form that is
  exact but for 25-bit collisions, a dense form of 16,384 six-bit
  registers, Ertl's improved estimator, and a canonical stored form. Merged
  sketches are byte for byte the sketch of the union. Dense sketches from
  3,500 to 1,000,000 items are off by 0.65% RMS (the target is 1%).
- **Rollups fed from one replay-safe flush.** Each batch writes the daily
  and new hourly counts, the quota meter, visitor hashes, hourly and daily
  visitor sketches and raw events in one transaction, keyed so that a
  retried batch whose commit landed writes nothing again (migration 0021).
  Raw events have their own memory bound (`RELINK_CLICK_EVENT_BACKLOG`),
  and hourly rows are kept for `RELINK_CLICK_HOURLY_RETENTION_DAYS`
  (default 92).
- **`GET /v1/analytics`.** Series by hour, day, ISO week, month or `all`,
  the top N groups by up to three of link, country, device and referrer,
  filters on each, and `compare=previous` or `year`, over at most 366 days.
  Unique visitors are the merged sketches, given when grouping and
  filtering by link only. `RELINK_ANALYTICS_MAX_ROWS` (default 1,000,000)
  caps the rows one query reads, past which it gets 422
  `query_too_expensive`. Answers come from one read-only snapshot. 30 days
  by day grouped by country reads 60,000 rows in 60 ms.
- **Bots and link previews.** `relink_core::classify::bot_kind` tells
  crawlers, link-preview fetchers, monitors and tools from people by a
  versioned list of 91 tokens (`BOT_LIST_VERSION` 1). In-app browsers count
  as people. A bot's click is counted under device class `bot` but never
  feeds a visitor hash or a sketch. The analytics API leaves bots out
  unless asked for with `include_bots=true`, and reports the list version.
- **Live clicks.** `GET /v1/links/{code}/live` is a server-sent events
  stream of a link's clicks: time, country, device, referrer and the bot
  flag, never the address. Clicks reach it from redirects at any instance
  (relayed over `pg_notify`) and from edge batches. Each workspace's
  channel is a ring of 256 clicks, so a slow stream falls behind alone and
  is told how many it missed. Streams are capped at 50 per workspace and
  10,000 per instance, and each ends after an hour.
- **End to end.** `tests/click_analytics.rs` walks the whole week on two
  instances:
  - two days of edge batches for two links that share 300 people
  - live streams on one instance that get each click within a second,
    from either instance and from the edge
  - people, a crawler and two link previews over HTTP
  - the query API answering alike at both instances, with unique visitors
    within 1% of the exact count per link, per day and over both
  - raw events in their month's partition with no address in any value
  - an old month dropped while the rollups keep their counts
  - another workspace seeing none of it

  `examples/demo.sh` has a new step 8 showing the same from the command
  line.

Changed:

- Edge clicks carry only a day, so the origin places each at the time it
  arrived, kept within the reported day. `ClickEvent` has `at_ms` instead
  of `day`.
- Targeting rules on `device: ["bot"]` use the new classification, at the
  origin and the edge. `device_class` on a browser User-Agent went from
  153 ns to 222 ns, and the Worker bundle from 247,017 to 249,111 bytes
  gzipped.
- 100,000 worst-case clicks now drain in 7.9 s instead of 3.5 s, mostly
  for the raw events.
- `futures-util` is a direct dependency. It was already in the tree.

Fixed:

- The outage test's set-up could fail while its first database connection
  was still opening; it now retries (#82).
- The session clean-up test raced the instance's own housekeeping (#80).
- Dropping each test database forced a checkpoint that stalled other tests
  under CI (#83).
- `rustix` was updated to 1.1.6 for RUSTSEC-2026-0486, and the chrono
  "unmaintained" advisory is listed in `deny.toml` so other advisories
  still fail the build (#81).
- The demo's visits sent curl's own User-Agent, which is now a bot, so its
  stats showed no visitors (#84).
- A hostname ending in two dots and a character IDNA ignores, such as
  `kk26kkk26k.0X0..` with U+034F after it, was stored in a form that adding
  it again refused. Final dots are now counted on the parsed host, and the
  stored form must parse back to itself (#85).

### Week 3 (2026-11-16 to 2026-11-22): targeting rules, deep links, versions, schedules and protected links (#24)

Added:

- **Targeting rules.** Links take `rules`: an ordered list of
  `{"if": condition, "url": ...}`. Conditions combine `all`, `any` and
  `not` over country, ISO 3166-2 region, device, OS, browser, preferred
  language, referrer host, time window (instants, weekdays and hours at a
  UTC offset) and query parameters. `relink_core::rules_v2` compiles a list
  to a flat decision list with forward jumps only. A list may hold at most
  64 leaf conditions, so no visit tests more than 64. The API refuses a bad
  list with the JSON path of the part at fault (migration 0016).
- **Rules on the redirect path, at the origin and the edge.** The origin
  compiles a link's rules once, when the row enters its cache. KV records
  carry the compiled decision list, which the Worker checks but never
  compiles. Both read the same facts: region (`RELINK_REGION_HEADER`,
  trusted only from `RELINK_TRUSTED_PROXIES`), User-Agent,
  Accept-Language, Referer and the query string, which the Worker now
  forwards. Answers from links with rules are `no-store`. A one-leaf list
  takes about 26 ns; the worst case, 64 leaves with every fact read, takes
  about 0.8 µs.
- **Mobile deep links.** Custom domains take `apps` and serve
  `apple-app-site-association` (at both paths) and `assetlinks.json` for
  them. Links take `app` targets: iPhones and iPads go to the App Store, and
  Android browsers get an intent URL that opens the app or falls back to
  the store. The origin and the edge both do this, and the Worker reads
  only the pre-built `Location` values and files (migration 0017).
- **Version history and schedules.** Every change to a link is a version,
  built by the database in the same transaction (the newest 100 are kept).
  New routes: `GET /v1/links/{code}/versions`,
  `POST /v1/links/{code}/rollback`, and `POST/GET/DELETE` on
  `/v1/links/{code}/schedules`, which swap destinations or enable or
  disable a link at a set time. A scheduler on every instance applies each
  change exactly once, using `FOR UPDATE SKIP LOCKED`, and applies changes
  that fell due during a database outage once it is back
  (`RELINK_SCHEDULE_POLL_MS`, migration 0018).
- **Protected links.** `protection` sets a password, a consent text or
  both. Passwords are hashed with argon2id (19 MiB, t=2), with at most two
  hashes at once. Wrong guesses are limited per link per hour across
  instances (`max_attempts`, default 10), after which the link answers 429.
  A signed grant cookie lets the visitor through, and any change of
  password or text revokes it. Protected links are never published to KV,
  so the edge forwards their forms to the origin (migration 0019).
- **Previews.** `/{code}+` shows where a link goes without a click, at the
  origin and rendered from KV at the edge. A protected link's preview says
  only that it is protected.
- **End to end.** `tests/smart_links.rs` walks the whole week on two
  instances, with the edge's own request logic in front of them:
  - association files
  - 16 kinds of visitor routed alike by rules and app targets
  - an edit, a scheduled swap that both schedulers race to apply, and a
    rollback, each followed by the edge
  - a password and consent page, with its attempt limit shared across
    instances and its grant working at both
  - previews and the audit chain

  `examples/demo.sh` has a new step 7 showing the same from the command
  line.
- **Tests.** A property test compares the compiled rules with a naive
  tree-walking interpreter over 100,000 generated requests, in all three
  forms the rules are loaded. Another requires the origin and the edge to
  give equal answers for random rule lists. 31 invalid-rule and 15
  invalid-app cases are tested through the API.

Changed:

- The Worker forwards the visitor's query string, `Accept-Language`, region
  and POSTed forms (at most 4 KiB) to the origin.
- `Link.expires_at` is parsed with chrono's strict RFC 3339 parser, which
  keeps the Worker bundle under 250 KB gzipped (246,885 to 247,272 bytes,
  depending on the toolchain).
- `apple-app-site-association` is a reserved word.

Fixed:

- Adding a redirect outcome or a database operation panicked, because
  their metric counters were fixed-size arrays. They are now sized from the
  enums.
- Newer clippy refused a `Result` with a large error on the redirect path.
  The redirect path now uses an explicit `Routed` enum.

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
