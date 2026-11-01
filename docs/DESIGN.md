# relink design

The interesting part of a URL shortener is the redirect: it is the only
request strangers send, it is most of the traffic, and it has to keep working
when everything behind it is having a bad day. Most decisions below follow
from three requirements. A popular link must not touch the database or any
lock shared by all requests. Recently used links must keep redirecting while
Postgres is down. And a link with a click limit must never be followed more
times than allowed, on any number of instances, without a database write per
click.

Out of scope for now: custom domains, a UI, and storage other than Postgres.

## Three crates, and why the split is where it is

`relink-core` holds everything that decides what a redirect does: alias and
URL validation, expiry, the geo rule, health-aware destination choice, A/B
assignment and the cookie that makes it sticky, and the JSON shape of a link.
It does no I/O, owns no clock and no random source (callers pass both in), and
depends only on `url`, `chrono` without its clock, `serde`, `sha2` and `hmac`.
That is what lets it build for `wasm32-unknown-unknown`, and CI checks that
it still does.

The reason to share this code rather than write it twice is the cookie. A
visitor assigned variant B by the origin must get B from the edge and the
other way round, because traffic moves between them all the time: a link KV
has not received yet goes to the origin, a link with a click limit always
does. Two implementations of the weighting, the MAC input or the cookie
attributes would drift, and the symptom would be visitors silently switching
variants mid-experiment. `crates/relink-edge/tests/stickiness.rs` sends
cookies from one target to the other in both directions.

`relink-server` owns everything with state: Postgres, the cache, click
leases, the analytics pipeline, health checks and the KV sync.
`relink-edge` is deliberately thin. Its handler (`src/logic.rs`) is written
against two traits, `Kv` and `Origin`, so it runs and is tested natively;
`src/worker.rs` is the wasm-only glue to the workers-rs API (pinned at 0.8.7).

## Data model

| Table | Holds |
|---|---|
| `workspaces` | The tenant boundary: name, and `personal_owner` for the workspace each API key owner gets implicitly. |
| `workspace_members` | Member, workspace and role (`owner`, `admin`, `editor` or `viewer`). |
| `links` | Code, workspace, owner (its creator), destinations as a JSON array of `{url, weight}`, options, `clicks_reserved`, per-destination health failure counts. |
| `api_keys` | Workspace, owner, name, SHA-256 of the key, scopes, expiry, the key that replaced it on rotation, revocation time. |
| `click_daily` | Click counts per link, UTC day, country, device class and referrer host. |
| `visitor_daily` | Visitor hashes for unique counts, today and yesterday only. |
| `visitor_rollup` | Unique visitor counts for older days. |
| `visitor_salts` | One random salt per UTC day. |
| `kv_outbox` | Codes whose KV copy must be rewritten or deleted. |

`code` uses the `C` collation (bytewise and case-sensitive, as base62 needs)
and a `CHECK` repeats the API's character rules. The destination list is
checked to hold 1 to 10 entries, and a row with a zero weight is refused when
read, so a hand-edited row produces an error instead of a panic.

| Index | Query it serves |
|---|---|
| `links (code)` unique | Redirect lookups by code, and alias conflicts as a constraint violation rather than a race. |
| `links (owner, id DESC)` | Keyset pagination `WHERE owner = $1 AND id < $cursor ORDER BY id DESC`; each page is a range scan whatever its depth. |
| `links (health_checked_at NULLS FIRST) WHERE health_check AND enabled` | The health worker's "next due"; links without checks cost nothing. |
| `api_keys (key_hash)` unique | One probe per uncached key. |
| `click_daily` primary key | The flusher's upsert; stats use its `(link_id, day)` prefix. |
| `visitor_daily` primary key | `ON CONFLICT DO NOTHING` deduplication; the table holds two days, so the roll-up scan by day stays small. |
| `kv_outbox (next_attempt_at)` | The sync worker's "what is due". |
| `links (workspace_id, id DESC)` | Workspace listing with keyset pagination, and the row-level security predicate. |
| `workspace_members (member)` | The workspaces one person belongs to. |
| `workspaces (personal_owner)` unique | Finding an owner's personal workspace; concurrent first uses create one. |

### Tenancy

Every link and API key carries a `workspace_id`; statistics belong to the
workspace of their link. Migration 0003 created one personal workspace per
existing owner, with that owner as its `owner` member, and moved every row
into it.

The boundary is enforced by Postgres, not only by `WHERE` clauses in the
service. A transaction that acts for a tenant (`Db::begin_tenant`) runs as the
role `relink_tenant` and sets `relink.workspace_id`, both with `SET LOCAL`, in
the same simple-query message as its `BEGIN`, so scoping costs no round trip
of its own. Row-level security policies on `workspaces`, `workspace_members`,
`links`, `api_keys` and the three statistics tables compare against that
setting through `relink_current_workspace()`, which reads an unset or reset
setting as NULL. So a tenant query that forgot to name a workspace matches no
rows and can write none, and an insert or update that names another workspace
is refused by the same policy acting as its `WITH CHECK`. Inserts default
`workspace_id` to the transaction's workspace. Because both settings are
transaction-local, a pooled connection returns to the pool unscoped whether
the transaction committed, rolled back or was dropped.

On the request path, every management handler takes the `Workspace` extractor
(`src/tenant.rs`). It authenticates the key and takes the key's workspace; a
request may name its workspace in a `Relink-Workspace` header, and one that
names a different workspace from its key's is refused with
`permission_denied` (403) before anything is read, rather than quietly served
from the key's own. Every query the API runs lives on `Tenant`
(`Db::tenant(workspace_id)`), and each runs in its own tenant transaction.
Those queries filter only by code or cursor: the workspace comes from the
policies alone, so a link in another workspace is "not found" exactly like a
code that does not exist, and links belong to the workspace, not to the key
owner who created them (`links.owner` records the creator). Codes stay
globally unique, because the short URL carries no workspace. Statistics read
the link and its four aggregates in one transaction, so all parts come from
one snapshot. A read that was one round trip is now three (`BEGIN` with the
scoping, the query, `COMMIT`); the API is not latency-critical the way
redirects are, and the guarantee is worth it.

The connecting role owns the tables, so policies do not apply to it. It runs
the work that crosses workspaces by design: click flushes, health checks, the
KV outbox, click leases and key lookups during authentication (a key is how
the workspace is found, so that lookup cannot be scoped by it).
`relink_tenant` is `NOLOGIN NOBYPASSRLS`, holds only the table privileges the
API needs, and is created by the migration if missing (roles are
cluster-wide); where the migrating user lacks `CREATEROLE`, an administrator
creates it in advance and grants it to that user.

Redirect lookups by code, from the redirect path, the edge publisher and
`relink kv-record`, run as a third role, `relink_redirect` (migration 0004),
on a pool of their own (`RELINK_DB_LOOKUP_CONNECTIONS`, default 8) whose
connections `SET ROLE` once when they open, so the lookup is still one round
trip. The role has no table privileges at all. Its one grant is `EXECUTE` on
`relink_link_by_code(text)`, a `SECURITY DEFINER` function with a pinned
`search_path` that returns the link with exactly that code. A connection on
this pool cannot list links, read keys, statistics or salts, or write
anything, so a bug on the hottest path cannot become a dump of every tenant's
links. The separate pool also keeps a burst of cache misses from queueing
behind API transactions, and the reverse.

### Roles and API key scopes

A member's role in a workspace is `viewer`, `editor`, `admin` or `owner`. A
key carries scopes, a non-empty subset of `links:read`, `links:write` and
`stats:read` (migration 0005; keys made before it keep all three). What a
request may do is the intersection of the two: the key must carry the scope
and its owner's role must grant it. Viewers are granted `links:read` and
`stats:read`; editors, admins and owners all three. Admins and owners differ
in whom they manage (admins manage editors and viewers, owners everyone),
which the member and key administration built on this uses.

Both halves are checked because they change for different reasons. A scope
narrows one key for one job (a dashboard that only reads statistics); a role
says what a person may do at all. Reading the role at authentication, rather
than copying it into the key, means demoting someone narrows every key they
hold and removing them disables those keys, without finding and rewriting
the keys. The role comes from a primary-key probe of `workspace_members`
joined into the key lookup, so it costs no round trip, and it is cached with
the key for the same 30 s as revocation.

Each management route declares its scope as a type (`Allowed<LinksWrite>`
and so on in `src/tenant.rs`), and the OpenAPI document lists the same scope
on each operation; a test reads the document and checks, route by route, that
a key with every other scope gets `permission_denied` (403) and a key with
only that scope succeeds. The check runs in the extractor, before the body is
read, so a read-only key learns it cannot write before it learns its JSON is
malformed. The message says which half failed: the key lacks the scope, or
the role does not grant it. `relink create-key` refuses scopes the owner's
role does not grant, so such a key exists only after a demotion.

A key may expire. The lookup filters expired keys, and a cached key's expiry
is checked against the clock on every request, so expiry is exact rather
than "within the cache TTL". Rotation (`relink rotate-key ID --overlap 1d`)
is one transaction: it locks the old key, inserts a successor with the same
owner, workspace, name and lifetime (counted from now) and the scopes the
owner's role grants today, records it in `rotated_to`, and moves the old
key's expiry to the end of the overlap (never later than it already was).
Both keys work during the overlap, so a deployment can roll to the new key
with no moment where neither works. A key is rotated once; rotating it again
is refused and names the successor, so a chain of keys never forks. The
overlap is capped at 30 days and a lifetime at ten years. An instance that
cached the old key before the rotation honours the new end within the cache
TTL, the same bound as revocation.

## The redirect path on the origin

### The cache

Links live in a fixed-capacity map split into 64 shards behind reader-writer
locks, keyed with SipHash under a random key so clients cannot aim codes at
one shard. Eviction is CLOCK (Corbató, "A Paging Experiment with the Multics
System"): a read sets a per-entry bit with a relaxed atomic store under the
shard's read lock, and an insert into a full shard sweeps a hand until it
finds a clear bit. Reads never take the write lock, which true LRU would need.

Freshness follows HTTP's stale-while-revalidate and stale-if-error
(RFC 5861), counted from when the entry was loaded:

| Age | State | What a request does |
|---|---|---|
| under the TTL (30 s) | fresh | serves it |
| under TTL + 5 min | stale | serves it and starts one background refresh |
| under TTL + 24 h | expired | waits up to 100 ms for a refresh, else serves it |
| older | gone | treated as a miss |

Codes the database does not know are cached as negative entries for 10 s.
Strings that cannot be codes are refused before the cache.

A fourth state, *suspect*, covers entries that may describe a link as it was
before a change: a load that was in flight when the link was invalidated, or
everything cached before the change listener reconnected (notifications may
have been lost while it was down). A suspect entry is never served while the
database can answer; the request waits for a fresh load and falls back to the
old entry only on a database error. Without this, a link disabled while a
cache miss for it was in flight would keep redirecting until its TTL ran out.

### Coalescing, shedding and the breaker

A miss goes through a single flight (the pattern of Go's
[`x/sync/singleflight`](https://pkg.go.dev/golang.org/x/sync/singleflight)):
the first request starts the lookup in its own task, later ones for the same
code wait for it, and a client hanging up does not cancel it for the rest.
Lookups for different codes share 32 slots; a miss that cannot get one in
250 ms is answered 503, which keeps a flood of made-up codes from becoming a
flood of queries.

During an outage every lookup fails only after the 2 s query timeout. So
after any failed lookup the resolver stops trying on the request path for one
second: expired and suspect entries are served at once, misses are refused at
once. The first successful lookup closes the breaker. Once the database has
failed, cached links cost nothing extra, and when it comes back it sees at
most one probe per code per second per instance.

### Coherence between instances

Every change to a link (create, update, delete, health flip) runs
`pg_notify('relink_link_changes', '<id>:<code>')` in the same transaction, so
a notification is delivered exactly when the change commits. Each instance
listens and evicts the code. If the listening connection drops, every cached
entry becomes suspect when it reconnects.

The bound on serving a disabled link from the origin is therefore: zero on the
instance that made the change, the notification delay (milliseconds) on the
others, and, if the listener is down, until the entry is next used after its
30 s TTL plus one refresh round trip. If the database is also down, cached
entries are served as they were, by design, for up to a day.

## Click limits without a write per click

This is escrow (O'Neil, "The Escrow Transactional Method"). Each instance
reserves a block of clicks with one statement and spends it from an atomic
counter:

```sql
UPDATE links l
   SET clicks_reserved = l.clicks_reserved + LEAST($max_lease,
         GREATEST(1, (l.max_clicks - l.clicks_reserved) / 8),
         l.max_clicks - l.clicks_reserved)
  FROM (SELECT id, clicks_reserved AS before FROM links WHERE id = $1 FOR NO KEY UPDATE) o
 WHERE l.id = o.id AND l.max_clicks IS NOT NULL AND l.clicks_reserved < l.max_clicks
RETURNING l.clicks_reserved - o.before
```

The row lock serialises reservations, and a grant never exceeds what is
left, so the grants sum to at most `max_clicks`. A redirect is served only
after taking one unit of a grant. Clicks served ≤ clicks reserved ≤
`max_clicks`: the overshoot is zero.

What it costs is undershoot. An instance that dies keeps its unspent lease
forever. Lease size is `min(max_lease, max(1, remaining / 8))`, up to 100
clicks early on (one round trip per 100 clicks) and shrinking to single clicks
near the end, so a crash late in a link's life loses little. Shutdown, link
updates and idle sweeps hand unspent clicks back. Measured with three
instances and 180,000 requests for a 100,000-click link: 100,000 served, and
99,996 when one instance was killed with SIGKILL mid-run.

If the lease is empty and the database cannot be reached, the click is
refused with 503; serving it might exceed the limit. After a failed
reservation the limiter waits a second before asking again, so clicks are
refused at once instead of queueing behind a timeout. During shutdown it
stops reserving before it hands everything back.

One race needed care. Updating a link retires its local lease and returns
the balance. A refill in flight at that moment adds its grant to the retired
lease and then re-checks the retired flag; the retirer sets the flag before
swapping the balance out. With sequentially consistent operations on both
sides at least one of them sees the other, so nothing is stranded. The
property test in `limiter.rs` drives this with random invalidations, and
removing the re-check makes it fail.

## The edge

### What it serves and what it passes on

The Worker looks up `link:<code>` in KV (read with a 60 s colo cache) and
evaluates it with `relink-core`. It answers itself when the record exists and
the link has no click limit: redirects, 404 for disabled links, 410 for
expired ones, 451 or the fallback for geo-blocked visitors. It forwards to the
origin, without following redirects, when the record is missing (KV may not
have caught up with a new link), when KV fails, and for every link with a
click limit. The country comes from Cloudflare's `cf` object, which clients
cannot set; the visitor's address from `CF-Connecting-IP`. Both are passed to
the origin, which believes them because the edge is in its
`RELINK_TRUSTED_PROXIES`.

### Getting records into KV

The origin publishes through a transactional outbox (Chris Richardson,
["Pattern: Transactional outbox"](https://microservices.io/patterns/data/transactional-outbox.html)).
Every link change inserts the code into `kv_outbox` in the same transaction,
so a committed change cannot be forgotten. A worker claims due entries with
`FOR UPDATE SKIP LOCKED`, reads the current row, and PUTs its JSON to the
Cloudflare KV REST API, or DELETEs the key if the link is gone. The entry is
removed only after KV accepted the write and only if it was not re-queued in
the meantime. A failed write pushes the entry's next attempt back
exponentially, from 1 s up to 10 minutes. The worker wakes on the same change
notifications the caches use, and polls once a second as a fallback.

An outbox only covers changes made through relink. Keys deleted by hand, or a
namespace restored from an old copy, are caught by a reconciliation that runs
at start and hourly: it lists every KV key and every link code and queues the
differences. It compares key sets, not values; stale values are the outbox's
job.

Disabled links are published with `enabled: false` rather than deleted, so
the edge answers 404 itself instead of asking the origin every time. Publishing
is off unless `RELINK_KV_ACCOUNT_ID`, `RELINK_KV_NAMESPACE_ID` and
`RELINK_KV_API_TOKEN` are all set. The token only ever goes to
`RELINK_KV_API_BASE`, which must be https.

### Consistency between KV and Postgres

KV is eventually consistent. Cloudflare's documentation puts propagation of a
write to other locations at up to about 60 seconds, and our reads cache in the
colo for 60 seconds, which fits inside that. So, for links the edge serves:

- A change (disable, new destination, new geo rule, health flip) reaches a
  given location within the outbox delay (under a second normally) plus about
  60 seconds. A disabled link can therefore keep redirecting at the edge for
  roughly a minute after the origin has stopped serving it. That is the price
  of not asking the origin on every request.
- If writes to the KV API keep failing, the edge keeps serving the last record
  it received until a retry succeeds. The outbox guarantees the write happens
  eventually, not when. An operator who cannot wait can point traffic at the
  origin directly.
- Expiry is exact at the edge: the record carries `expires_at` and the
  Worker compares it with its own clock.
- Click limits are exact because the edge never serves limited links. Every
  click on them goes through the origin's lease counter. Serving them at the
  edge would need either a per-click call to a central counter or leases held
  by isolates that can disappear without notice, which would turn the zero
  overshoot bound into something much weaker.
- A new link is served by the origin until its record arrives.

### Clicks from the edge

The Worker computes the same fingerprint as the origin (`relink-core`'s
`visitor::fingerprint`) and batches clicks per isolate. The first click into
an empty batch schedules a send five seconds later through `ctx.wait_until`;
fifty clicks send immediately. The origin's `POST /v1/edge/clicks` checks a
shared token in constant time, validates every field as strictly as its own,
and feeds the same click queue. Delivery is at most once: an isolate evicted
before sending, or a failed POST, loses that batch, at most fifty clicks or
five seconds of one isolate's traffic. Counting edge clicks exactly would need
a durable queue between edge and origin; for analytics, a small bounded loss
is the better trade.

## Analytics

A redirect computes the click's dimensions and a visitor fingerprint, then
calls `try_send` on a bounded channel; a full channel counts a drop rather
than delaying the visitor. One flusher aggregates by `(link, day, country,
device, referrer)` and, every second or 5,000 clicks, writes with
`INSERT ... SELECT FROM UNNEST(...) ON CONFLICT DO UPDATE`. Rows are merged by
their stored key first, because Postgres refuses a statement that updates the
same row twice; a missing referrer is stored as `(direct)`, which no parsed
host can equal.

Writes go in transactions of at most 5,000 count rows and 5,000 visitor rows,
so a large backlog after an outage never needs one statement that outlives
the query timeout. Measured against Postgres in Docker: 100,000 count rows and
100,000 visitor rows drain in about 3 s. On failure the rest stays pending and
is retried with backoff, bounded by `RELINK_CLICK_BACKLOG` rows; past that,
clicks are dropped and counted. A chunk the database refuses three times for a
reason other than unavailability is dropped and counted as `rejected`,
because retrying it forever would block every later click.

What counts as a click: a redirect to a destination, or to the fallback when
nothing is healthy. Geo refusals, expired and over-limit links show up only in
`relink_redirects_total` by outcome.

### Unique visitors without storing addresses

The fingerprint is `SHA-256("relink-visitor" | address | User-Agent
prefix)[0..16]` and never leaves memory. What gets stored is `HMAC-SHA256(salt,
link_id | fingerprint)[0..16]`, where the salt is 32 random bytes created on
first use for each UTC day and shared by all instances through
`visitor_salts`. This is the scheme Plausible describes in its
[data policy](https://plausible.io/data-policy).

Salts and the hashes made with them are kept for today and yesterday. Then
the hashes are rolled up into a count and the salt is deleted. After that,
nobody holding the database and the code can test whether a given address
visited (IPv4 is small enough to brute-force a hash with a known salt), and
including the link ID stops correlation across links within a day. A flush
delayed past that window keeps its click counts but drops its visitor hashes,
counted in `relink_visitors_dropped_total`; creating a fresh salt for the old
day would count those visitors twice. Unique visitors are therefore per day
only.

## Health checks and SSRF

The worker claims due links with `FOR NO KEY UPDATE SKIP LOCKED`, so several
instances share the work without coordination. The weaker lock matters:
click flushes take key-share locks on the links they count (through the
foreign key), and `FOR UPDATE` conflicts with those, so busy links were
silently skipped round after round. A test caught it as an intermittent
failure. Each destination gets a `GET`
with a 5 s timeout. A 2xx, 3xx, 401, 403, 405 or 429 counts as alive; after two
consecutive failures the destination is taken out of rotation, and a flip
publishes a change notification (and a KV update). Results are written only if
the destinations did not change since the claim. Probes to the same host are
spaced at `RELINK_HEALTH_PER_HOST_RPS` (one per second by default); a probe
whose turn would come after the check interval waits for the next round.

A health check is a request from inside your network to a URL a stranger
chose, so it gets three layers. At creation, destinations must be http(s)
without credentials, and hosts that cannot be public are refused: IP literals
unless allowed, single-label names, `localhost`, `.local`, `.internal`,
`.home.arpa`, `.test`, `.invalid`, `.example`, `.onion`. At probe time the
client's DNS resolver drops every address that is not globally routable (the
IANA special-purpose registries, RFC 6890; for IPv6 only `2000::/3` minus
documentation and protocol ranges, with mapped, NAT64 and 6to4 forms judged by
the IPv4 address inside), and the connection uses exactly the addresses the
resolver returned, so a name cannot be rebound between check and connect.
And redirects are never followed, proxy variables are ignored and bodies are
not read. The resolver is the layer that matters: a public-looking name can
resolve to `169.254.169.254` tomorrow.

## Trust boundaries

`X-Forwarded-For`, `CF-Connecting-IP` and `CF-IPCountry` are ordinary headers
that any client can send. relink reads them only when the socket peer is in
`RELINK_TRUSTED_PROXIES`, and takes the client address as the rightmost
forwarded hop that is not itself a trusted proxy (the leftmost entry is
whatever the client wrote). With no trusted proxies configured, no header is
believed, and configuring a country or client-address header without trusted
proxies is a startup error. The CDN must also strip or overwrite these headers
on requests from clients; Cloudflare does this for `CF-Connecting-IP` and
`CF-IPCountry`.

API keys are `rlk_` plus 256 random bits. Only SHA-256 hashes are stored; a
fast hash suits a secret with full entropy, unlike a password. A key is found
through the unique hash index and the stored hash compared in constant time.
Known keys are cached for 30 s (so revocation and role changes take up to
30 s everywhere, while expiry is exact);
unknown ones for 5 s in a separate cache, so a flood of made-up keys cannot
evict real ones. Lookups of uncached keys are limited per client address
(5 per second) and globally (200 per second), so guessing keys costs a bounded
number of index probes and cannot lock out clients already authenticated.
Per-key request limits (10 per second, burst 20) apply after authentication.

Requests must be `application/json` with at most 64 KiB (256 KiB for edge
click batches), unknown fields and duplicate keys are refused, and every value
is range-checked. Internal errors carry a request ID and nothing else.
`/metrics` is on its own listener bound to loopback by default.

## Shutdown

On SIGTERM the server stops accepting connections and gives every phase one
shared budget (`RELINK_SHUTDOWN_TIMEOUT_S`, 10 s): draining requests, stopping
lease reservations, flushing the click queue, stopping background tasks,
returning unspent leases and closing the pool. A phase that runs long takes
time from the next rather than stretching the total past an orchestrator's
grace period; a test with Postgres gone at shutdown finishes inside the budget
and counts the clicks it could not write.

## Failure modes

| Failure | Behaviour |
|---|---|
| Postgres down | Cached links redirect (no added latency once the breaker opens); uncached codes and API calls get 503 within the 2 s timeout; clicks are buffered up to the backlog bound; readiness stays 200 and reports `"database":"down"`. |
| Postgres slow | Every query, including waiting for a connection, is bounded by the same timeout on the client and by `statement_timeout`. |
| Postgres restarts | Dead pooled connections fail one query and are replaced; the change listener reconnects and marks every cached entry suspect. |
| Miss storm for one code | One query. |
| Flood of unknown codes | At most 32 lookups in flight; the rest 503 after 250 ms. |
| Flood of made-up API keys | At most 5 lookups per second per address and 200 overall; the rest get 429. |
| Click queue full | Click dropped and counted; the redirect is unaffected. |
| Instance crash | Up to one flush interval of clicks and one lease per limited link are lost; no limit is exceeded. |
| KV API failing | Changes wait in the outbox and are retried with backoff; the edge serves the last records it has. |
| KV missing a record | The edge forwards to the origin. |
| Worker isolate evicted | Up to 50 unsent edge clicks are lost. |
| Health target hangs | 5 s timeout, counted as a failure. |

## Limits

| Limit | Value |
|---|---|
| Destination URL | 2048 characters, before and after normalisation |
| Destinations per link | 10, weights 1 to 1000 |
| Countries per geo rule | 300 |
| Alias | 3 to 64 of `[A-Za-z0-9_-]`, alphanumeric at both ends |
| Generated code | 7 base62 characters by default (4 to 32); collisions retried 5 times |
| `max_clicks` | 1 to 10¹² |
| `expires_at` | in the future, within 10 years |
| Request body | 64 KiB; 256 KiB and 1,000 clicks for edge batches |
| Page size | 1 to 100, default 50 |
| Stats range | 366 days, top 50 per dimension |
| Cache | 100,000 entries |
| Click queue / backlog | 65,536 clicks / 200,000 aggregated rows |
| Flush transaction | 5,000 count rows and 5,000 visitor rows |
| User-Agent scanned | 512 bytes (256 in the fingerprint) |
| Lookup concurrency | 32 |
| Uncached key lookups | 5/s per address, 200/s overall |
| API rate | 10/s, burst 20, per key and instance |
| KV outbox retry | 1 s doubling to 10 min |
| Edge click batch | 50 clicks or 5 s |

## Observability

JSON logs on stderr with request IDs; one line per API request, redirects at
debug level so the hot path does not pay for a log line. Prometheus metrics on
the admin listener cover redirect latency, redirects by outcome, cache results
(`hit`, `negative_hit`, `stale`, `stale_on_error`, `miss`), coalesced and shed
lookups, click queue depth, backlog, drops by reason, late visitor hashes,
database errors by operation, lease grants, health probes, KV writes, deletes,
errors and reconciled drift, edge clicks, API requests and refusals, and pool
usage.

## Dependencies

Direct dependencies are pinned to exact versions in the manifests (and every
transitive one in `Cargo.lock`), each at least two weeks old when chosen,
with one exception: tokio is on 1.53.3 because every older 1.53 release is
affected by RUSTSEC-2026-0386 (`AsyncFd` I/O safety), and a known advisory
outweighs the age rule. `cargo deny` checks licenses and sources, `cargo
audit` known advisories.

| Crate | Why it earns its place |
|---|---|
| `tokio` | The async runtime under axum, sqlx and reqwest. |
| `axum` | Routing and extractors on hyper. Writing HTTP/1 parsing and graceful shutdown ourselves would be the riskiest code in the repo. |
| `sqlx` | Postgres driver with a pool, `LISTEN/NOTIFY` and embedded migrations, without an ORM. Queries are plain SQL strings. |
| `reqwest` | HTTP client for health probes and the KV API. It accepts a custom DNS resolver, which the SSRF defence depends on. |
| `serde`, `serde_json` | JSON for the API, the KV record and the edge wire format. |
| `url` | WHATWG URL parsing and IDNA; not something to hand-roll when the result decides where a server sends requests. |
| `hmac`, `sha2`, `subtle` | HMAC-SHA256 for A/B cookies and visitor hashes, SHA-256 for keys, constant-time comparison. |
| `getrandom` | The OS CSPRNG for codes, keys and salts. |
| `chrono` | Timestamps and UTC dates; the core uses it without its clock so it stays wasm-friendly. |
| `tracing`, `tracing-subscriber` | Structured JSON logs with request-scoped spans. |
| `worker` | The workers-rs binding to the Cloudflare Workers runtime; wasm32 only. |
| `proptest`, `criterion`, `tower` (dev) | Property tests, benchmarks, and driving the router in-process in benchmarks. |

Metrics, the cache, single flight, token buckets, CIDR parsing and hex are
each a few dozen lines and written here instead of pulled in.

## At a larger scale

A membership filter (Bloom or cuckoo) of all codes, maintained from the change
feed, would answer most made-up codes without a query; it needs an answer for
codes created on another instance before the filter hears about them. The
miss path is a single-row read by unique key and could go to read replicas,
with notifications still from the primary. HyperLogLog sketches (Flajolet et
al., "HyperLogLog: the analysis of a near-optimal cardinality estimation
algorithm") would replace per-visitor rows with a fixed size per link and day.
Partitioning `click_daily` by month would make retention a `DROP PARTITION`.
Per-key rate limits are per instance; a global limit needs a shared counter.
And at the edge, a link with a click limit could be served from a Durable
Object holding its counter, at the cost of a hop to wherever that object
lives.
