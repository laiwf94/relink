# relink design

The interesting part of a URL shortener is the redirect: it is the only
request strangers send, it is most of the traffic, and it has to keep working
when everything behind it is having a bad day. Most decisions below follow
from three requirements. A popular link must not touch the database or any
lock shared by all requests. Recently used links must keep redirecting while
Postgres is down. And a link with a click limit must never be followed more
times than allowed, on any number of instances, without a database write per
click.

Out of scope for now: a web console, and storage other than Postgres.

## Three crates, and why the split is where it is

`relink-core` holds everything that decides what a redirect does: alias and
URL validation, expiry, the geo rule, health-aware destination choice, A/B
assignment and the cookie that makes it sticky, and the JSON shape of a link.
It also holds the HyperLogLog++ sketches for unique counts, so the origin
and the edge build the same bytes, and the QR encoder.
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
| `links` | Code, workspace, custom domain (none for the default domain), owner (its creator), destinations as a JSON array of `{url, weight}`, options, `clicks_reserved`, per-destination health failure counts. |
| `domains` | Custom domains: workspace, hostname, verification token, who added it, when it was verified, and the outcome of the last check; the certificate's expiry and renewal time, and the last issuance attempt's outcome, failure count and next attempt. |
| `domain_certificates` | Each domain's current certificate chain, PEM, its private key sealed with AES-256-GCM, validity, renewal time and when it was issued. Server role only. |
| `acme_accounts` | The ACME account per CA directory: its URL and sealed key. Server role only. |
| `acme_challenges` | HTTP-01 challenges being validated: token, hostname, key authorization, expiry. |
| `api_keys` | Workspace, owner, name, SHA-256 of the key, scopes, expiry, the key that replaced it on rotation, revocation time. |
| `click_daily` | Click counts per link, UTC day, country, device class and referrer host. |
| `visitor_daily` | Visitor hashes for unique counts, today and yesterday only. |
| `visitor_rollup` | Unique visitor counts for older days. |
| `visitor_salts` | One random salt per UTC day. |
| `click_hourly` | `click_daily` at the resolution of a UTC hour, with the link's workspace. Kept for `RELINK_CLICK_HOURLY_RETENTION_DAYS`. |
| `visitor_sketch_hourly`, `visitor_sketch_daily` | A HyperLogLog++ sketch of each link's visitors per UTC hour and per UTC day. |
| `click_batches` | The random key of every click batch written in the last week, so a retried batch is applied once. Server role only. |
| `click_events` | Raw clicks, one row each: time, workspace, link, domain, country, device class, referrer host, visitor hash (none for bots) and a bot flag. Partitioned by UTC calendar month (`click_events_pYYYYMM`); retention drops whole months. |
| `kv_outbox` | Codes whose KV copy must be rewritten or deleted. |
| `users` | People who signed in: issuer and subject at the provider, their member name, email address and display name. |
| `oidc_logins` | Sign-ins between the redirect to the provider and its return: SHA-256 of `state`, nonce, PKCE verifier, return path, expiry. |
| `sessions` | SHA-256 of each session cookie, its person, CSRF token and expiry. |
| `audit_log` | Every change made by a person or an operator: workspace, sequence number, time, actor, how they acted, action, target, the state before and after, and the hash chain. |
| `audit_heads` | The last sequence number and hash of each workspace's audit chain. |
| `link_versions` | Each link's settings after every change that altered them, numbered per link, with who made the change, how (`create`, `update`, `rollback`, `schedule`, `migration`), the version a rollback restored and the schedule that applied it. The newest 100 per link. |
| `link_schedules` | Changes to apply to a link later: when, the new destinations and/or `enabled`, who scheduled it, and its state (`pending`, `applied`, `failed`, `canceled`) with the version it produced or why it failed. |

`code` uses the `C` collation (bytewise and case-sensitive, as base62 needs)
and a `CHECK` repeats the API's character rules. The destination list is
checked to hold 1 to 10 entries, and a row with a zero weight is refused when
read, so a hand-edited row produces an error instead of a panic.

| Index | Query it serves |
|---|---|
| `links (COALESCE(domain_id, 0), code)` unique | Redirect lookups by domain and code, alias conflicts per domain as a constraint violation rather than a race, and the KV reconciliation's walk of default-domain codes. |
| `domains (hostname) WHERE verified_at IS NOT NULL` unique | Only one workspace can prove a hostname; loading the verified hostnames for routing. |
| `domains (workspace_id, hostname)` unique | A workspace adds a hostname once; finding one by hostname. |
| `domains (tls_next_attempt_at NULLS FIRST, id) WHERE verified_at IS NOT NULL` | The certificate worker's claim of domains due for issuance or renewal. |
| `links (owner, id DESC)` | Keyset pagination `WHERE owner = $1 AND id < $cursor ORDER BY id DESC`; each page is a range scan whatever its depth. |
| `links (health_checked_at NULLS FIRST) WHERE health_check AND enabled` | The health worker's "next due"; links without checks cost nothing. |
| `api_keys (key_hash)` unique | One probe per uncached key. |
| `click_daily` primary key | The flusher's upsert; stats use its `(link_id, day)` prefix. |
| `visitor_daily` primary key | `ON CONFLICT DO NOTHING` deduplication; the table holds two days, so the roll-up scan by day stays small. |
| `click_hourly` primary key `(link_id, hour, country, device, referrer_host)`; `(workspace_id, hour)`; `(hour)` | The flusher's upsert and one link's hours; a workspace's hours, also the row-level security predicate; retention. |
| `visitor_sketch_hourly (link_id, hour)`, `visitor_sketch_daily (link_id, day)` primary keys; `visitor_sketch_hourly (hour)` | Locking a sketch to merge into it, and one link's sketches over a range; retention. |
| `click_batches (id)` primary key, `(at)` | The replay check that opens every flush transaction; expiring old keys. |
| `click_events (link_id, at)`, `(workspace_id, at)`, on every partition | One link's events over a time range; a workspace's events over a time range, which is also the row-level security predicate. Partition pruning on `at` limits either to the months asked for. |
| `kv_outbox (next_attempt_at)` | The sync worker's "what is due". |
| `link_versions (link_id, version)` primary key | A link's history newest first, by keyset; the current version's snapshot for the "did anything change" check; pruning the oldest. |
| `link_schedules (run_at, id) WHERE state = 'pending'` | The scheduler's "what is due"; finished schedules cost nothing. |
| `link_schedules (link_id, id DESC)` | One link's schedules, newest first, by keyset, and its pending count. |
| `links (workspace_id, id DESC)` | Workspace listing with keyset pagination, and the row-level security predicate. |
| `workspace_members (member)` | The workspaces one person belongs to. |
| `workspaces (personal_owner)` unique | Finding an owner's personal workspace; concurrent first uses create one. |
| `users (issuer, subject)` unique, `users (member)` unique | Finding a person at sign-in; two people can never get the same member name. |
| `oidc_logins (state_hash)` primary key, `(expires_at)` | Taking a sign-in on return; clearing abandoned ones. |
| `sessions (token_hash)` primary key, `(expires_at)`, `(user_id)` | One probe per uncached session; clearing expired ones. |
| `audit_log (workspace_id, seq)` primary key | Reading a chain in order for verification, in batches by keyset. |
| `audit_heads (workspace_id)` primary key | Taking the next sequence number; the row lock orders a workspace's entries. |

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
owner who created them (`links.owner` records the creator). Codes are
unique per domain: the short URL carries no workspace, but it does carry
its host ("Custom domains" below). Statistics read
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
key carries scopes, a non-empty subset of `links:read`, `links:write`,
`stats:read` and `conversions:write` (migration 0005, and 0023 for the last;
keys made before 0005 keep the first three, and keys keep the scopes they
were made with). What a
request may do is the intersection of the two: the key must carry the scope
and its owner's role must grant it. Viewers are granted `links:read` and
`stats:read`; editors, admins and owners all four. `conversions:write`
posts conversions and nothing else, so the key a destination's server
holds cannot read or change links. Admins and owners differ
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

### Console sign-in

People sign in with any OpenID Connect provider (`RELINK_OIDC_ISSUER`,
`RELINK_OIDC_CLIENT_ID`, optionally `RELINK_OIDC_CLIENT_SECRET`), using the
authorization code flow with PKCE (`src/oidc.rs`). Programs keep using API
keys; the two never mix in one request, and an `Authorization` header wins
over a cookie.

`GET /v1/auth/login` stores the pending sign-in in Postgres (`oidc_logins`:
the SHA-256 of a random `state`, a random `nonce`, the PKCE verifier and the
return path, for ten minutes), puts `state` in a `relink_login` cookie, and
redirects to the provider's authorization endpoint with the S256 challenge.
`GET /v1/auth/callback` then requires, in order: the cookie equals `state`
(compared in constant time), which stops anyone completing their own sign-in
in another person's browser; the pending sign-in exists and has not expired,
taken with `DELETE ... RETURNING` so each completes at most once, even if the
provider said no; the code exchanges at the token endpoint with the verifier
(client secret in HTTP basic authentication, or a public client); and the ID
token passes every check of OpenID Connect Core 3.1.3.7 that applies to a
token from the token endpoint. The signature must be RS256 or ES256 by a key
in the provider's published key set, verified with `ring`; `none`, the HMAC
algorithms (which would let a key set's public key act as a shared secret)
and anything with `crit` are refused before the payload is read. Then `iss`
must equal the configured issuer exactly, `aud` must include our client ID,
`azp` must be our client ID when present (and is required with several
audiences), `exp`, `iat` and `nbf` are checked with 60 s of clock skew, and
`nonce` must equal the stored one. Because state, verifier and nonce live in
Postgres, the callback can land on any instance. Both endpoints write to
Postgres before anyone is authenticated, so they draw on the same
per-address (5 per second) and global (200 per second) budget as lookups of
unknown API keys, and beyond it get 429.

Provider metadata and keys are fetched on first use and cached for an hour.
A token signed by a key we do not have refetches the key set, at most once
every 30 s, which is how a provider's key rotation is followed without
letting a stream of bogus key IDs turn into a stream of fetches. Discovery
must name the configured issuer, and the endpoints it lists must be https
(http is accepted only when the issuer itself is on loopback, for tests).

The first sign-in of an identity (issuer and subject) creates a `users` row
and a personal workspace the person owns. Their member name comes from the
preferred username, the email local part or the display name, reduced to the
member-name alphabet, and is chosen so that it matches no existing member,
API key owner, link creator or personal workspace, adding `-2`, `-3`... and
then a random suffix. Taking an existing name would hand whoever registers
`alice` at the provider all of alice's memberships. The name never changes
afterwards; the email address and display name are refreshed at each
sign-in. `RELINK_OIDC_ALLOWED_DOMAINS` limits sign-in to verified email
addresses at the listed domains.

A session is a `relink_session` cookie: `rls_` and 256 random bits,
`HttpOnly`, `SameSite=Lax`, `Secure` unless `RELINK_COOKIE_SECURE=false`, and
`Path=/v1` so redirects never carry it. Only its SHA-256 is stored, like an
API key's, and it ends at a fixed time (`RELINK_SESSION_TTL_S`, 12 hours).
Each session has its own CSRF token, returned by `GET /v1/auth/session`
together with the person's workspaces and roles. Every request
authenticated by the cookie whose method is not GET, HEAD or OPTIONS must
carry it in `X-CSRF-Token`, so another site cannot make a signed-in browser
create, change or delete anything, sign-out included. `SameSite=Lax` alone
would not do: it still sends the cookie on top-level navigations, and
browsers differ on what counts as same-site.

A session acts in the workspace named by `Relink-Workspace`, or in the
person's personal workspace, with the rights of their role there and nothing
else: the same `Allowed<S>` check as keys, with every scope present so the
role alone decides. Session lookups share the key path's defences: unknown
tokens are cached for 5 s and their lookups limited per address and
globally; known sessions are cached for 10 s and roles for 30 s. Sign-out
deletes the row and the cached copy, so it is immediate on the instance that
served it and takes at most 10 s elsewhere. A per-person token bucket (all
of a person's sessions share one) limits requests like the per-key one.
Expired sessions and abandoned sign-ins are deleted by the minute-by-minute
maintenance task.

### Audit log

Every change made by a person or an operator is appended to an audit log
(`src/audit.rs`, migration 0007) in the same transaction as the change, so
an entry exists exactly when its change committed: a refused or rolled-back
change leaves neither. That covers creating, changing and deleting links;
creating, rotating and revoking keys; creating workspaces; creating,
accepting and revoking invitations; signing in (the first sign-in creates
the person) and signing out. Bookkeeping the server
does on its own (click counts, leases, health results, the KV outbox) is
not logged: nobody decided it, and it would bury the log.

An entry names the actor (a member, or none for an operator at the command
line or the server itself), how they acted (`key:<id>`, `session:<user id>`,
`cli` or `system`), the action (`link.update` and so on), the target
(`link:<id>`, `key:<id>`, `workspace:<id>`, `user:<id>`) and the state
before and after as JSON. A link's state is its redirect record plus its
creator; a key's is its ID, owner, name, scopes and expiry, never its hash.
Sign-ins and sign-outs land in the person's personal workspace.

Each workspace has its own hash chain. Entry *n* stores the hash of entry
*n − 1* and its own hash, SHA-256 over a version tag, that previous hash,
the workspace, the sequence number, the time in microseconds and every other
field, each length-prefixed so text cannot move from one field to the next
unnoticed. `before` and `after` are hashed in jsonb's text form, which
Postgres produces deterministically, so a dump and restore keeps the chain
valid. The hashes are computed by a `BEFORE INSERT` trigger, not by the
writer: whatever sequence number or hash a writer supplies is replaced, so
no code path can break or skip the chain. The trigger takes the next number
with one `INSERT ... ON CONFLICT DO UPDATE` on `audit_heads`, which locks
that workspace's head row until the transaction ends. Entries of one
workspace are therefore numbered in commit order with no gaps (a rolled-back
change returns its number), and workspaces never wait for each other. Each
change costs one more statement in its transaction; two changes in the same
workspace serialise on the head for the rest of their transactions, which
for API changes is one statement plus `COMMIT`.

The log is append-only: triggers refuse `UPDATE`, `DELETE` and `TRUNCATE`
even from the table owner, and `relink_tenant` holds only `SELECT` and
`INSERT`, under a row-level security policy that keeps it inside its own
workspace's chain and away from `audit_heads` entirely. Someone who owns the
tables can still drop the triggers; that is what the chain is for.

`relink audit-verify [--workspace ID]` reads each chain in batches of 1,000
(so memory stays flat), recomputes every hash in Rust, independently of the
trigger, and stops at the first break, naming the workspace, the entry and
whether it was altered, is missing, does not follow from its predecessor, or
disagrees with the chain's head. An edit anywhere breaks that entry; an
entry removed from the middle leaves a gap; one removed from the end leaves
the head ahead of the chain. On success it prints each head as
`WORKSPACE:SEQ:HASH`. A chain can only be rewritten without detection by
someone who also recomputes every later hash and the head; keeping printed
heads somewhere the database's owner cannot write, and passing them back
with `--anchors`, detects that too, back to the oldest anchor.

### Plans and quotas

A plan (`src/quota.rs`, migration 0008) is a named row of limits: how many
links and custom domains a workspace may hold and how many clicks it may
receive in a calendar month, UTC. A missing limit is no limit. Every workspace is on one plan; the
seeded `unlimited` plan is the default, so a self-hosted install behaves as
before until an operator defines plans with `relink plan-set` and moves
workspaces with `relink plan-assign`, which is recorded in the workspace's
audit chain as `workspace.plan` with the limits before and after.
`relink_tenant` may read every plan and its own workspace's usage but holds
`UPDATE` on `workspaces` only for the `name` column, so no tenant query can
move a workspace to another plan.

Clicks are metered from the click pipeline, not the redirect: the flusher's
transaction that adds a batch to `click_daily` also adds it to
`workspace_usage (workspace_id, month)`, grouped by the month of each
click's own day, so a late flush after an outage lands in the month the
clicks happened and the meter always equals the statistics. It costs one
more statement per flushed chunk and nothing per redirect. Concurrent
flushers on several instances touch usage rows in sorted order, so they
queue rather than deadlock. Clicks trail redirects by the flush interval
(one second by default), which is the meter's only inaccuracy.

Limits are checked when a link is created, inside the creating
transaction, and a refusal is `quota_exceeded` (403) naming the limit and,
for clicks, the day it resets. Under a link limit the transaction first
locks the workspace row (`FOR NO KEY UPDATE`, which foreign-key checks from
other inserts do not wait for) and then counts with a fresh snapshot, so
concurrent requests cannot both take the last slot: 20 racing for 3 slots
create exactly 3. The count stops at the limit (`SELECT count(*) FROM
(SELECT 1 FROM links LIMIT n)`), so a check reads at most `n` index entries
however large the workspace, and workspaces without a link limit take no
lock and count nothing. Lowering a limit below what a workspace holds keeps
every link; only new ones are refused.

Quotas never refuse a redirect. A printed QR code or a link in a sent email
must keep working when its workspace runs out of clicks, so over the
monthly allowance links keep redirecting and keep being counted, and only
creating new links stops until the month turns. `GET /v1/usage` (scope
`stats:read`) returns the plan, the link and domain counts and the month's
clicks, each with its limit.

The domain limit (migration 0010) is checked when a domain is added, under
the same workspace row lock, so concurrent adds cannot overrun it either;
unverified domains count, since each one is a pending claim. Whatever the
plan, a workspace holds at most 1,000 domains, so listing them is always
one bounded answer.

### Invitations

People join a workspace by invitation (`src/invite.rs`, migration 0009). A
signed-in admin or owner invites by email address or by member name, with a
role their own role manages (`Role::manages`: admins invite editors and
viewers, owners anyone) and a lifetime between five minutes and 30 days,
seven by default. The answer carries a one-time link,
`/v1/invites/rli_<64 hex>`, shown only then: like an API key, only the
token's SHA-256 is stored. The request path is logged with the token
replaced by `{token}`, and neither the token nor its hash is in the audit
log.

Invitations are managed with a session, never an API key. A key's scopes
cover links and statistics; letting a read-only dashboard key mint owner
invitations would make every leaked key a way in. The same reasoning
applies to acceptance, which needs the session cookie and its CSRF token.

Holding the link is not enough to use it. Accepting requires a signed-in
person who is the one invited: for an email invitation, an address equal
(case-insensitively) to the invited one that the provider marked verified at
their latest sign-in (`users.email_verified`, refreshed at each sign-in);
for a member-name invitation, exactly that name. A name can only be invited
if someone already has it, because a name nobody has yet could later be
taken by whoever signs in first with a matching username. So a forwarded,
logged or guessed link is useless to anyone else, and the check reads the
person's row in the accepting transaction, not the cached session.

Acceptance is one transaction as the server's own role: the person is not a
member yet, and the token is what names the workspace, so it cannot be a
tenant query (key lookups are the same). It locks the invitation row
(`FOR UPDATE`), so concurrent acceptances queue and exactly one finds it
pending; it then inserts the membership, marks the invitation accepted and
appends `invitation.accept` to the workspace's chain. Someone who is
already a member gets `already_exists` and the invitation stays pending, so
a mistaken click does not burn it. The accepting instance drops its cached
"not a member" for that person and workspace at once; other instances follow
within the 30 s role cache, the same bound as any role change.

Creating, listing and revoking are tenant queries, so row-level security
keeps them inside the workspace and an invitation in another workspace is
`not_found`. `relink_tenant` holds `SELECT`, `INSERT` and `UPDATE` on
`invitations` but not `DELETE`: revoking stamps `revoked_at` and
`revoked_by`, and the record stays listed. Only a pending invitation can be
revoked, by someone whose role manages the invited role. A workspace may
have at most 100 pending invitations whatever its plan, checked under the
same workspace row lock as link quotas, so concurrent requests cannot
overrun it; beyond that is `quota_exceeded`. `GET /v1/invitations` lists
every pending invitation, then the newest others, 200 in all, with a
status computed from the database clock: `pending`, `accepted`, `revoked`
or `expired`.

### Custom domains

A workspace can serve links on its own hostnames (`src/domains.rs`,
migration 0010). `POST /v1/domains` adds a hostname, unverified, with a
random 128-bit token; the workspace publishes it as a TXT record
`relink-domain-verification=<token>` at `_relink-challenge.<hostname>`, and
`POST /v1/domains/{hostname}/verify` checks for it. Adding, verifying and
deleting need `links:write` and the admin or owner role (reading needs
`links:read`), and each lands in the audit chain as `domain.create`,
`domain.verify` or `domain.delete`.

A hostname is stored lowercase with IDNA applied and no final dot, and
must pass the public-host rules destinations follow (no IP addresses,
single labels, `localhost`, `.internal` and the like) and be letters,
digits and hyphens; the server's own host is refused. Many workspaces may
claim the same hostname, but a unique index over verified hostnames lets
only the first to prove it have it. A claim that cannot be proved
therefore blocks nobody, which matters because anyone can type anyone's
domain into the form.

The lookup speaks DNS itself (`src/dns.rs`): the operating system's
resolver only answers address queries. One question over UDP to the
resolvers in `RELINK_DNS_SERVERS` (or `/etc/resolv.conf`), retried over
TCP when truncated, with a random query ID, a connected socket and the
question checked in the answer, and CNAME chains followed only within the
answer. relink never connects to the domain being verified, and the name
it asks about has already passed the public-host rules, so verification
cannot be aimed at an internal service. Each verify request costs one
query, limited by the per-key API rate. A failed check stores what was
found (no record, records of another kind, another token, a resolver
error) and answers 200 with the domain, so a console can show why.

Codes are unique per domain: a unique index on `(COALESCE(domain_id, 0),
code)`, with 0 for the default domain, so `promo` on the default domain and
`promo` on `go.example.com` are two links. A link's domain must belong to
its workspace, which a foreign key on `(workspace_id, domain_id)` enforces
even against the table owner, and must be verified when the link is
created. A domain with links cannot be deleted (`failed_precondition`):
their short URLs are printed and sent, and deleting the domain would break
them silently. The API addresses a link on a domain with `?domain=` on
`/v1/links/{code}` and its statistics; links carry `domain` and a
`short_url` on it.

Redirects are routed by `Host`. Every instance keeps the verified
hostnames in memory, in 16 shards behind reader-writer locks, loaded at
start, whenever a `domains` change notification arrives (sent in the
verifying or deleting transaction), whenever the change listener
reconnects and once a minute. A request whose host is a verified domain
looks its code up there and nowhere else; any other host, including the
one in `RELINK_PUBLIC_BASE_URL`, is the default domain, exactly as before
custom domains existed. The default host is compared first without
allocating, and with no verified domains the map is not touched at all,
so the default domain's hot path is unchanged. The cache key of a link on
a domain is `<domain id>/<code>`, so the two never collide in the cache,
the single flight or change notifications. Lookups run as
`relink_redirect` through `relink_link_by_domain_code(domain, code)`, as
narrow as the default-domain function, which now matches only links
without a domain. Until the first load succeeds, a request for a host that
could be a custom domain gets 503: serving the default domain's link of
the same code could send a visitor somewhere the domain's owner never
chose. IP addresses and single-label hosts can never be one, so they are
always the default domain.

The edge serves custom domains too, keyed by host and code; see "Custom
domains at the edge".

### Per-domain settings

Each domain has settings (`relink_core::site`, migration 0015, a `jsonb`
column), changed with `PATCH /v1/domains/{hostname}` by an admin or owner
and audited as `domain.update` with the settings before and after:

| Setting | Effect |
|---|---|
| `root_url` | `/` redirects there (302, `no-store`); validated like a destination |
| `not_found_page` | HTML served with 404 for unknown codes, disabled links and paths that cannot be a code here |
| `gone_page` | HTML served with 410 for expired links and links at their click limit |
| `prefixes` | up to 8 lowercase segments accepted in front of a code: `/campaign/abc` is `abc` |
| `case_insensitive` | `/ABC` is `abc`; codes created on the domain are stored lowercase |
| `apps` | the iOS (`team_id`, `bundle_id`) and Android (`package`, `sha256_cert_fingerprints`) apps the domain belongs to, served as its association files ("Deep links") |

The decisions are functions in `relink_core::site`, called by the origin
and the Worker alike. `target(path, settings)` reads the path as sent,
still percent-encoded (codes are plain ASCII, so an encoded path never
names one): empty is the root, one segment is a code, two segments are a
code behind one of the domain's prefixes, and anything else is a miss.
`page(kind, ...)` picks the domain's page or the built-in plain text and
fills in `{{code}}` and `{{host}}`, HTML-escaped. A domain's page is the
workspace's HTML on the workspace's own hostname, but it is served with a
`Content-Security-Policy` that allows no scripts, forms or framing (only
images, styles and fonts), and `nosniff`. Prefixes may not be reserved
words, so `/v1/links` on a custom domain is still the API. The default
domain has no settings and is answered exactly as before: `/` and paths
with a `/` are unknown paths there, with the API's JSON 404.

Case-insensitivity is only sound if no stored code on the domain has an
uppercase letter, so turning it on is refused while one does
(`failed_precondition`, naming a code). The check runs under `FOR UPDATE`
on the domain row; a link being created holds `FOR KEY SHARE` on it until
it commits, so the two serialise, and a link created afterwards reads the
new rule and stores its code in lowercase (a generated code too, which
then retries on collision like any other).

Settings travel with the domain: in the in-memory map every instance
routes by (reloaded on the same change notification as verification), and
inside the domain's `host:` record at the edge, except `apps`, which the
record carries as the rendered association files.

### Certificates

With `RELINK_ACME_DIRECTORY` set, relink gets a certificate for every
verified domain from that ACME certificate authority (RFC 8555) with its
own client (`src/acme.rs`, migration 0011). There is no certbot or sidecar
to run, and no shared volume between instances: the state is in Postgres.

The client is the protocol and nothing else. Every request is a JWS
(RFC 7515) signed with the account's P-256 key, by `ring`, over a nonce the
CA issued; spare nonces from responses are kept, and a request the CA
refuses with `badNonce` is retried with a fresh one, at most three times.
The account is registered once per directory and its key stored in
`acme_accounts`; if two instances register at once, the first stored wins
and the other's account is never used. An order is placed for the
hostname, its authorization is answered over HTTP-01 (the key
authorization is the token and the account key's RFC 7638 thumbprint), and
once the order is ready it is finalized with a PKCS#10 request for a fresh
P-256 key, written by `src/der.rs`. The chain is downloaded as PEM, and the
leaf is read back: it must name the hostname and certify exactly the key
relink generated. Polling follows the CA's `Retry-After` within 50 ms to
10 s, and the whole order is bounded by `RELINK_ACME_ORDER_TIMEOUT_S`.
Every URL the CA hands out must be https, like the directory. Each
certificate gets its own key, so renewals rotate keys.

`AcmeWorker` runs on every instance. A round claims up to four verified
domains that have no certificate, or whose certificate has reached its
renewal time, and are not waiting out a failure, with `FOR NO KEY UPDATE
SKIP LOCKED`. The claim sets `tls_next_attempt_at` 15 minutes ahead, so
instances never order the same domain at once and a crashed instance's
claims lapse. A round runs every `RELINK_ACME_INTERVAL_MS` (a minute by
default), and immediately when a domain is verified on any instance (the
`domains` change notification). A certificate is renewed two thirds of the
way through its lifetime: after 60 days for a 90-day certificate, leaving
30 days for retries. A failure records the CA's reason in `tls_error` and
waits 5 minutes, doubling per failure in a row up to a day, and never less
than a `Retry-After` the CA sent with a rate limit. A CA that no longer
knows the account (`accountDoesNotExist`) gets a new one at the next
attempt. Success stores the chain and key in `domain_certificates` and the
expiry and renewal time on the domain in one transaction, and clears the
failures.

The CA validates by fetching `http://<domain>/.well-known/acme-challenge/
<token>`, and reaches whichever instance the domain's address points at.
So every instance answers it. Challenges are written to `acme_challenges`
with a `pg_notify`, and each instance keeps the pending ones in memory,
loaded the way verified domains are: at start, on the notification, on
reconnect and every minute. The answer is given only for the hostname the
challenge was made for, matched without case or port. A token not in
memory may have been published a moment ago, so it is looked up in
Postgres, at most 20 times a second per instance. A flood of made-up
tokens therefore costs memory lookups once that budget is spent, and never
a query each. Challenges are withdrawn when the order ends, whatever the
outcome, and expire after an hour if an instance dies first. The key
authorization is not secret: the CA fetches it over plain HTTP.

Tenants see a verified domain's certificate state in `GET
/v1/domains/{hostname}`: `pending`, then `issued` (a failed renewal shows
its error while the certificate is still valid) or `failed`, with the
error and the next attempt. They cannot read `domain_certificates`,
`acme_accounts` or `acme_challenges`, which have no grants for the tenant
role. Private keys are stored sealed, as the next section describes.

### Terminating TLS

With `RELINK_TLS_ADDR` set, relink serves the public routes over TLS too
(`src/tls.rs`), with rustls on the aws-lc-rs provider: TLS 1.2 and 1.3,
HTTP/1.1 by ALPN. Each custom domain gets its own certificate, chosen by
the SNI name in the client's hello (without case or a final dot) from a
map in memory; the server's own host, clients that send no SNI and names
without a certificate get the default certificate from
`RELINK_TLS_CERT_FILE` and `RELINK_TLS_KEY_FILE`, or no handshake at all
when there is none. A chain is served only if its leaf certifies the key
it is stored with.

Certificates are swapped in without a restart. Storing a certificate sends
a `certificates` change notification in the same transaction, and every
instance then reloads: one query lists each verified domain's certificate
by issue time, without the certificate, and only those that differ from
the map are read, opened and parsed, so a renewal costs one row however
many domains there are. Handshakes in progress keep the certificate they
started with; the next one gets the new. A certificate that cannot be
opened or parsed is logged and counted, and its domain keeps serving the
one it had. Reloads also run when a domain is verified or deleted (its
certificate goes with it), when the change listener reconnects and once a
minute, which also re-reads the default certificate files and keeps the
old ones if the new ones do not load.

Private keys, the certificates' and the ACME account's, are sealed before
they reach Postgres, with AES-256-GCM under `RELINK_KEY_ENCRYPTION_KEY`
(`ring`). The key encryption key is configuration, never stored, and the
same on every instance; ACME requires it. A sealed key is a 4-byte header
(`rlk` and a version), a random 96-bit nonce, the ciphertext and the
128-bit tag. The associated data names the row (`relink certificate key`
and the domain's id, or `relink acme account key` and the directory URL),
so a key copied to another row, altered or sealed under another key does
not open. Check constraints on both tables refuse any key without the
header, whatever role writes it. A database dump therefore holds no usable
key. Migration 0012 deleted the plaintext keys stored before it; the
worker registers a new account and orders every domain a new certificate.
Changing the key encryption key leaves stored keys unreadable in the same
way: delete the rows of `acme_accounts`, and set `tls_renew_at` to now on
the domains, and they are ordered again.

The listener accepts connections and runs each handshake in its own task,
at most 1,024 at once (the rest wait in the kernel's accept queue), each
bounded by `RELINK_TLS_HANDSHAKE_TIMEOUT_MS` (10 s), so a client that
opens a connection and says nothing holds one slot for that long and
nobody else up. Finished connections go to axum like a plain listener's,
with the peer's address, so trusted proxies, rate limits and click
counting work the same on both. On shutdown the listener closes with the
others and its requests drain within the same budget.

### A custom domain, start to finish

The domain pieces meet in this order for each branded domain:

1. **Added.** An admin or owner adds the hostname (`POST /v1/domains`).
   It is checked and stored with a verification token, unverified, and
   counted against the plan's domain limit under the workspace row lock.
   An unverified domain routes nothing and is published nowhere.
2. **Proved.** `POST /v1/domains/{hostname}/verify` asks the configured
   resolvers for `_relink-challenge.<hostname>` TXT. Once the token is
   there, the first workspace to prove the hostname gets it, and the
   `domains` notification puts it in every instance's domain map: from then
   on `Host` (or `x-forwarded-host` from a trusted proxy) routes codes on
   that domain only.
3. **Certified.** Verifying wakes the ACME worker. One instance claims the
   domain, orders the certificate, and any instance answers the CA's
   HTTP-01 request. The sealed key and chain are stored, the
   `certificates` notification makes every TLS listener serve them by SNI,
   and the domain is due again at two thirds of the certificate's
   lifetime.
4. **Shaped.** `PATCH /v1/domains/{hostname}` sets the root redirect, the
   404 and 410 pages, prefixes and case folding. `relink_core::site`
   decides what a path means, the same code at the origin and in the
   Worker.
5. **Published.** The outbox queues `host:<hostname>` with the settings and
   `link:<hostname>/<code>` for each link. The KV sync registers the
   custom hostname in the zone before writing the domain record, so the
   edge never routes a host its zone does not serve.
6. **Removed.** A domain with links cannot be deleted. Deleting an empty
   one drops it from the domain maps and the certificate store, deletes its
   KV record and then its custom hostname. Its hostname is the default
   domain again. Every step but the certificate is audited.

`tests/custom_domains.rs` drives all six through the HTTP API, the binary,
real TLS connections and the edge's request logic in front of the origin.
Step 6 of `examples/demo.sh` shows steps 1, 2 and 4 from the command line,
with a one-record DNS server (`examples/txt-dns.py`) standing in for the
domain's zone.

### A management request, start to finish

The pieces above meet on every management request, in this order:

1. **Who.** The `Workspace` extractor authenticates an API key from
   `Authorization`, or else a session cookie, which must also send
   `X-CSRF-Token` on anything but a read. Unknown credentials share the
   per-address budget for guessing.
2. **Where.** A key acts only in its own workspace; a session acts in the
   workspace named by `Relink-Workspace`, or the person's personal one. A
   key that names another workspace, or a person who is not a member, gets
   `permission_denied`.
3. **May they.** The route's scope (`Allowed<S>`) must be both on the key
   and granted by the member's current role, so a demotion narrows old keys
   too. Refusals happen before the body is read.
4. **What they see.** The query runs in a tenant transaction as
   `relink_tenant` with `relink.workspace_id` set, so row-level security,
   not the handler, decides which rows exist.
5. **Whether it fits.** Creating a link checks the plan inside that same
   transaction, under the workspace row lock when a link limit applies.
6. **The record.** The audit entry is inserted in that transaction too, so
   a change and its entry commit or roll back together, and a refused
   request leaves none.

`tests/workspaces.rs` drives all six steps through the real sign-in flow,
the HTTP API and the binary. Step 5 of `examples/demo.sh` shows them from
the command line.

### Versions and schedules

Every change to what a link does is kept as a numbered version, so a bad
edit can be undone and a campaign can be switched over at a set time
(`src/schedule.rs`, migration 0018).

**Snapshots are written by the database.** A version holds the link's
settings, the fields `PATCH` can change, as one JSON object built by the
SQL function `relink_link_spec(links)` from the row itself; the server
only reads it back, as `LinkSpec`. A snapshot therefore cannot drift from
the row it describes, and links that existed before the migration got
their version 1 from the same function, marked `migration`. Timestamps in
it are written in UTC with microseconds whatever the session's time zone,
so equal settings always give equal JSON.

**Recording a version** happens inside the transaction of the change,
after the row is written: one query compares the row's snapshot with the
stored snapshot of its current version (`links.version`). If they are
equal (a `PATCH` that sets what was already set, a schedule that enables
an enabled link), nothing is recorded and the version number stays. If
not, `links.version` goes up by one and the new snapshot is inserted with
the actor, how the change was made, and, for a rollback, the version it
restored or, for a scheduled change, its schedule. Versions beyond the
newest 100 are deleted in the same transaction, by primary key. The cost
is three statements on a write, none on the redirect path: the redirect
role's functions return `links.*`, which carries `version`, and nothing
else there reads history.

**A rollback** (`POST /v1/links/{code}/rollback` with `{"version": n}`)
locks the link, reads version `n` and applies all of its settings through
the same code as a `PATCH`. So it is itself a new version, history only
grows, a rollback can be rolled back, and everything a `PATCH` does
follows: health counters reset if the destinations changed, other
instances and the edge hear of it through the change notification and
the KV outbox, and the audit log gets `link.rollback` with the state before
and after. The settings are restored as they were stored, not validated
again: they were valid when written, and refusing to restore a version
because, say, its `expires_at` has passed would make undo unreliable
exactly when it is needed. A version the link no longer keeps is
`not_found`.

**Schedules.** `POST /v1/links/{code}/schedules` takes `run_at` (in the
future, within 10 years) and new destinations (`url` or `destinations`,
validated and normalised like a `PATCH`), `enabled`, or both. A link has
at most 20 pending schedules, counted under the link's row lock so two
concurrent requests cannot both take the last slot. `DELETE` on a
schedule cancels it if it is still pending (`failed_precondition`
otherwise); finished schedules are kept, so the list shows what happened.

Every instance runs the scheduler, which every `RELINK_SCHEDULE_POLL_MS`
(default 1000) reads up to 100 due pending schedules, oldest first, with
their link's workspace, through the partial index. Each is then applied in
a tenant transaction for that workspace: it takes the schedule's row lock
with `FOR UPDATE SKIP LOCKED` and re-checks that it is pending and due,
locks the link, applies the change through the `PATCH` path (version
source `schedule`, audit action `schedule.apply`, as the server) and marks
the schedule `applied` with the version it produced, all before one
commit. Another instance that reads the same schedule skips it while the
lock is held and finds it applied afterwards, so each change is applied
exactly once however many instances run; an instance that dies before the
commit leaves it pending for the next tick. The instance that applied it
drops its cached copy at once, the others on the change notification. A
database outage stops the tick and leaves due schedules pending, counted
in `relink_db_errors_total{op="schedule"}`; they apply on the first tick
after it ends. A change the server cannot read (a row edited by hand) is
marked `failed` with the reason instead of being retried forever, and
counted in `relink_schedules_failed_total`. Lock order is schedule, then
link, and nothing takes them the other way round: creating a schedule
locks only the link, cancelling only the schedule.

Scheduled changes are limited to destinations and `enabled` because those
are what a campaign switches at a set time, and a change chosen long in
advance must still be valid when it runs: an `expires_at` or a targeting
rule set months ahead could be in the past, or refer to a policy that has
changed, by then.

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

### Targeting rules

`relink-core/src/rules_v2.rs` holds the rules engine both targets run:
an ordered list of `{"if": condition, "url": ...}` where conditions combine
`all`, `any` and `not` over country, ISO 3166-2 region, device, OS, browser,
preferred language, referrer host, a time window (instants, weekdays and
hours at a UTC offset) and query parameters. The first rule that holds picks
the destination; none falls through to the link's own destinations.

`compile` validates a list and flattens it into a decision list: one step
per leaf, each with a jump for true and one for false, so `all`, `any` and
`not` become jumps (`not` swaps them) and evaluation short-circuits like the
tree without a stack. Every jump goes forward, and a list holds at most 64
leaves over all its rules, so no visit tests more than 64. Each test is
bounded too: country lists are binary-searched, User-Agent and
Accept-Language reads stop at 512 bytes, and query strings at 64 parameters
within 2,048 bytes (a parameter crossing the limit is dropped, never seen
cut short). Facts are gathered once per visit and only those some leaf
reads, so a country-only list never classifies the User-Agent. On the
benchmark machine a one-leaf list takes about 26 ns and the worst case, 64
leaves all tested and every fact read, about 0.8 µs
(`cargo bench --bench hot_path -- rules_v2`).

`crates/relink-core/tests/rules.rs` checks the compiler against a naive
interpreter that walks the written tree recursively, computes every fact
up front, reads the time of day through chrono and decodes query strings
into new buffers. Each run generates 1,000 rule lists (about a fifth of them at
exactly 64 leaves, the bound) and 100 requests for each, 100,000 in all,
from small vocabularies so that rules often match, with random headers
mixed in and query strings that land around the parameter and byte limits.
For every request the compiled list, in all three forms it is loaded (by
the API, by the origin from a row, by the edge from the published decision
list), must pick the same rule and test the same number of leaves as the
tree walk: the decision list is short-circuit evaluation of the tree, so it
must stop exactly where the walk stops. Moving the query byte limit by one,
dropping the dot check from referrer subdomains or misreading a clock time
each makes it fail within seconds.

Links carry their rules as `rules` in the API (`POST /v1/links`,
`PATCH /v1/links/{code}`, where a list replaces the old one and `null` or
`[]` removes it). The server compiles every list it is given under the
destination policy, so a refused list is `invalid_argument` with the JSON
path of the part at fault (`rules[1].if.all[0].country[2]: "USA" is not a
two-letter country code`), and serde's own errors cover unknown leaves and
fields. A list that compiles is stored as written, with each rule's
destination normalised, in `links.rules` (migration 0016, a `jsonb` array
bounded to 64 KiB). It is part of `relink_core::model::Link`, so the
redirect role reads it with the rest of the row, audit entries show it,
and the edge gets it inside the link's KV record; the field is left out
of that record when a link has no rules.

On the redirect path a link's rules are compiled once. `Link.rules` is a
`RuleSet`, holding the written list and its compiled decision list. The
database column holds the written list, and the origin compiles it when it
loads a row into its cache; stored destinations are taken as the API
normalised them, so a destination policy made stricter later cannot make a
link unreadable. The KV record carries the compiled decision list instead
(`rules_v2::program`: `{"steps": [...], "urls": [...]}`), which the edge
loads after checking every promise the compiler makes (at most 64 steps and
32 rules, jumps forward and in range, value lists bounded, country lists
sorted). The edge therefore never links the compiler. Shipping it would
have cost about 19 KB of the gzipped Worker bundle, which is 249,224 bytes
with rules evaluated, under the 250 KB target (239,760 before). A record
published before this change holds the written list under `rules`, which
does not parse as a decision list, so the edge sends that link to the
origin until it is next published. `relink_core::rules::evaluate` runs them after the
disabled, expiry and country checks and before the link's destinations: a
matching rule sends the visitor to its URL with the link's status, no A/B
cookie, no health or fallback, and still takes a click (and a lease, for a
link with a click limit). Every answer from a link with rules is
`no-store`, whether or not a rule held, because a cache in between would
give one visitor's answer to the next.

Both targets pass the same facts. The origin reads `User-Agent`,
`Accept-Language`, `Referer` and the query string from the request, and the
country and region from `RELINK_COUNTRY_HEADER` and `RELINK_REGION_HEADER`,
believed only from `RELINK_TRUSTED_PROXIES`. The edge reads the country and
`regionCode` from Cloudflare's `cf` object and the rest from the request,
and when it forwards it sends all of them to the origin: the visitor's
query string on the URL, the three headers as received, and the region as
`cf-region-code` (set `RELINK_REGION_HEADER=cf-region-code` behind the
Worker). `crates/relink-edge/tests/rules.rs` generates links with random
rule lists over every leaf type and random visitors, answers each request at
the origin and at the edge (which forwards click-limited links to that same
origin), and checks that the responses are the same and that both are
`no-store`. A redirect a rule chose is counted as
`relink_redirects_total{outcome="rule"}`.

On the benchmark machine a cached link whose 64 leaves are all tested costs
about 2.2 µs in the origin handler, against about 0.96 µs for a link
without rules (`cargo bench --bench hot_path -- handler_cache_hit`).
Parsing and compiling that 64-leaf list takes about 38 µs
(`rules_v2_parse_and_compile_64_conditions`), which is why it happens once
per cached link and not per request.

### Deep links

`relink-core/src/deeplink.rs` holds both halves of mobile deep linking, and
both targets call it.

**Domain association.** A custom domain's `apps` setting names the iOS and
Android apps it belongs to (up to 8 of each). Team IDs are 10 letters or
digits, stored uppercase; bundle IDs and package names are checked for
their platform's syntax; each Android app lists 1 to 8 SHA-256 signing
fingerprints, accepted with or without colons and stored as uppercase pairs
joined by colons. A refused list names the part at fault
(`apps.android[0].sha256_cert_fingerprints[1]: ...`). The domain then
answers `/.well-known/apple-app-site-association` (and the legacy
`/apple-app-site-association`) and `/.well-known/assetlinks.json` with
`application/json`, cached for five minutes (Apple fetches the first
through its own CDN, Android the second when the app is installed), and
counts each as `relink_redirects_total{outcome="app_file"}` at the origin. The
Apple file lists each app under both `appIDs` with `components` (iOS 13
and later) and `appID` with `paths`, so every iOS version associates every
path; the domain only serves links, and an app can hand a URL it does not
handle back to the browser. A domain without apps for a platform answers
that file with its 404 page, and the default domain has neither. Both are
`relink_core::site::Target::AppFile`, read from the path before codes and
prefixes, and `apple-app-site-association` is a reserved word, so no code
can shadow it. The Worker does not parse the app list: the origin renders
both files into the domain's `host:` record (`EdgeDomain::publish`, which
leaves `apps` out of the published settings), and the edge serves them as
they are.

**App targets on links.** A link's `app` says where phones go instead of
its destinations: `ios.store_url`, the App Store page, and
`android.package`, `android.url` (the deep link, such as
`myapp://item/42` or an https app link) and an optional
`android.store_url`. Store URLs are validated and normalised like
destinations. A deep link must be `scheme://...` in at most 1,024
printable ASCII characters without `#`, with a lowercase scheme other than
`http` and the ones a browser would act on itself (`javascript`, `data`,
`file`, `intent` and the like); a refused part is named
(`app.android.url: ...`). The written form is stored in `links.app`
(migration 0017, `jsonb`, at most 8 KiB) and returned by the API.

`rules::evaluate` applies them after targeting rules and before the
destinations: a visitor whose User-Agent is iOS (iPhone or iPad) goes to
the App Store page, and an Android one to

```text
intent://item/42#Intent;scheme=myapp;package=com.example.app;S.browser_fallback_url=<store URL, percent-encoded>;end
```

which opens the app at `myapp://item/42` when it is installed and sends
the browser to the store URL, by default the package's Play Store page,
when it is not. A visit that reaches relink on iOS is one the app did not
take (with the domain's association file, an installed app opens the link
before the request is sent), so the store is the right answer there.
Crawlers, desktops and other systems follow the destinations, so link
previews show the web page. An app redirect keeps the link's status, sets
no A/B cookie, counts a click (and takes a lease for a limited link), is
counted as `relink_redirects_total{outcome="app"}`, and, like every answer
from a link with app targets, is `no-store`.

The redirect path never builds an intent per request. `Link.app` is
`AppTargets`, the two `Location` values, compiled when the origin loads
the row; a stored part that fails the API's checks (a row edited by hand)
compiles to nothing rather than to a bad header. The KV record carries the
same two strings, as the list `[ios, android]` with `""` for a platform
that is not set, so the Worker reads a list of strings it already knows
how to parse. `crates/relink-edge/tests/rules.rs` generates links with app
targets among its rule lists and checks that origin and edge answer every
visitor alike; `crates/relink-edge/tests/domains.rs` does the same for the
association files on random domains.

Fitting this into the Worker took two changes to what it parses. Records
carry compiled forms only, as above. And `Link.expires_at` is now read with
chrono's strict RFC 3339 parser instead of its `FromStr`, whose general
format parser was about 2 KB of the gzipped bundle; every record is
written by chrono, so the strict parser reads them all. The bundle went
from 249,224 to 241,476 bytes gzipped.

### Protected links

A link can ask for a password, for consent, or both, before it redirects
(`protection` in the API; `relink-core/src/gate.rs` has the pages and the
cookie, `relink-server/src/protect.rs` the rest). Disabled, expired and
geo-blocked links answer as they would without it: the page only comes in
front of a redirect. Until the visitor holds a grant, `GET /{code}`
answers 200 with an interstitial: a password field, the link's consent
text, or both, and one button. The form has no `action`, so it posts to
the page's own URL with its query string and any path prefix. When the
origin accepts it, it answers 303 back to that same URL with a grant
cookie, and the visitor's browser asks again and is redirected as usual:
rules, app targets, A/B assignment, click limits and click counting all
happen in the one place they always do. Nothing about the destination is
in the page, and a protected link's answers are never cacheable.

**Passwords.** They are 4 to 256 bytes without control characters, and
stored only as an argon2id hash in PHC form (`links.password_hash`,
migration 0019): 19 MiB of memory, two passes, one lane, a 16-byte random
salt, the OWASP baseline. argon2 is the one dependency added for this,
because a password hash for a secret people choose must be memory-hard; a
fast hash such as SHA-256 would let anyone who reads the table try
billions of guesses a second. Hashing runs on tokio's blocking pool, at
most two at once, so it can take at most 38 MiB however many requests
arrive, and never stalls the async workers. Verification uses the
parameters stored in the hash, so raising them later keeps old passwords
working. The hash never leaves the server: `Link.protection` serialises
`password: true` without it, which is all the API, the audit log and the
version history see. Protection is not part of a link's versions at all,
so a rollback leaves it as it is and no snapshot keeps an old hash.

**Attempt limits.** Every password check first takes one of the link's
attempts for the hour (`max_attempts`, 1 to 1,000, 10 by default) from
`link_password_attempts`, through `relink_password_attempt`, which locks
the link's row for the decision, so instances racing for the last attempt
cannot both win. A right password gives its attempt back
(`relink_password_refund`), so the limit counts wrong ones, and since the
attempt is taken before hashing, an attacker can make the origin compute at
most `max_attempts` hashes per link per hour. With the attempts used up, a
form answers 429 with `Retry-After` until the hour from the first attempt
is over, without hashing, and the page says how long to wait. The limit
is per link, not per visitor: a guesser can lock a link's legitimate
visitors out for an hour, but cannot get around it by changing address,
and an owner can raise the limit, which applies at once. The trade suits
links whose password is shared with a known group; a per-address limit
would be the other choice, and belongs with the threat model of week 43.

**Consent.** The consent text (1 to 1,000 characters, trimmed, newlines
kept, other control characters refused) is shown as escaped plain text;
the form carries `consent=yes`, and a submission without it is asked
again (400). With a password as well, both are on one page and both are
needed.

**Grants.** The cookie is `rl.<code>` (`.` is not a code character, so it
never meets an A/B cookie), `HttpOnly; SameSite=Lax; Path=/`, `Secure`
unless `RELINK_COOKIE_SECURE=false`, with the value
`<expiry in unix seconds>.<tag>`: the first 16 bytes of HMAC-SHA256, under
the cookie key, over the link ID, a digest of the password hash and the
consent text, and the expiry. A grant lasts 12 hours with a password and
30 days for consent alone. It cannot be moved to another link, extended,
or kept across a change: a new password or new consent text changes the
digest and revokes every grant at once, with nothing stored per visitor.
`Path=/` lets one grant cover `/abc` and `/campaign/abc` on a custom
domain.

**The pages.** Both the interstitial and the preview are a few hundred
bytes of HTML with one inline style sheet, under
`default-src 'none'; style-src 'unsafe-inline'; base-uri 'none';
form-action 'self'; frame-ancestors 'none'`, with `no-store`, `nosniff`
and `Referrer-Policy: no-referrer`. They run no script, so a visitor
without JavaScript gets the same page, and they cannot be framed for
clickjacking. A form is read only as `application/x-www-form-urlencoded`
(415 otherwise) and only up to 4 KiB (413).

**Previews.** `/{code}+`, and `/{prefix}/{code}+` on a custom domain, is
the link's preview page (`site::Target::Preview`): the link's path and
where this visit would go, decided by `rules::evaluate` exactly as the
redirect would be (so a link with targeting rules previews the visitor's
own destination), with a note when an A/B split has more than one, and a
Continue link to the short link itself. It sets no A/B cookie, takes no
click lease and counts no click (`outcome="preview"`). A disabled, expired
or geo-blocked link answers its usual 404, 410 or 451, and a protected
link's preview says only that it is protected. Only GET previews; a POST
to one is 405.

**At the edge.** A protected link is never published to KV: the KV sync
deletes its key, so the edge sends its visitors to the origin, the only
place that holds the hash. That also keeps a Worker deployed before this
change from redirecting past a password it does not know about. A
protected record found in KV anyway goes to the origin too, and the
Worker reads its `protection` only as far as knowing it is there
(`Protection::present`), which keeps the field's parser out of the
bundle. The Worker forwards a POST, only as a form of at most 4 KiB, to
the origin unread, with the visitor's facts as for a GET. Previews of
links in KV are rendered at the edge by the same `gate::preview` the
origin calls. The bundle went from 241,476 to 246,885 bytes gzipped,
mostly the preview page and the form forwarding.

**Metrics.** `relink_redirects_total` counts `gate` (a page shown),
`gate_accepted`, `gate_rejected` (a wrong password or missing consent),
`gate_locked` and `preview`.

### A routed link, start to finish

Week 3's features meet on one visit, in this order, at the origin and at
the edge alike:

1. **Which link.** `site` reads the path on the host: a code, a
   `/{code}+` preview, or on a custom domain one of its app association
   files, which are answered from the domain's record without a link.
2. **May they.** A protected link shows its password or consent page
   until the visitor holds a grant cookie for its current password and
   text. Only the origin holds the hash, so the edge forwards these.
3. **Is it live.** Disabled, expired, click-limited and geo rules answer
   as they did before.
4. **Targeting rules.** The compiled decision list runs over the visit's
   facts; the first rule that holds picks the destination.
5. **App targets.** With no rule holding, iPhones and iPads go to the App
   Store and Android browsers to the intent URL with its store fallback.
6. **Destinations.** Everyone else gets the link's own destinations, with
   A/B and health checks as before.

Any answer from steps 4 and 5, or from a link that has either, is
`no-store`, so no cache keeps an answer meant for another visitor. Edits,
rollbacks and applied schedules all go through the `PATCH` path. They
update the cache on every instance, notify the other instances and queue
the KV record, so the next visit at either target sees the new version.

`tests/smart_links.rs` walks this on two instances, with the edge's
request logic in front of them reading what the KV sync published:

- a verified domain's association files
- a link with rules over every kind of fact and app targets, giving 16
  visitors the same answer from either instance and the edge (the edge
  answers all of them itself)
- an edit, a schedule both schedulers race to apply, and a rollback, each
  followed by the edge
- a password and consent page that the edge never holds, wrong guesses
  limited across instances, and a grant that works at both
- previews, and the audit chain verified by the binary

Step 7 of `examples/demo.sh` shows the same from the command line.

## Click limits without a write per click

This is escrow (O'Neil, "The Escrow Transactional Method"). Each instance
reserves a block of clicks with one call to `relink_reserve_clicks`
(migration 0014) and spends it from an atomic counter. The function locks
the row, then updates the version it locked:

```sql
SELECT clicks_reserved, max_clicks INTO reserved, lim
  FROM links WHERE id = p_link FOR NO KEY UPDATE;
-- 0 when there is no limit or nothing is left
grant_n := LEAST(p_max_lease, GREATEST(1, (lim - reserved) / 8), lim - reserved);
UPDATE links SET clicks_reserved = reserved + grant_n WHERE id = p_link;
RETURN grant_n;
```

This used to be one `UPDATE ... FROM (SELECT ... FOR NO KEY UPDATE)` that
joined the row to a locked copy of itself. Under load, with click flushes
holding key-share locks on the row through their foreign keys, two
reservations could deadlock: the outer update waited a second time for a
tuple lock that the next reservation already held while waiting on the
first (#76). Locking and then updating as separate statements, inside one
function call, waits at most once and still costs one round trip.
`NO KEY UPDATE` rather than `UPDATE` keeps reservations from queueing behind
those flushes.

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
click limit. Protected links are never in KV, and a POST (a protected
link's form) is forwarded unread ("Protected links" above). The country and
region come from Cloudflare's `cf` object,
which clients cannot set; the visitor's address from `CF-Connecting-IP`. They
are passed to the origin, which believes them because the edge is in its
`RELINK_TRUSTED_PROXIES`, with the visitor's query string, `User-Agent`,
`Referer` and `Accept-Language`, so targeting rules decide there as they
would have at the edge.

Each isolate keeps the link records it has parsed, by KV key
(`logic::Parsed`: at most 256 records and 2 MiB of text, oldest dropped
first). An entry is reused only while KV returns exactly the text it was
parsed from, so a hot link costs a string comparison instead of a parse,
and a changed record is parsed afresh on its first read: the cache can
never answer with something KV no longer says.

### Custom domains at the edge

Both sides read the host the same way, with `relink_core::host`:
`custom_host` drops the port and a final dot and returns `None`, meaning
the default domain whatever domains exist, for a missing `Host`, an IP
address, a single label, a malformed port or the default host itself
(`RELINK_PUBLIC_BASE_URL`'s host at the origin, `DEFAULT_HOST` in the
Worker). Anything else might be a verified domain, compared in lowercase.

KV holds three kinds of record (`relink_core::wire`):

| Key | Value | Written while |
|---|---|---|
| `link:<code>` | the link | the link exists on the default domain |
| `link:<host>/<code>` | the link | the link exists on the verified domain `<host>` |
| `host:<host>` | `{"id": <domain id>, "settings": {...}, "files": [<apple-app-site-association>, <assetlinks.json>]}` (settings left out while they are the defaults, `apps` always; `files` left out without apps) | `<host>` is a verified domain |

Hostnames and codes never contain `/`, so no two records share a key, and
only canonical keys parse (`KvKey::parse`): lowercase hostnames the
`domains` table accepts and plausible codes.

For a host that might be a custom domain the Worker reads
`link:<host>/<code>` first. When it is missing, `host:<host>` decides: a
verified domain without that code goes to the origin (KV may not have the
link yet, and a custom domain must never fall back to the default domain's
link of the same code), while a host that is not a domain is the default
domain, read from `link:<code>`, exactly as the origin routes it. A failed
read or a record that will not parse goes to the origin. So a link on a
custom domain costs one KV read, the same as a default-domain link
requested on `DEFAULT_HOST`; only default-domain links requested on other
hostnames cost three. The record for the host is read only on a miss
because a hit already proves the domain is verified: domain links are
published only while their domain is.

A domain's settings are in its record. `/` and paths that are not a plain
code read the record first (one read), then the link they name (a second):
`/campaign/abc`, or `/ABC` on a case-insensitive domain. The root redirect
and the domain's 404 page for paths that cannot be a code are answered at
the edge from the record alone. A link found by the one-read path reads
the record only if it needs the domain's 404 or 410 page. Codes the domain
may have but KV does not still go to the origin, which answers with the
same page.

A Worker cannot set `Host` on a fetch, so when it forwards to the origin
it names the visitor's host in `x-forwarded-host`. The origin routes by the
first value of that header when the peer is in `RELINK_TRUSTED_PROXIES`,
and by `Host` otherwise. A visitor gains nothing by sending it: `Host` is
theirs to choose anyway. The Worker forwards the host part it routed by
itself (`relink_core::host::host_part`: no port, no final dot), not the
raw header, and nothing when there is none. Forwarding the raw value let a
`Host` of `a.example.com,b.example.com`, which the edge reads as the
default domain, reach the origin as `a.example.com`; the property test
below found it.

`crates/relink-edge/tests/domains.rs` checks that the two agree on every
domain decision. Each case generates verified domains with random settings
(root redirect, pages, prefixes, case rule) and links on them and on the
default domain (live, expired, disabled, click-limited), loads them into
an origin `App` and into the KV records the sync would publish, and sends
random `Host` values (any case, ports, final dots, IP literals, unknown,
listed and malformed hosts) and paths (prefixes, mixed case,
percent-encoding, junk) to both: to the origin directly, and to the edge,
which forwards what it cannot answer to that same origin from a trusted
address. Status, `Location`, content type, security headers and body must
be equal. The one allowed difference is the default domain's `/` and
multi-segment paths, which the origin answers as unknown API paths and the
edge, which serves no API, with its plain 404. A second test pins the
cases the edge must answer itself, so the property cannot pass by
forwarding everything. The `host` fuzz target feeds arbitrary bytes to the
`Host` reader, the forwarded value, the origin's routing, hostname
validation for new domains and path reading on a custom domain, and checks
that they agree.

With `RELINK_KV_ZONE_ID` set, the sync also manages the zone's custom
hostnames (Cloudflare for SaaS), which is what routes a domain's traffic to
the Worker and gives it Cloudflare's certificate. Syncing `host:<host>` for
a verified domain first makes sure the hostname is registered (looked up by
name, created with HTTP validation if absent), then writes the record; for
a domain that is gone it deletes the record, then removes the hostname. A
failure at either step fails the whole entry, which is retried. The same
API token is used, so it then needs custom hostname edit rights on that
zone. Without a zone ID the operator routes custom domains to the Worker
by other means, and the KV records work the same.

### Getting records into KV

The origin publishes through a transactional outbox (Chris Richardson,
["Pattern: Transactional outbox"](https://microservices.io/patterns/data/transactional-outbox.html)).
Every link change inserts the link's KV key into `kv_outbox` in the same
transaction, and verifying or deleting a domain inserts its `host:` key, so a
committed change cannot be forgotten. Migration 0013 turned the outbox from
codes into whole KV keys (and prefixed the entries already queued), with a
check that every entry is a `link:` or `host:` key. A worker claims due
entries with `FOR UPDATE SKIP LOCKED`, reads the current state (the link by
domain and code through the redirect role's lookup, or the verified domain
by hostname), and PUTs its JSON to the Cloudflare KV REST API, or DELETEs
the key if the record is gone. A key relink would never write is deleted. The entry is
removed only after KV accepted the write and only if it was not re-queued in
the meantime. A failed write pushes the entry's next attempt back
exponentially, from 1 s up to 10 minutes. The worker wakes on the same change
notifications the caches use, and polls once a second as a fallback.

An outbox only covers changes made through relink. Keys deleted by hand, or a
namespace restored from an old copy, are caught by a reconciliation that runs
at start and hourly: it lists every `link:` and `host:` key in KV, walks every
published link (default domain and verified domains, 5,000 at a time in
domain and code order) and every verified domain, and queues the
differences. It compares key sets, not values; stale values are the outbox's
job. With a zone configured it also lists the zone's custom hostnames and
queues every verified domain missing there, so a hostname deleted in the
dashboard comes back. It never removes a hostname on its own: the zone may
hold names relink did not add. If the hostname list fails, the whole
reconciliation fails and runs again on the next tick, rather than queueing
every domain. Domains verified before migration 0013 are published by the
first reconciliation after it.

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
than delaying the visitor. One flusher aggregates by `(link, hour, country,
device, referrer)`, keeps the raw events, and every second or 5,000 clicks
writes with `INSERT ... SELECT FROM UNNEST(...) ON CONFLICT DO UPDATE`
(see "Rollups" below for everything one write feeds). Rows are merged by
their stored key first, because Postgres refuses a statement that updates the
same row twice; a missing referrer is stored as `(direct)`, which no parsed
host can equal.

Writes go in transactions of at most 5,000 hourly count rows, 5,000 visitor
rows and 5,000 raw events, so a large backlog after an outage never needs
one statement that outlives the query timeout. On failure the batch is kept
whole and retried with backoff, and the rest stays pending, bounded by
`RELINK_CLICK_BACKLOG` rows; past that, clicks are dropped and counted. Raw
events take one entry per click, so they have their own bound,
`RELINK_CLICK_EVENT_BACKLOG`; past it a click still reaches every rollup and
only its raw event is dropped, counted in
`relink_click_events_dropped_total`. A batch the database refuses three times
for a reason other than unavailability is dropped and counted as `rejected`,
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

### Rollups

One flush transaction feeds everything at once, so the tables never
disagree about which clicks they hold:

| Table | Written as |
|---|---|
| `click_daily` | Upsert adding counts per link, day and dimension. |
| `click_hourly` | The same per UTC hour, with the link's workspace. |
| `workspace_usage` | The quota meter: the day's clicks added to the workspace's month. |
| `visitor_daily` | Visitor hashes, `ON CONFLICT DO NOTHING`. |
| `visitor_sketch_hourly`, `visitor_sketch_daily` | Sketches merged into the stored ones. |
| `click_events` | One row per click. |

The daily rows of a batch are its hourly rows added up by day, so the two
always agree, and both agree with the raw events per dimension; a test
checks that against Postgres.

**Idempotent on replay.** A batch gets 16 random bytes as its key when it
is formed, and its transaction starts with `INSERT INTO click_batches ...
ON CONFLICT DO NOTHING`. A failed batch is kept whole, with its key, and is
the first thing written on the next attempt. Most failures roll the
transaction back, and the retry simply writes it. But a connection can drop
after `COMMIT` reached the server and before its answer came back. Then the
retry finds its key, writes nothing and reports a replay
(`relink_click_batches_replayed_total`), so no count, quota or event is added
twice. Keys are kept a week (a batch is only ever retried by the flusher
that made it, which gives up at shutdown) and deleted by housekeeping.

**Visitor sketches.** Each batch builds, per link, a sketch for every hour
and every day it covers, and merges them into `visitor_sketch_hourly` and
`visitor_sketch_daily`. A plain upsert cannot merge, because the new value
depends on the stored one, so the transaction:

1. creates the missing rows empty with `ON CONFLICT DO NOTHING`, in key
   order, which also waits for any other flusher inserting the same key;
2. locks and reads the rows with `SELECT ... FOR UPDATE`, in key order;
3. merges here and writes the results back.

Concurrent flushers therefore lock the same rows in the same order: no
deadlock, and no flusher overwrites another's visitors. Eight flushers
merging into the same rows at once end with exactly the sketch of all
their visitors, in a test. Merging is idempotent too, but the batch key
already guarantees a sketch is merged once.

A sketch is fed `HMAC-SHA256(day's salt, "hll" | fingerprint)[0..8]`. This is
the same value for every link on a day, so sketches of different links merge
into the visitors of all of them: someone who clicked two links counts
once. The link ID is left out on purpose here, unlike `visitor_daily`. The
key is the day's salt, which is destroyed after two days, and a sketch keeps
at most 25 bits of each hash (see "Unique visitor sketches"). Across days a
returning visitor counts once per day, because the salt changes. That is the
same rule as the daily counts.

**Edge clicks** carry only their UTC day (`WireClick::day`). The origin places
such a click at the time it arrived, moved into the reported day if that is
yesterday or tomorrow. The edge sends within five seconds, so the hour is
right but for clicks sent across the hour.

**Retention.** Hourly rows and hourly sketches are kept for
`RELINK_CLICK_HOURLY_RETENTION_DAYS`, 92 by default (1 to 3,660). Daily rows
and daily sketches stay as long as their link. Housekeeping deletes at most
50,000 expired rows per table per minute, so a lowered retention drains
gradually and never holds locks for long.

**Cost.** Against a local Postgres 16, 100,000 clicks that are each a new
row in every table (a distinct referrer and visitor per click, the worst
case) drain in 7.9 s, in 20 transactions of about 0.4 s. Before this, when
only the daily tables and visitor hashes were written, the same clicks took
3.5 s. Raw events are the largest part. Typical traffic repeats its
dimension keys, so most clicks add to an existing hourly row and only the
raw event is new.

### Raw events and partitions

The daily aggregates answer one question each. To slice by any dimension
over any period, every click is also kept as a row in `click_events`
(migration 0020). The table is partitioned by range on `at`, one partition
per UTC calendar month, named `click_events_pYYYYMM`.

Retention is in whole months, counting the current one:
`RELINK_CLICK_EVENTS_RETENTION_MONTHS`, 13 by default, so a full year
before the current month is always there. Expiring a month is a
`DROP TABLE` of its partition. It frees the space at once, writes no WAL
per row, leaves no dead tuples for vacuum and takes the same time for a
million rows as for ten. A `DELETE ... WHERE at < cutoff` on one large
table does none of that.

The partition manager (`src/partitions.rs`) runs in every instance's
housekeeping loop, once a minute. It creates the partitions for the
current month and the two after it, and drops those older than the
retention. Months are created two ahead, so a month boundary never finds
its partition missing, even after the servers were stopped for weeks.
Without a partition an insert fails, and the table has no default
partition. A default partition would hide the problem, and Postgres would
then have to scan it before it could create the missing month.

Each run is one transaction, in which the manager:

- takes `pg_try_advisory_xact_lock`. If another instance holds it, the run
  does nothing, so instances never race to create the same month;
- sets `lock_timeout = '1s'`. Creating or dropping a partition takes a
  strong lock, and Postgres queues every later insert behind a waiting
  lock request. Behind a long analytics query the run gives up after one
  second, rolls back everything, and tries again a minute later;
- creates months through `relink_click_events_partition(date)`. The
  migration uses the same function for its first three months. It writes
  the bounds in UTC with an explicit offset, so the session's time zone
  cannot move a month boundary;
- drops only partitions whose name is exactly `click_events_p` and six
  digits. An operator's own partition, for example an archive attached by
  hand, is reported and left alone.

`relink_click_partitions_created_total` and
`relink_click_partitions_dropped_total` count the changes.

An event holds no client address, for the same reason the aggregates do.
`visitor` is the HMAC of the day's salt, the link and the fingerprint,
the value stored in `visitor_daily`. Two days later the salt is destroyed,
and from then on nobody can link the hash to an address. Within one link
and day it still tells visitors apart, which unique counts over any slice
need.

There is no foreign key to `links`. Checking one would add a lookup to
every insert, and `ON DELETE CASCADE` would search every partition when a
link is deleted. Events of a deleted link leave with their month.
`workspace_id` is stored on each event, so the tenant policy
(`workspace_id = relink_current_workspace()`) needs no join and uses the
`(workspace_id, at)` index. Neither policies nor grants pass from a
partitioned table to its partitions, and `relink_tenant` holds no grant on
any partition. A tenant transaction therefore reads events only through
`click_events` and its policy, and reading a partition by name is refused.
Tenants cannot write events.

### Unique visitor sketches

Counting unique visitors from `visitor_daily` rows costs a row per visitor
per link and day, and a count over many links or days has to read and
de-duplicate all of them. A HyperLogLog sketch holds a fixed amount of state
per link and period instead, and the sketches of two periods merge into the
sketch of their union. `relink-core/src/hll.rs` implements HyperLogLog++
(Heule, Nunkesser and Hall, "HyperLogLog in Practice", EDBT 2013), in the
core so the edge can build the same bytes:

- **Hash.** 64 bits. Visitor hashes are already uniform keyed hashes, so
  their first 8 bytes are used as they are (`insert_hash`); any other item
  goes through the first 8 bytes of SHA-256 (`insert`), which never changes
  between builds, as stored sketches require.
- **Dense form.** Precision 14: the first 14 bits pick one of 16,384
  registers, and a register keeps the longest run of leading zeros, plus
  one, seen in the remaining 50 bits (0 to 51, 6 bits). In memory a byte per
  register, 16 KiB; stored packed, 12,288 bytes.
- **Sparse form.** For small sets, a sorted list of the first 25 bits of
  each hash, with the run length of the remaining 39 bits kept only when the
  11 bits after the dense index are all zero (otherwise the dense value can
  be read from the index itself). The estimate is linear counting over 2^25
  buckets, which is exact but for two hashes sharing 25 bits: about
  n²/2^26 pairs, 0.14 at the limit. Past 3,072 entries, where 4 bytes each
  would outgrow the dense registers, the sketch converts to dense, and
  converting gives exactly the registers a dense sketch of the same hashes
  would hold. Most links get far fewer visitors than that per hour or day,
  so most sketches stay sparse, at 2 to 3 bytes per visitor stored.
- **Estimate.** The paper corrects the dense estimate with empirical bias
  tables for each precision. Here the dense estimate is Ertl's improved
  estimator ("New cardinality estimation algorithms for HyperLogLog
  sketches", 2017, algorithm 6), computed from the histogram of register
  values. It needs no tables and is unbiased from a few thousand items to
  billions. The relative standard error is 1.04/√16384 = 0.81%.
- **Merge.** Sparse with sparse is the union of two sorted lists, keeping
  the larger value per index; anything with a dense sketch is a
  register-wise maximum. A sketch depends only on the set of hashes put
  into it, not on their order or on how it was assembled from merges, so a
  merged sketch is byte for byte the sketch of the union. A property test
  checks this, together with commutativity, associativity and idempotence.
- **Stored form.** Version, precision and kind bytes, then either the
  entry count and per entry the varint gap from the previous index (and the
  run-length byte where there is one), or the packed registers. Decoding
  refuses anything the encoder could not have written: another version or
  precision, unsorted or out-of-range indexes, non-minimal varints,
  impossible values and trailing bytes.

Accuracy is tested against exact counts from fixed seeds
(`crates/relink-core/tests/hll.rs`). Sparse sketches up to 3,000 items are
within 0.1% in every trial. From 3,500 to 1,000,000 items, 384 dense
sketches have an RMS relative error of 0.65% and a bias of −0.03%; the
worst single sketch is 2.2% off, under three standard errors. Merging 40
links over 30 days, or 48 trials of 30 overlapping daily sketches, gives the
sketch of the union exactly, with an RMS error of 0.65%.

The sparse form keeps 25 bits of each hash, enough to test whether a known
item is in a sketch. Sketches are therefore only ever fed keyed hashes
whose key is not stored next to them, such as the salted visitor hash,
never addresses or fingerprints.

On the benchmark machine (4 cores of a 2.1 GHz Xeon; `cargo bench --bench
hot_path -- hll`), adding a visitor hash takes 3 ns to a dense sketch and
21 ns to a sparse one with 1,000 entries; through SHA-256, 78 ns. Merging
30 daily sketches into a month takes 13 µs when they are dense and 38 µs
when they are sparse with 100 visitors each (the list is rebuilt on every
merge). A dense estimate takes 11 µs, a sparse one 25 ns. Decoding a stored
dense sketch takes 10 µs and a 1,000-entry sparse one 2.8 µs.

### Querying analytics

`GET /v1/analytics` (`src/analytics.rs`) answers the questions the daily
stats endpoint cannot: any period of whole UTC hours, a series by hour,
day, ISO week, month or one point for the whole period, grouped by up to
three of link, country, device and referrer, filtered on any of them, the
top N groups by clicks, and the same numbers for the period just before or
a year earlier. It needs `stats:read`.

```console
$ curl -s "localhost:8080/v1/analytics?from=2026-11-01&to=2026-11-30&group_by=country&device=mobile&compare=previous" \
    -H "Authorization: Bearer $KEY"
```

**Which rollups answer it.** A period of whole days at a granularity of a
day or longer reads `click_daily` and `visitor_sketch_daily`, which are
kept as long as their link. Anything else reads `click_hourly` and
`visitor_sketch_hourly`, and is refused with a clear message if it reaches
further back than `RELINK_CLICK_HOURLY_RETENTION_DAYS`, rather than
returning a silently short answer. Dates as `to` are included (the period
ends at the next midnight); RFC 3339 times must be whole hours, and `to` is
excluded. Points start where `date_trunc` puts them in UTC, the series has
every point with 0 for those without clicks, and the period is at most 366
days and 1,000 points.

**Unique visitors** are the merge of the sketches the period covers (see
"Unique visitor sketches"), estimated once per point, per top link and for
the total. Sketches exist per link and hour or day, not per country, device
or referrer, so `visitors` is null whenever the query groups or filters by
one of those: a number there would be wrong, not approximate. Sketches are
fed a hash keyed by the day's salt, so over several days a visitor counts
once per day, as in the daily stats. The sketches are streamed in time
order and merged one point at a time, so a query holds at most one sketch
per point being built, per top link and for the totals (16 KiB each when
dense), never all the rows it reads.

**One statement for the clicks.** The clicks query is a single statement
over a `MATERIALIZED` CTE that reads the rollup rows once. From it the
statement returns, tagged by kind: the number of rows read, the total per
point, the compared period's total, and, for the top N groups (ranked by
clicks, ties in byte order of their values so the database and the server
agree), their clicks per point and in the compared period. The compared
period is read in the same scan (`cur` marks rows of the period itself), so
it costs no second query. Dimension names and `date_trunc` units come from
fixed lists in the code; every value is a bound parameter. Without a link
filter the scan goes through `link_id IN (SELECT id FROM links)`, which
row-level security limits to the workspace, so the rollups' primary keys
(which start with `link_id`) serve it. Links in a filter are named `code` or
`hostname/code` and resolved first; one the workspace does not have is a
404, as everywhere else.

**Cost limit.** A query may read at most `RELINK_ANALYTICS_MAX_ROWS`
rollup rows and sketches in total (1,000,000 by default, 1,000 to 10⁸). The
CTE carries `LIMIT max + 1`, and the sketch scan `LIMIT` of what remains, so
however broad the query, Postgres stops one row past the limit, and the
query is refused with 422 `query_too_expensive` and a hint to narrow it.
The answer reports `rows_scanned`, so callers can see how close they are.
Everything runs in one `REPEATABLE READ, READ ONLY` transaction, so the
clicks, the sketches and the link names come from the same snapshot, and
within the query timeout like every other API query.
`relink_analytics_queries_total`, `relink_analytics_queries_refused_total`
and `relink_analytics_rows_scanned_total` count them.

**Cost.** On the benchmark machine (4 cores of a 2.1 GHz Xeon, local
Postgres 16), with one workspace of 1,000 links, 1.2 million hourly rows
over 30 days and a sparse daily sketch per link and day, measured over HTTP:

| Query | Rows read | Time |
|---|---|---|
| 30 days by day, grouped by country | 60,000 | 60 ms |
| 30 days by day, grouped by link, with visitors | 89,000 | 140 ms |
| 15 days by hour, total only | 603,000 | 330 ms |
| 15 days by hour, grouped by country | 603,000 | 470 ms |
| 26 days by hour, refused at the limit | 1,000,001 | 550 ms |
| 26 days by hour, two links named | 2,087 | 50 ms |

A refused query costs about as much as the largest one allowed, well inside
the 2-second query timeout. The transaction turns JIT off: the planner's
estimates for scans under row-level security cross JIT's threshold, and
compiling took about 300 ms, longer than the 60 ms query it was compiling.

### Bots and link previews

Pasting a link into a chat app or a social post makes the app fetch it to
draw a card, and crawlers, uptime monitors and scripts follow links too.
Counted as people, they inflate clicks the moment a link is shared.
`relink-core/src/classify.rs` recognises them from the User-Agent, at the
origin and at the edge alike, with a versioned list:

| Kind | Examples |
|---|---|
| `crawler` | Googlebot, Bingbot, Applebot, AhrefsBot, GPTBot, ClaudeBot, CCBot |
| `preview` | facebookexternalhit (also iMessage), Twitterbot, Slackbot, Discordbot, WhatsApp, TelegramBot, LinkedInBot, Mastodon, Bluesky |
| `monitor` | UptimeRobot, Pingdom, StatusCake, Datadog Synthetics, Lighthouse |
| `tool` | curl, Wget, python-requests, Go's client, axios, Postman, headless Chrome |

`AGENTS` holds about 90 named tokens; when none matches, the generic words
`bot`, `crawl`, `spider`, `preview` and `headless` catch the rest, except
inside words of real browsers such as the CUBOT phone brand. Real in-app
browsers (Facebook's FBAN, Instagram, LinkedInApp, Telegram-Android) are not
bots: they are people reading the page. The list is checked when the crate
compiles (sorted by first byte, lowercase, no token shadowed by an earlier
one), and `BOT_LIST_VERSION` (now 1) must change with it: a test pins a
digest of the list to the version.

Matching reads the first 512 bytes, lowercased. Named tokens match where a
word starts (at the start or after a byte that is not a letter or digit),
which is where every real client puts its name; the first one found wins,
so a preview fetcher built on an HTTP library is still a preview. The scan
finds word starts eight bytes at a time with SWAR range tests, rejects
almost every word with an 8 KiB bitmap of the tokens' first two bytes, and
compares only the few tokens that share the word's first two bytes, both
tables built at compile time. The generic words are then five `contains`
calls. On the benchmark machine `device_class` of a browser's User-Agent
went from 153 ns (ten hard-coded tokens) to 222 ns, and the cached-redirect
handler benchmark showed no significant change; the Worker bundle grew by
2.1 KB gzipped, to 249,111 bytes, close to the 250 KB target.

A User-Agent is whatever the client sends, so this catches clients that
announce themselves, which the well-behaved ones do; one that claims to be a
browser counts as a browser.

What happens to a bot's click:

- It is counted, in every rollup, under the device class `bot`, so nothing
  is lost and the stats endpoint still shows it in its device breakdown.
- Its raw event has `bot = true` and no visitor hash.
- It is never a visitor: it feeds no visitor hash and no sketch. Sketches
  have no device dimension, so this is the only way to keep bots out of
  unique visitors.
- `GET /v1/analytics` leaves it out (`device <> 'bot'` on the click scan)
  unless the query has `include_bots=true`; filtering by `device=bot`
  without it is refused, since it could only return nothing. Every answer
  says `include_bots` and the `bot_list_version` that classified it.
  `visitors` are people either way.
- Targeting rules can route `device: ["bot"]`, for example to send
  previews a static page.

Quotas and click limits count bot clicks like any other: the redirect was
served either way.

### Live clicks

`GET /v1/links/{code}/live` is a server-sent events stream of one link's
clicks as they happen, for a console showing a launch or a campaign going
out. It needs `stats:read`, like every other analytics read, and shows what
the rollups keep: time, country, device class, referrer host and whether it
was a bot. Bots are left out unless the stream asks for
`include_bots=true`. The stream opens with an `open` event, then sends one
`click` event per click.

`src/live.rs` keeps one broadcast channel per workspace with a stream open
and a map from each watched link to its workspace. A click is offered to
it as it is taken, before the click queue, at the origin and from the edge
batch alike. With no link watched anywhere that is one atomic load; with
some, a read lock and a map lookup. A click on a watched link is sent once
to its workspace's channel, and each stream keeps the clicks on its own
link. The redirect never waits for a stream.

**Backpressure.** A channel is a ring of `RELINK_LIVE_BUFFER` (256) clicks.
A stream reads it only as fast as its connection takes bytes, so a slow
client falls behind alone. Once it is a ring behind, the oldest clicks are
overwritten; the stream gets a `lag` event with how many it missed and
carries on from the oldest click still held. That count covers the
workspace's channel, so it is an upper bound for the stream's link. Clicks
waiting when a stream is woken go out in one write, up to 64.

**Limits.** At most `RELINK_LIVE_MAX_PER_WORKSPACE` (50) streams per
workspace and `RELINK_LIVE_MAX_STREAMS` (10,000) per instance; more are
refused with 429 `resource_exhausted`. An idle stream gets a comment every
`RELINK_LIVE_KEEPALIVE_MS` (15 s) so proxies keep it open, and
`X-Accel-Buffering: no` asks nginx not to buffer it. A stream ends after
`RELINK_LIVE_MAX_AGE_S` (an hour). `EventSource` reconnects by itself, and
signs in again, so a revoked key or session stops streaming within the
hour. Shutdown ends every stream first, so the drain waits only for
ordinary requests.

**Across instances.** A visitor's click lands on whichever instance the
load balancer chose, and the stream may be open on another. An instance
with streams announces its watched link IDs on the `relink_live`
notification channel, at once when a link is first watched and then every
`RELINK_LIVE_ANNOUNCE_MS` (10 s). Every instance remembers links watched
elsewhere for three intervals. A click on such a link goes on a bounded
relay queue (`RELINK_LIVE_RELAY_QUEUE`, 4,096; dropped and counted when
full, never waited for). The relay task sends everything queued at once
with `pg_notify`, split under Postgres's 8,000-byte payload limit, about
150 clicks per notification. Receivers parse each line as strictly as an
edge click and hand the clicks to their streams; an instance ignores its
own notifications. Nothing is written to a table, and with no stream open
anywhere, nothing is sent. A stream opened on another instance gets
relayed clicks once the first announcement arrives, normally a few
milliseconds after it opens.

**Latency.** A click on the same instance is in the stream as soon as the
redirect has been answered; a relayed one adds a notification round trip.
`tests/live.rs` checks both are under a second. Clicks served by the edge
reach the origin in its batches (50 clicks or 5 s), so they appear with
that delay.

### A click, start to finish

Week 4's parts meet on every click, in this order, at either instance and
for clicks the edge sends in its batches alike:

1. **Classify.** The redirect reads the click's country, device class and
   referrer host; `classify::bot_kind` marks crawlers, link-preview
   fetchers, monitors and tools as device class `bot`. A person also gets
   a fingerprint from their address and User-Agent, which never leaves
   memory.
2. **Live.** The click is offered to `LiveHub` before anything else: to
   the streams on this instance watching its link, and to the relay when
   another instance has announced it watches the link.
3. **Queue.** The click goes on the bounded click queue with `try_send`.
   Nothing in steps 2 to 6 makes the redirect wait.
4. **Flush.** One transaction, keyed against replay, adds the click to
   the daily and hourly rollups and the quota meter. For a person it adds
   a keyed hash to the hourly and daily visitor sketches. The raw event,
   without the fingerprint or any address, goes to its UTC month's
   partition of `click_events`.
5. **Query.** `GET /v1/analytics` reads the daily or the hourly rollups
   and merges the sketches of the links and periods asked for. It leaves
   bots out unless asked to include them.
6. **Retention.** Hourly rows expire after their retention and whole
   months of raw events are dropped, while the daily rollups stay as long
   as their link.

`tests/click_analytics.rs` walks this on two instances:

- two days of edge batches for two links that share 300 people
- live streams on one instance, getting each click within a second from
  either instance and from the edge, and bots only when asked for
- people, a crawler and two link previews over HTTP
- the query API answering alike at both instances: by day and by hour,
  grouped by link, country, device and referrer, filtered, top N and
  compared with the day before; unique visitors are within 1% of the exact
  count of people per link, per day and over both
- raw events in their month's partition, with no column for an address and
  no address or User-Agent in any value
- an old month dropped by the partition manager, with the rollups intact
- another workspace seeing none of it

Step 8 of `examples/demo.sh` shows the same from the command line.

## Webhooks

A workspace admin registers an endpoint (`POST /v1/webhooks`) for any of
four events: `link.created` and `link.updated` when someone creates or
changes a link (through the API, a rollback or a schedule), `link.expired`
when a link's `expires_at` passes, and `health.changed` when a
destination's health check result flips. `src/webhooks.rs` holds all of
it; migration 0022 the tables.

**Written with the change.** An event becomes one row per subscribed,
enabled endpoint in `webhook_deliveries`, inserted by `webhooks::emit` in
the same transaction as the change: `Tenant::insert_link` and
`Tenant::apply_patch` for link changes, `Db::record_health` for health.
A change that commits is always delivered eventually; one that rolls back
never is. With no endpoint subscribed, `emit` is one insert that selects
nothing from a workspace's few `webhooks` rows. A patch that changes
nothing a client sees (only bookkeeping such as `version` or
`updated_at`) sends nothing. `link.updated` carries the link now, the
names of the fields that changed and their previous values.

**Expiries.** Nothing happens in the database when an expiry passes, so the
delivery worker looks for links whose `expires_at` is past and differs from
`links.expiry_announced`, through a partial index that holds only links
with an expiry not yet announced. Each is marked announced and its event
written in one transaction, with `SKIP LOCKED` so instances split the work.
Keeping the expiry that was announced, rather than a flag, means moving
`expires_at` later announces the new expiry in its turn. Links that had
already expired when the migration ran are marked announced, not sent.

**Delivery, at least once.** `WebhookWorker` claims up to
`RELINK_WEBHOOK_CONCURRENCY` (16) due rows with `FOR UPDATE SKIP LOCKED`,
and in the same statement moves their due time past twice the request
timeout. The tries then run concurrently, with no lock held. A 2xx answer
marks the delivery delivered; anything else (another status, a refused
connection, a timeout, a blocked address) adds one to its tries and makes
it due again after `backoff`: `RELINK_WEBHOOK_RETRY_BASE_MS` (30 s) doubled
for each failed try after the first, capped at `RELINK_WEBHOOK_RETRY_MAX_MS`
(6 h), then scaled by a random factor between 0.5 and 1 so endpoints that
failed together do not all retry together. With the defaults the twelve
tries of `RELINK_WEBHOOK_MAX_ATTEMPTS` span 7 to 15 hours; after the
last, the delivery is failed. An instance that dies mid-try never records
it, so the row comes back when its claim runs out and is sent again. That,
and an endpoint that answers after the timeout, are why delivery is at least
once rather than exactly once. Two instances never hold the same row at
once, so in normal running each event reaches each endpoint once
(`tests/webhooks.rs` checks 40 events through two instances). Deliveries
are not ordered: a retried event can arrive after a later one.

**What is sent.** A `POST` of the stored payload, byte for byte the same on
every try:

```json
{"id": "evt_6c1f...", "type": "link.updated", "created_at": "2026-11-22T10:15:02.113Z",
 "workspace_id": 3, "data": {"link": {...}, "changed": ["destinations"], "previous": {...}}}
```

`data.link` is the link as `GET /v1/links/{code}` shows it. Headers:
`Relink-Event`, `Relink-Event-Id` (the same for every try and every
endpoint, for dropping duplicates), `Relink-Delivery` (the row in the
delivery log) and `Relink-Signature: t=<unix seconds>,v1=<hex>`, where the
hex is HMAC-SHA256 under the endpoint's secret of the timestamp, a dot and
the body. The timestamp is the time of the try, so a receiver can refuse
anything signed more than a few minutes ago; `webhooks::verify` is the
check, and its unit test pins a known answer. The secret (`whsec_` and 64
hex characters, the whole string being the key) is shown when the endpoint
is registered and when `rotate_secret` replaces it, and never again. It is
stored as is, because the server must sign with it; sealing it under the
key encryption key belongs with the encryption at rest of week 38.

**The delivery log.** Every try is a row in `webhook_attempts`: when, the
status (or none), how long it took, the error, and the first 512 bytes of
the answer. `GET /v1/webhooks/{id}/deliveries` lists an endpoint's
deliveries newest first, filtered by state; `GET .../deliveries/{delivery}`
adds the payload and every try; `POST .../retry` makes a failed or pending
delivery due now, giving a failed one one more try. Disabling an endpoint
fails its pending deliveries, so a paused endpoint does not keep the worker
scanning them; they can be retried once it is enabled again. Finished
deliveries are deleted `RELINK_WEBHOOK_RETENTION_DAYS` (30) after they were
created, 10,000 at a time each minute; pending ones never are.

**Boundaries.** Endpoints, deliveries and tries are under row-level
security like links: a workspace sees only its own, and a delivery's
composite foreign key ties it to its endpoint's workspace. Managing and
reading webhooks needs the admin or owner role (`links:write` or
`links:read`), since an endpoint receives every link of the workspace;
each change is in the audit log as `webhook.create`, `webhook.update` or
`webhook.delete`, without the secret. A workspace holds at most 50
endpoints. The URL must be https on a public host by the destination
rules, and the requests follow the health checker's SSRF defences below:
the resolver drops non-public addresses, IP literals are checked against
the same list, redirects are not followed, no proxy is used, and only the
start of an answer is read. `RELINK_WEBHOOKS_ENABLED=false` keeps an
instance from sending; events are still queued for the others.

## Conversions

A link with `conversion_window_days` (1 to 365) tracks conversions: every
redirect appends `rl_cid=<click id>` to the URL it sends the visitor to,
replacing any `rl_cid` already there and keeping the fragment last. The
destination keeps the id (in its session or with the sign-up), and its
server posts it back with what happened. `relink-core/src/conversion.rs`
mints and reads ids, `src/conversions.rs` takes the postbacks, migration
0023 the table.

**Nothing is written per click.** The id is 36 bytes, 48 characters of
base64url, and carries what attribution needs, signed:

| Bytes | Field |
|---|---|
| 0 | format version, 1 |
| 1..9 | link id |
| 9..13 | click time, Unix seconds |
| 13..15 | what chose the URL (destination, rule, app target or fallback) and its index |
| 15..19 | `SHA-256("relink-cid-url\0" \| url)[0..4]` |
| 19..26 | nonce |
| 26..36 | `HMAC-SHA256(key, "relink-cid\0" \| bytes 0..26)[0..10]` |

The key is `RELINK_COOKIE_KEY`, under its own label so a tag never passes
as an A/B cookie or a grant, and the Worker holds the same key, so the edge
mints ids with the same code and its clicks convert like the origin's. A
redirect with a click id is never cacheable (each click needs its own),
which is the one cost tracking adds to the redirect besides one SHA-256
and one HMAC. On the development machine minting and appending an id takes
0.32 µs and checking one 0.22 µs, and a cached redirect with an id 1.59 µs
against 1.03 µs without (`cargo bench --bench hot_path -- click_id`). The id is signed, not encrypted: it shows its
holder the link id, the time and the variant, nothing about the visitor,
and unlike the visitor hashes it is not stored per click anywhere. Changing
`RELINK_COOKIE_KEY` invalidates ids already handed out, as it does A/B
assignments. 80 bits of tag make a forgery a guess the API refuses.

**Postbacks.** `POST /v1/conversions` takes `click_id`, `event` (1 to 64 of
`[A-Za-z0-9_.:-]`), an optional `value` in minor units with an optional
ISO 4217 `currency`, an optional `external_id` and an optional `occurred_at`
(default now, at most 5 minutes ahead). It needs `conversions:write`. The
server checks the tag (400 otherwise), finds the link in the caller's
workspace under row-level security (404 for another workspace's link, or a
deleted one), and requires that the link still tracks conversions and that
`occurred_at` is from 5 minutes before the click to `conversion_window_days`
after it, using the link's window at the time of the post (409 otherwise).
Turning tracking off stops both the ids and the postbacks.

**Attribution.** The id names the target kind and index, so a conversion is
attributed to the destination index (the A/B variant), the targeting rule,
the app target or the fallback. The URL is named by comparing the id's hash
with what the link has at that index now and, if the destinations changed
since the click, with its kept versions (newest first). A conversion whose
URL has left all of them keeps its kind and index with `destination` null.

**Counted once.** Each conversion is one row, unique per workspace and
event on `dedup`: `x:` and `external_id` when one is given, otherwise `c:`
and the click id. So a signup counts once per click however often it is
posted, and an order counts once even if two clicks claim it. A repeated
post answers 200 with the stored row and `duplicate: true` (201 for a new
one); `ON CONFLICT DO NOTHING` makes two concurrent posts of the same
conversion store one. Rows are deleted with their link.

**Stats.** `GET /v1/links/{code}/conversions` (`stats:read`) adds up the
conversions that happened in a range of UTC days, optionally of one event,
in total and per (target, index, URL): count, distinct converted clicks,
counts per event and value totals per currency (null for plain numbers),
read in one repeatable-read snapshot from the `(link_id, occurred_at)`
index. The link's current destinations come first, in order and with zeros,
so every variant shows; then URLs it no longer has and other targets, most
conversions first. There are no conversion rates yet: the click rollups are
not kept per destination.

`relink_conversions_total`, `relink_conversions_duplicate_total` and
`relink_conversions_rejected_total` count posts by outcome.

## Bulk jobs

Imports, exports and changes to many links run as background jobs
(`src/jobs.rs`, migration 0024). Each one is a row in `jobs`, under
row-level security like links, with its kind, its parameters, a state
(`queued`, `running`, `succeeded`, `failed`, `cancelled`), counters and a
cursor saying where its next step starts.

**Uploads.** `POST /v1/jobs/import` takes the file as the body, `text/csv`
or `application/x-ndjson`, up to `RELINK_JOB_MAX_UPLOAD_MB` (256 MB). The
handler reads it as it arrives and cuts it into chunks of whole records,
at most 500 records or 1 MiB each, written to `job_chunks` in the same
transaction as the job; an upload that fails half-way leaves nothing, and
the server holds one chunk at a time. Record boundaries are found by a
scan that tracks whether it is inside a quoted CSV field, so a quoted
field may hold newlines and the cut falls in the same place however the
body arrives (a property test cuts random files at random places). A
byte order mark and blank lines are dropped. What refuses a whole upload
is what can be told without looking at a record's meaning: an unknown or
repeated CSV column, no `url` column, a record over 64 KiB, an open quote
at the end, no rows. The limit on queued and running jobs (10 per
workspace) is checked last, with the workspace row locked, just before the
commit, so a slow upload does not hold the lock.

**Rows.** A CSV record becomes the body `POST /v1/links` would take (the
columns are `url` and any of `code`, `domain`, `redirect_type`,
`expires_at`, `max_clicks`, `enabled`, `health_check`, `fallback_url`,
`conversion_window_days`, with an export's other columns skipped); an
NDJSON line is that body. Each is checked by the same function as the API
(`api::validate_create`) and inserted by the same one
(`Tenant::insert_in`), with its audit entry, first version, change
notification and `link.created` event. A record that fails is counted and
the first 100 are kept in `job_errors` with their number and the error
code and message the API would have answered; the rest of the chunk still
goes in. Every reason to refuse a row (the checks, a taken code, the
plan's link limit, an unverified domain) is found before anything of the
row is written, which is why the link insert is `ON CONFLICT DO NOTHING`:
a step needs no savepoint per row, so it never opens hundreds of
subtransactions, which past 64 would slow every snapshot on the server.

**Steps, exactly once.** `JobWorker` claims the runnable job that ran
least recently (`ORDER BY last_run_at NULLS FIRST`, `FOR UPDATE SKIP
LOCKED`), setting a lease (`RELINK_JOB_LEASE_MS`, 60 s) and a random
token. A step is one transaction in the job's workspace: lock the job row,
check it is still running under this token, do one chunk of an import (or
a page of an export or patch), move the cursor and counters on, extend the
lease, commit. A worker that dies mid-step loses that step only; once its
lease runs out another worker claims the job and does the step again from
the stored cursor, and a worker that comes back after losing its lease
finds a different token and stops before writing. So each record is done
exactly once (`tests/jobs.rs` takes a job over mid-way and counts the
links). A step may run for half the lease. After `RELINK_JOB_SLICE_MS`
(2 s) the worker releases the job and claims again, so jobs take turns
and one big import does not hold up another workspace's export. A step
that fails is tried again after the poll interval; five in a row fail the
job, as does a patch whose change no longer passes its checks (a time
that has since passed).

**Exports and patches.** An export reads its workspace's links in ID order
up to the newest one when the job was made, 1,000 a step, and writes each
step's lines as one output chunk (at most about 1 MiB); `GET
/v1/jobs/{id}/output` streams the chunks back one at a time once it has
succeeded. CSV holds a link's first destination and imports again as it
is; NDJSON lines are the link as the API shows it. A patch applies one
`PATCH /v1/links/{code}` body, checked when the job is made, to up to
1,000 codes or to every link (on one domain), 200 links a step, each
through `Tenant::apply_patch` with its version, audit entry and
`link.updated` event. Codes the workspace does not have are listed as
failed rows when the job is made.

**Progress and retention.** `GET /v1/jobs/{id}` has the state, `total`,
`processed` (succeeded plus failed), `progress` from 0 to 1, the first
100 failed rows and, for a failed job, why. `POST .../cancel` stops a job
before its next step; what it did stays. Making and cancelling a job are in
the audit log (`job.create`, `job.cancel`). An import's chunks are
deleted when it finishes; finished jobs, with an export's file, are
deleted after `RELINK_JOB_RETENTION_DAYS` (7). `RELINK_JOBS_ENABLED=false`
keeps an instance from running jobs; any other instance runs them.

**How fast.** On a 4-core container with Postgres 16 on the same machine,
a 1,000,000-row CSV (46 MB) uploads in 0.7 s and imports in 13 minutes
(775 s), about 1,290 links a second, each with everything a single
`POST /v1/links` writes; the server's resident memory stayed under 19 MB
throughout. Exporting the million as CSV takes 8 s and downloading the
172 MB file 0.5 s, with the server under 24 MB. The import is bound by the per-link writes on one
connection; set-based inserts of a step's links would be the next step
if it needs to be faster.

## QR codes

`relink-core/src/qr.rs` encodes QR codes (ISO/IEC 18004:2015) and writes
them as SVG or PNG. It is in the core so the origin and the Worker can draw
the same symbol from the same bytes, and like the rest of the core it does
no I/O and builds for wasm32.

**What it encodes.** One segment in byte mode, versions 1 to 40, at any of
the four error-correction levels: L (about 7% of codewords recoverable), M
(15%), Q (25%) and H (30%). A link is a URL, and byte mode reads the same in
every scanner, so there are no numeric, alphanumeric or kanji segments, no
ECI and no structured append. The smallest version that holds the data at
the asked level is used, and the level is never raised to fill spare room,
so the same input always gives the same symbol. The data, a terminator, and
the pad bytes `EC 11` fill the version's data codewords, which are split into
its blocks, each given its Reed-Solomon codewords over GF(256) (polynomial
`0x11D`), and interleaved. Codewords are placed in two-module columns from
the bottom right, around the finder, timing and alignment patterns and the
version information (version 7 and up). Each of the eight data masks is
applied in turn with its format information (BCH(15,5)), scored by the
standard's four penalty rules (runs of five or more, 2×2 blocks, 1:1:3:1:1
finder-like patterns with four light modules on a side, the quiet zone
counting as light, and the dark share's distance from half), and the lowest
score wins, ties going to the lower mask.

**Writers.** Both draw a quiet zone, four modules unless asked for 0 to 16,
in the light colour; colours are `#rgb` or `#rrggbb`. The SVG has a
background `<rect>` and one `<path>` with a rectangle per horizontal run of
dark modules, and `shape-rendering="crispEdges"`; its width and height are
the scale (1 to 32 pixels per module, 8 by default) times the modules.
The PNG is a 1-bit palette image, light at index 0 and dark at index 1,
with filter type 0 on every row. Its pixels go into deflate's stored
(uncompressed) blocks of up to 65,535 bytes, in a zlib stream with its
Adler-32: no deflate implementation and no dependency, and every decoder
reads stored blocks. At one bit per pixel a short link's code at the
defaults is 9 KB; the largest image (version 40, border 16, scale 32) is
6,688 pixels a side and 5.6 MB, which is why the scale stops at 32.

**Tests.** `crates/relink-core/tests/qr.rs` compares every symbol, module
for module and with the same chosen mask, against Nayuki's `qrcodegen`, an
independent encoder used only as a dev-dependency: both ends of every
version at every level, every mask forced at seven versions, and 200 random
inputs. Unit tests check the capacities and codeword counts against the
standard's tables, the format and version codes against its annexes, and
the Reed-Solomon codewords against its worked example in annex I. The PNG
is read back by a separate reader (its own bit-by-bit CRC-32 and Adler-32)
and the SVG's path is parsed back into modules, both compared pixel for
pixel with the symbol.

**Speed.** A short link (version 2-M) encodes in about 50 µs, almost all of
it scoring the eight masks; its SVG takes about 15 µs and its PNG about
30 µs. A version 40 symbol takes about 3 ms (`cargo bench --bench hot_path -- qr_`).

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
`.home.arpa`, `.test`, `.invalid`, `.example`, `.onion`, `.alt`. At probe time the
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
Session cookies get the same treatment, plus a CSRF token on every
state-changing request ("Console sign-in" above).

Requests must be `application/json` with at most 64 KiB (256 KiB for edge
click batches), unknown fields and duplicate keys are refused, and every value
is range-checked. Internal errors carry a request ID and nothing else.
`/metrics` is on its own listener bound to loopback by default.

## Shutdown

On SIGTERM the server stops accepting connections and gives every phase one
shared budget (`RELINK_SHUTDOWN_TIMEOUT_S`, 10 s): ending live click streams,
draining requests, stopping lease reservations, flushing the click queue,
stopping background tasks, returning unspent leases and closing the pool. A phase that runs long takes
time from the next rather than stretching the total past an orchestrator's
grace period; a test with Postgres gone at shutdown finishes inside the budget
and counts the clicks it could not write.

## Failure modes

| Failure | Behaviour |
|---|---|
| Postgres down during a scheduled change | Due schedules stay pending and are applied on the first scheduler tick after the database returns. |
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
| KV missing a `host:` record | Until the outbox or reconciliation writes it, the edge serves that host's codes from the default domain where the domain's own link is not in KV either; links that are in KV are still served correctly. |
| Custom hostname API failing | The domain's `host:` entry waits in the outbox; links already in KV keep being served. |
| Worker isolate evicted | Up to 50 unsent edge clicks are lost. |
| Verified domains not loaded | Possible only when Postgres went away between migrations and start; requests whose host could be a custom domain get 503 until the change listener connects and loads them. |
| DNS resolver down | Verification answers 200 with the resolver error in `check_error`; verified domains are unaffected. |
| ACME CA down or refusing | The domain keeps its current certificate; the error is stored on the domain and retried after 5 minutes, doubling to a day, or after the CA's `Retry-After`. A first certificate stays `pending` or `failed` meanwhile. |
| Stored certificate unreadable (another key encryption key, corrupt row) | Logged and counted in `relink_tls_certificate_errors_total`; the domain keeps the certificate in memory, or gets the default one after a restart. |
| Default certificate files replaced with a bad pair | The old certificate keeps being served; the reload logs why. |
| Slow or stalled TLS clients | Each handshake is cut off after 10 s; at most 1,024 run at once, the rest wait in the accept queue. |
| Instance dies mid-order | Its claim lapses after 15 minutes and another instance orders again; its challenges expire after an hour. |
| Health target hangs | 5 s timeout, counted as a failure. |

## Limits

| Limit | Value |
|---|---|
| Destination URL | 2048 characters, before and after normalisation |
| Destinations per link | 10, weights 1 to 1000 |
| Countries per geo rule | 300 |
| Targeting rules | 32 rules and 64 leaf conditions per link, nested 8 deep, 300 values per leaf; queries read up to 64 parameters within 2,048 bytes |
| App targets | deep link 1,024 printable ASCII characters; package name 255; stored object 8 KiB |
| Version history | the newest 100 versions per link |
| Conversions | attribution window 1 to 365 days; event 64 characters; `external_id` 128; value 0 to 10¹⁵ minor units; 5 minutes of clock skew either way |
| Jobs | 10 queued or running per workspace; uploads up to 256 MiB (`RELINK_JOB_MAX_UPLOAD_MB`, 1 to 4,096), records up to 64 KiB, chunks of 500 records or 1 MiB; 100 failed rows kept per job; patches of 1 to 1,000 codes or every link; 5 failed steps in a row fail a job; kept 7 days after they finish (`RELINK_JOB_RETENTION_DAYS`) |
| Schedules | 20 pending per link; `run_at` within 10 years; due schedules looked for every second (`RELINK_SCHEDULE_POLL_MS`), 100 per query |
| QR codes | byte mode, versions 1 to 40: 2,953 bytes at L, 2,331 at M, 1,663 at Q, 1,273 at H; quiet zone 0 to 16 modules (4 by default); 1 to 32 pixels per module (8 by default) |
| Domain apps | 8 iOS and 8 Android apps per domain, 8 fingerprints per Android app; bundle ID 155 characters |
| Alias | 3 to 64 of `[A-Za-z0-9_-]`, alphanumeric at both ends |
| Generated code | 7 base62 characters by default (4 to 32); collisions retried 5 times |
| `max_clicks` | 1 to 10¹² |
| `expires_at` | in the future, within 10 years |
| Request body | 64 KiB; 256 KiB and 1,000 clicks for edge batches |
| Page size | 1 to 100, default 50 |
| Stats range | 366 days, top 50 per dimension |
| Cache | 100,000 entries |
| Unique-count sketch | precision 14; sparse up to 3,072 entries (4 bytes each in memory), then dense: 16 KiB in memory, 12,291 bytes stored |
| Click queue / backlog | 65,536 clicks / 200,000 aggregated rows |
| Raw click events | 13 calendar months, the current one included (`RELINK_CLICK_EVENTS_RETENTION_MONTHS`, 1 to 120); partitions created two months ahead |
| Flush transaction | 5,000 hourly count rows (and the daily rows they add up to), 5,000 visitor rows and 5,000 raw events |
| Raw event backlog | 200,000 events while the database is down (`RELINK_CLICK_EVENT_BACKLOG`, 0 to 5×10⁷); past it only raw events are dropped |
| Analytics queries | 1,000,000 rollup rows and sketches read (`RELINK_ANALYTICS_MAX_ROWS`, 1,000 to 10⁸); 366 days and 1,000 points; 3 group-by dimensions; 50 values per filter; top 1 to 100 groups |
| Live streams | 50 per workspace and 10,000 per instance; 256 clicks buffered per workspace; a 4,096-click relay queue; announcements every 10 s, kept 30 s; one hour per stream |
| Hourly rollups | 92 days (`RELINK_CLICK_HOURLY_RETENTION_DAYS`, 1 to 3,660); 50,000 rows per table deleted per minute; replay keys kept 7 days |
| User-Agent scanned | 512 bytes (256 in the fingerprint) |
| Lookup concurrency | 32 |
| Uncached key lookups | 5/s per address, 200/s overall |
| API rate | 10/s, burst 20, per key and instance |
| KV outbox retry | 1 s doubling to 10 min |
| Custom hostnames listed per reconciliation | 1,000 pages of 50 |
| Edge click batch | 50 clicks or 5 s |
| Plan limits | 0 to 10¹⁵ links, domains and monthly clicks, or unlimited (the default plan) |
| Custom domains | 1,000 per workspace whatever the plan; hostnames up to 253 characters |
| DNS answer | 2 s per resolver (`RELINK_DNS_TIMEOUT_MS`); 4 KiB over UDP, 64 KiB over TCP |
| ACME | 4 domains claimed per round; an order within 300 s (`RELINK_ACME_ORDER_TIMEOUT_S`); responses up to 1 MiB; 16 spare nonces; 3 attempts on a bad nonce; retries 5 min doubling to a day; challenge database lookups 20/s per instance |
| TLS | 1,024 handshakes at once, 10 s each (`RELINK_TLS_HANDSHAKE_TIMEOUT_MS`); sealed keys up to 16 KiB |

## Observability

JSON logs on stderr with request IDs; one line per API request, redirects at
debug level so the hot path does not pay for a log line. Prometheus metrics on
the admin listener cover redirect latency, redirects by outcome, cache results
(`hit`, `negative_hit`, `stale`, `stale_on_error`, `miss`), coalesced and shed
lookups, click queue depth, backlog, drops by reason, late visitor hashes,
raw events dropped, click batches replayed, analytics queries answered and
refused and the rows they read,
database errors by operation, lease grants, health probes, KV writes, deletes,
custom hostnames added and removed,
errors and reconciled drift, edge clicks, API requests and refusals, link creations refused per plan
limit, certificates issued and failed orders, HTTP-01 answers served, TLS
handshakes completed and failed, certificates loaded and those that could
not be, and pool usage.

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
| `reqwest` | HTTP client for health probes, the KV API, the OpenID Connect provider and the ACME CA. It accepts a custom DNS resolver, which the SSRF defence depends on. |
| `serde`, `serde_json` | JSON for the API, the KV record and the edge wire format. |
| `url` | WHATWG URL parsing and IDNA; not something to hand-roll when the result decides where a server sends requests. |
| `rustls`, `tokio-rustls` | TLS termination: the handshake, record layer and certificate selection by SNI, on the aws-lc-rs provider. TLS is not code to hand-roll, and both are already in the tree through reqwest at these versions, so they add no new code to the build. |
| `ring` | RS256 and ES256 signature verification for OpenID Connect ID tokens, and P-256 key generation and ES256 signing for ACME requests and certificate requests, and AES-256-GCM for keys at rest. RSA and ECDSA are not code to hand-roll, and `ring` is already in the tree through rustls, so it adds no new code to the build. |
| `hmac`, `sha2`, `subtle` | HMAC-SHA256 for A/B cookies and visitor hashes, SHA-256 for keys and the audit chain, constant-time comparison. |
| `getrandom` | The OS CSPRNG for codes, keys and salts. |
| `argon2` | argon2id for protected links' passwords. A password people choose needs a memory-hard hash, and argon2 is not code to hand-roll; it shares `digest` and `getrandom` with crates already in the tree, so it adds only itself, `blake2`, `password-hash` and `base64ct`. Built at `opt-level = 3` in the dev profile too, so tests hash in milliseconds. |
| `futures-util` | Reads a query's rows as a stream, so sketches are merged as they arrive instead of all held at once; already in the tree through axum and sqlx. |
| `chrono` | Timestamps and UTC dates; the core uses it without its clock so it stays wasm-friendly. |
| `tracing`, `tracing-subscriber` | Structured JSON logs with request-scoped spans. |
| `worker` | The workers-rs binding to the Cloudflare Workers runtime; wasm32 only. |
| `proptest`, `criterion`, `tower` (dev) | Property tests, benchmarks, and driving the router in-process in benchmarks. |
| `qrcodegen` (dev) | A second, independent QR encoder that every symbol is compared with in `relink-core`'s tests. It has no dependencies and is not in any build. |

Metrics, the cache, single flight, token buckets, CIDR parsing, hex,
base64 and base64url are each a few dozen lines and written here instead of
pulled in. So are the QR encoder and its PNG writer (`relink-core/src/qr.rs`,
about 1,050 lines with comments, before its tests), which need Reed-Solomon
over GF(256), CRC-32, Adler-32 and stored deflate blocks, and no image or
compression crate. So is the DER the ACME client needs (`src/der.rs`, under 500
lines with comments): writing one fixed shape of certificate request and reading the
validity, names and key of a certificate. A general ASN.1 crate would be
larger than that.

## At a larger scale

A membership filter (Bloom or cuckoo) of all codes, maintained from the change
feed, would answer most made-up codes without a query; it needs an answer for
codes created on another instance before the filter hears about them. The
miss path is a single-row read by unique key and could go to read replicas,
with notifications still from the primary.
Partitioning `click_daily` by month would make retention a `DROP PARTITION`.
Per-key rate limits are per instance; a global limit needs a shared counter.
And at the edge, a link with a click limit could be served from a Durable
Object holding its counter, at the cost of a hop to wherever that object
lives.
