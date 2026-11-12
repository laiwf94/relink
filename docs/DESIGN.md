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
| `kv_outbox` | Codes whose KV copy must be rewritten or deleted. |
| `users` | People who signed in: issuer and subject at the provider, their member name, email address and display name. |
| `oidc_logins` | Sign-ins between the redirect to the provider and its return: SHA-256 of `state`, nonce, PKCE verifier, return path, expiry. |
| `sessions` | SHA-256 of each session cookie, its person, CSRF token and expiry. |
| `audit_log` | Every change made by a person or an operator: workspace, sequence number, time, actor, how they acted, action, target, the state before and after, and the hash chain. |
| `audit_heads` | The last sequence number and hash of each workspace's audit chain. |

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
| `kv_outbox (next_attempt_at)` | The sync worker's "what is due". |
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
inside the domain's `host:` record at the edge.

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
click limit. The country comes from Cloudflare's `cf` object, which clients
cannot set; the visitor's address from `CF-Connecting-IP`. Both are passed to
the origin, which believes them because the edge is in its
`RELINK_TRUSTED_PROXIES`.

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
| `host:<host>` | `{"id": <domain id>, "settings": {...}}` (settings left out while they are the defaults) | `<host>` is a verified domain |

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
Session cookies get the same treatment, plus a CSRF token on every
state-changing request ("Console sign-in" above).

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
| `chrono` | Timestamps and UTC dates; the core uses it without its clock so it stays wasm-friendly. |
| `tracing`, `tracing-subscriber` | Structured JSON logs with request-scoped spans. |
| `worker` | The workers-rs binding to the Cloudflare Workers runtime; wasm32 only. |
| `proptest`, `criterion`, `tower` (dev) | Property tests, benchmarks, and driving the router in-process in benchmarks. |

Metrics, the cache, single flight, token buckets, CIDR parsing, hex,
base64 and base64url are each a few dozen lines and written here instead of
pulled in. So is the DER the ACME client needs (`src/der.rs`, under 500
lines with comments): writing one fixed shape of certificate request and reading the
validity, names and key of a certificate. A general ASN.1 crate would be
larger than that.

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
