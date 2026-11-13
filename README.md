# relink

A URL shortener for teams. You create short links through an API; visitors
who open `/{code}` get redirected. The redirect is answered from memory on
the origin and can also run as a Cloudflare Worker reading from Workers KV,
and it keeps working while Postgres is down.

Links, API keys and statistics belong to workspaces, kept apart by Postgres
row-level security. People sign in with any OpenID Connect provider and act
as owner, admin, editor or viewer; they join a workspace by a one-time
invitation link. API keys carry scopes and an expiry and rotate with an
overlap. Each workspace is on a plan that limits its links and monthly
clicks, and every change is written to a hash-chained audit log that
`relink audit-verify` checks.

Links can live on a workspace's own branded domains. A domain is proved
with a DNS TXT record, keeps its own codes, gets its certificate from
relink's own ACME client (renewed and swapped in without a restart, served
by rustls with SNI), and has its own root redirect, 404 and 410 pages,
path prefixes and optionally case-free codes, decided the same way at the
origin and at the edge.

```console
$ curl -s localhost:8080/v1/links -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
    -d '{"alias":"pricing","destinations":[{"url":"https://example.com/a","weight":3},
                                          {"url":"https://example.com/b","weight":1}]}'
{"code":"pricing","short_url":"http://localhost:8080/pricing","destinations":[...],...}

$ curl -si localhost:8080/pricing | grep -iE '^(HTTP|location|set-cookie)'
HTTP/1.1 302 Found
location: https://example.com/a
set-cookie: rl_pricing=0.8f1c...; Path=/pricing; Max-Age=2592000; HttpOnly; SameSite=Lax; Secure
```

## How a redirect is served

A link is a short code plus one or more destinations. Codes are random base62
from the OS CSPRNG, or custom aliases checked for charset, length and reserved
words. Destinations must be http or https, carry no credentials and point at
public hosts; they are normalised before storage. On top of that a link can
have an expiry, a click limit, an A/B split across weighted destinations
(sticky per visitor through an HMAC-signed cookie), a country allow or deny
list with a fallback URL, and health checks that take failing destinations out
of rotation.

The origin answers `/{code}` from a bounded in-process cache with
stale-while-revalidate, stale-if-error, negative caching and one coalesced
database lookup per code. A short circuit breaker stops requests from queueing
behind a dead database. Click limits are enforced with per-instance leases
taken from Postgres, so a limit is never exceeded and no click costs a
database write.

The edge is a Cloudflare Worker that reads the link from Workers KV and applies
the same `relink-core` rules, so a visitor's A/B variant survives moving
between edge and origin. Links with a click limit, links KV does not have yet,
and KV errors go to the origin. Links on custom domains are served at the edge
too, keyed by host and code, with the same routing by `Host` as the origin.
Edge clicks are batched per isolate and posted to the origin in the
background.

On the origin, clicks go through a bounded queue into daily aggregates. Client
addresses are never stored, and unique visitors are counted with a keyed hash
whose salt is destroyed after two days.

## Running it

```console
$ docker run -d --name pg -e POSTGRES_PASSWORD=pg -p 5432:5432 postgres:16-alpine
$ export RELINK_DATABASE_URL=postgres://postgres:pg@localhost:5432/postgres
$ cargo run --release -p relink-server -- create-key alice   # prints id=1 owner=alice ... key=rlk_...
$ cargo run --release -p relink-server                       # :8080, metrics on 127.0.0.1:9090
$ ./examples/demo.sh          # the tour: links, workspaces, keys, a plan, the audit chain, a custom domain, then Postgres stopped mid-way
$ ./examples/edge-local.sh    # the Worker under wrangler dev, in front of a local origin
```

The Docker image is a multi-stage build onto distroless, running as non-root:

```console
$ docker build -t relink .
$ docker run -p 8080:8080 -e RELINK_DATABASE_URL=... relink
```

Configuration is by environment variable, listed with defaults at the top of
[crates/relink-server/src/main.rs](crates/relink-server/src/main.rs). Two
deserve a mention here. `RELINK_TRUSTED_PROXIES` lists the addresses of your
CDN or load balancer; the country and client-address headers are read only
from those peers, so a visitor cannot pick their own country (and so is
`x-forwarded-host`, which the edge uses to name a custom domain). `RELINK_KV_*`
turns on publishing to Workers KV; without it the origin works alone. With
`RELINK_KV_ZONE_ID` as well, each verified domain is registered as a custom
hostname of that Cloudflare zone, so its traffic reaches the Worker.
`RELINK_ACME_DIRECTORY` turns on certificates for custom domains, and
`RELINK_TLS_ADDR` serves them.

## Endpoints

The management API uses hashed API keys checked in constant time, per-key rate
limits, workspace scoping, cursor pagination, strict JSON with body limits, stable
error codes and request IDs. `/v1/links` endpoints take
`Authorization: Bearer <key>` and JSON bodies; the full schema is at
`/openapi.json`, an OpenAPI 3.1 document that a test checks against the router.

Keys carry scopes (`links:read`, `links:write`, `stats:read`) and act within
their owner's role in the workspace: viewers read links and statistics,
editors, admins and owners also write. Keys can expire, and rotation keeps the
old key working for an overlap window so deployments switch without downtime:

People sign in with any OpenID Connect provider instead of holding keys:
set `RELINK_OIDC_ISSUER` and `RELINK_OIDC_CLIENT_ID` (and
`RELINK_OIDC_CLIENT_SECRET` for a confidential client), register
`<RELINK_PUBLIC_BASE_URL>/v1/auth/callback` with the provider, and open
`/v1/auth/login`. The session cookie then works on every `/v1/links` endpoint
with the rights of the person's role in the workspace named by
`Relink-Workspace` (their own by default); requests that change anything also
send the session's CSRF token in `X-CSRF-Token`.

```console
$ relink create-key alice dashboard --scopes stats:read --expires-in 90d
$ relink create-key carol ci --workspace 3 --scopes links:read,links:write
$ relink rotate-key 7 --overlap 1h   # prints the new key and when key 7 stops working
```

A signed-in admin or owner brings people into a workspace with a one-time
invitation link, by email address or member name and with a role (admins
invite editors and viewers, owners anyone). Only the person invited can use
it: someone signed in with that verified address, or with that member name.
It works once, until it expires (7 days by default, at most 30), and can be
revoked before then:

```console
$ curl -s localhost:8080/v1/invitations -H "Cookie: relink_session=$S" \
    -H "X-CSRF-Token: $CSRF" -H "Relink-Workspace: 3" -H "Content-Type: application/json" \
    -d '{"email": "carol@example.com", "role": "editor"}'
{"id":5,"workspace_id":3,"email":"carol@example.com","role":"editor","status":"pending",
 ...,"url":"http://localhost:8080/v1/invites/rli_6f1c...e2"}
```

Every change (links, keys, workspaces, invitations, sign-ins and sign-outs) is appended to
the workspace's audit log in the same transaction, with who made it, how,
and the state before and after. Each workspace's log is a hash chain that
the database keeps append-only; `relink audit-verify` recomputes every hash,
stops at the first altered, missing or reordered entry, and prints each
chain's head so it can be kept elsewhere and checked later with `--anchors`:

```console
$ relink audit-verify
3:418:5c0e...a91f
verified 1 audit chain(s)
$ relink audit-verify --anchors 3:418:5c0e...a91f
```

Each workspace is on a plan that can limit how many links it holds and how
many clicks it receives per calendar month (UTC). The default plan,
`unlimited`, has no limits; operators define others and move workspaces
between them. Clicks are metered as the click pipeline writes them. A
workspace at a limit gets `quota_exceeded` when it creates a link; its
existing links keep redirecting and counting:

```console
$ relink plan-set free --links 1000 --monthly-clicks 50000 --domains 1
plan=free links=1000 monthly_clicks=50000 domains=1
$ relink plan-assign 3 free
workspace=3 plan=free links=1000 monthly_clicks=50000 domains=1 previous=unlimited
$ curl -s localhost:8080/v1/usage -H "Authorization: Bearer $KEY"
{"workspace_id":3,"plan":"free","period_start":"2026-11-01","period_end":"2026-12-01",
 "links":{"used":12,"limit":1000},"clicks":{"used":4210,"limit":50000},
 "domains":{"used":1,"limit":1}}
```

A workspace can serve links on its own domain. An admin or owner adds the
hostname, publishes the TXT record relink gives back, and asks relink to
check it; the first workspace to prove a hostname gets it. Links created
with `"domain"` live on it, where codes need only be unique on that domain,
and visitors are routed by the `Host` header (point the domain's DNS at
relink or at the proxy in front of it). Any other host serves the default
domain from `RELINK_PUBLIC_BASE_URL`:

```console
$ curl -s localhost:8080/v1/domains -H "Authorization: Bearer $KEY" \
    -H 'Content-Type: application/json' -d '{"hostname": "go.example.com"}'
{"hostname":"go.example.com","verified":false,"verification":{"type":"TXT",
 "name":"_relink-challenge.go.example.com","value":"relink-domain-verification=4be1..."},...}
$ curl -s -X POST localhost:8080/v1/domains/go.example.com/verify -H "Authorization: Bearer $KEY"
{"hostname":"go.example.com","verified":true,"verified_at":"2026-11-07T09:12:44Z",...}
$ curl -s localhost:8080/v1/links -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
    -d '{"url": "https://example.com/spring", "alias": "spring", "domain": "go.example.com"}'
{"code":"spring","domain":"go.example.com","short_url":"http://go.example.com/spring",...}
$ curl -si localhost:8080/spring -H 'Host: go.example.com' | grep -i ^location
location: https://example.com/spring
```

With edge publishing on, the domain is published to KV as `host:go.example.com`
and its links as `link:go.example.com/<code>`; set the Worker's `DEFAULT_HOST`
to the host of `RELINK_PUBLIC_BASE_URL`.

With `RELINK_ACME_DIRECTORY` set (for example
`https://acme-v02.api.letsencrypt.org/directory`, which accepts that CA's
terms of service), relink orders a certificate for each domain as soon as
it is verified, from its own ACME client. The CA checks the domain over
HTTP-01, so port 80 of the domain must reach relink, and any instance can
answer it. Certificates are renewed after two thirds of their lifetime;
failed attempts are retried with back-off. Certificate keys are stored
encrypted under `RELINK_KEY_ENCRYPTION_KEY`, which ACME requires. With
`RELINK_TLS_ADDR` set, relink terminates TLS itself and serves each domain
its certificate by SNI, picking up renewals from any instance without a
restart; `RELINK_TLS_CERT_FILE` and `RELINK_TLS_KEY_FILE` give the default
certificate for the server's own host. The domain shows where its
certificate stands:

```console
$ curl -s localhost:8080/v1/domains/go.example.com -H "Authorization: Bearer $KEY"
{"hostname":"go.example.com","verified":true,...,"certificate":{"status":"issued",
 "not_after":"2027-02-05T09:12:47Z","renew_at":"2027-01-06T09:12:47Z","error":null,...}}
```

| Endpoint | Purpose |
|---|---|
| `GET /{code}` | Redirect, on the domain named by `Host`. 404 unknown or disabled, 410 expired or over its limit, 451 geo-blocked without a fallback, 503 when not cached and the database is down. |
| `POST /v1/links` | Create: `url` or `destinations`, optional `alias`, `redirect_type`, `expires_at`, `max_clicks`, `geo`, `fallback_url`, `enabled`, `health_check`, `domain`, `rules` (targeting rules; see [docs/DESIGN.md](docs/DESIGN.md#targeting-rules)). |
| `GET /v1/links?limit=&cursor=` | Your links, newest first. |
| `GET /v1/links/{code}?domain=` | One link, with per-destination health; `domain` for a link on a custom domain. |
| `PATCH /v1/links/{code}?domain=` | Change fields; `null` clears optional ones. `rules` replaces the whole list. |
| `DELETE /v1/links/{code}?domain=` | Delete the link and its statistics. |
| `GET /v1/links/{code}/stats?from=&to=&domain=` | Clicks per UTC day with unique visitors, top countries, devices and referrers. |
| `GET /v1/usage` | The workspace's plan, link and domain counts and clicks this month, with their limits. |
| `POST /v1/domains` | Add a custom domain by `hostname`; answers with the TXT record that proves it. Admins and owners. |
| `GET /v1/domains`, `GET /v1/domains/{hostname}` | The workspace's domains, their verification state and, once verified, their certificate's. |
| `POST /v1/domains/{hostname}/verify` | Look the TXT record up now; verified, or `check_error` says what was found. |
| `DELETE /v1/domains/{hostname}` | Delete a domain that has no links left. |
| `GET /.well-known/acme-challenge/{token}` | The ACME HTTP-01 answer, on the host being validated, while its certificate is being ordered. |
| `GET /v1/auth/login?return_to=` | Sign in with the OpenID Connect provider (authorization code with PKCE). Absent unless `RELINK_OIDC_ISSUER` is set. |
| `GET /v1/auth/callback` | The provider's redirect back; starts a session cookie. |
| `GET /v1/auth/session` | Who is signed in, the session's CSRF token, and their workspaces and roles. |
| `POST /v1/auth/logout` | Sign out (with `X-CSRF-Token`). |
| `POST /v1/invitations` | Invite by `email` or `member` with a `role` and optional `expires_in`; answers with the one-time `url`, shown only then. Signed-in admins and owners only. |
| `GET /v1/invitations` | The workspace's invitations, pending first. |
| `DELETE /v1/invitations/{id}` | Revoke a pending invitation. |
| `GET /v1/invites/{token}` | The invitation link: what accepting would give, for a signed-in person. |
| `POST /v1/invites/{token}/accept` | Join the workspace, if you are the person invited. |
| `POST /v1/edge/clicks` | Click batches from the Worker, authenticated with `RELINK_EDGE_TOKEN`. Absent unless that is set. |
| `GET /healthz`, `/readyz`, `/openapi.json` | Liveness, readiness (stays ready with the database down, and says so), the API document. |
| `GET /metrics` (admin listener) | Prometheus metrics. |

Errors are `{"error":{"code":"invalid_argument","message":"...","request_id":"..."}}`.
The codes are `invalid_argument` 400, `unauthenticated` 401, `permission_denied`
403, `quota_exceeded` 403, `not_found` 404,
`method_not_allowed` 405, `already_exists` 409, `failed_precondition` 409,
`payload_too_large` 413,
`unsupported_media_type` 415, `resource_exhausted` 429, `internal` 500 and
`unavailable` 503. Another owner's link answers `not_found`.

## Testing

| What | How |
|---|---|
| Click limits | A property test runs several limiter instances against a model store under random interleavings, store failures and invalidations, and checks that clicks served never exceed the limit and every reserved click is accounted for. Breaking the counter, the grant rule or the hand-back on invalidation makes it fail. Three origin instances serving 960 concurrent requests for a 500-click link must serve exactly 500. |
| URL validation | Generated URLs (schemes, credentials, domains, reserved suffixes, IPv4 and IPv6 from every blocked range) are checked against a model built on plain CIDR arithmetic. |
| A/B | Shares over 20,000 draws match random weights within five standard deviations; unhealthy variants are never picked; cookies verify only for the same link, version and key. A cookie set by the origin keeps its variant at the edge and the other way round. |
| Database outage | A TCP proxy in front of Postgres cuts every connection: cached redirects keep working, uncached codes and writes get 503 within the query timeout, clicks are written after recovery, shutdown still finishes within its one deadline. |
| Analytics | Against real Postgres: 100,000 count rows plus 100,000 visitor rows drain in 5,000-row transactions; a referrer spelled like the "no referrer" marker does not collide with it; clicks for a day whose salt is gone keep their counts and drop their visitor hashes. |
| API | Every endpoint and error code over real HTTP: 26 invalid bodies, auth and revocation, per-address throttling of key guessing, owner isolation, pagination, rate and body limits, and the OpenAPI document compared with the router and real responses. |
| Roles and keys | Each route's documented scope is enforced (403 without it, success with only it, before the body is read); viewers cannot write even with an old all-scopes key; removed members' keys stop working; expiry is exact for cached keys; rotation keeps both keys for the overlap and no longer, cannot fork, and narrows scopes to the current role. |
| Quotas | Against real Postgres: 20 concurrent creations racing for a workspace's last 3 link slots create exactly 3 (and 4 or 5 without the row lock); clicks are metered into the month of their own day and equal the statistics month by month; at the click allowance creation is refused while redirects continue; tenants cannot change their plan or read another workspace's usage; plan moves are audited. |
| Invitations | Against real Postgres over HTTP: only the person invited joins (a verified address, or the member name); an unverified address, another person or an API key is refused; 20 concurrent acceptances of one link make one member; revoked, expired and used links are refused; admins cannot invite or revoke above their own role; 5 requests racing for the last 2 of 100 pending slots create exactly 2; tenants see only their own invitations and cannot delete any; each step is in the audit chain, which still verifies, and tokens are in neither the log nor the chain. |
| Workspaces end to end | One test walks week 1 as a team would: three people sign in through a fake OpenID Connect provider; the owner invites one by email as an editor and one by member name as a viewer, and each accepts only their own link, once; the editor creates links in the team workspace, the viewer only reads, and a stranger is refused; scoped, rotated and expiring keys are made with the binary; a plan's link and click limits refuse new links while redirects continue; the tenant role sees no rows in any tenant table without a workspace; every change is attributed in the team's audit chain, which the binary verifies with and without an anchor; signing out ends the session. |
| Custom domains end to end | One test walks week 2 as a customer would, on two instances: a workspace on a one-domain plan adds a domain and a second is refused; the domain verifies only once its TXT record is published (a local resolver), and nothing reaches the edge before; `promo` on the domain and `promo` on the default domain are two links and a third is refused; the ACME client gets a certificate from a local CA, both instances serve it by SNI to a client that checks it, and a renewal is served by both without a restart; the domain's root redirect, path prefix, case-free codes and its 404 and 410 pages are served over TLS, and the edge's own request logic, reading the KV records the sync published to a fake of the KV API and forwarding to the origin as the Worker does, gives the same responses, answering the root, codes, prefixes and pages without the origin; the domain is registered as a custom hostname; deleting it, refused while it has links, takes it off TLS, KV and the zone and gives its hostname back to the default domain; the steps are in the audit chain, which the binary verifies. |
| Custom domains | Against real Postgres over HTTP with a local DNS resolver: a domain verifies only with its own token published, and only the first workspace to prove a hostname gets it; the same code on the default and a custom domain are two links, routed by `Host` on two instances, including after an update; unknown hosts keep the default domain; a domain with links cannot be deleted, and once deleted both instances stop routing it; 12 concurrent adds against a 3-domain plan with one domain taken create exactly 2; editors and viewers cannot manage domains; the database refuses a link on another workspace's domain. The DNS client is tested against crafted answers (compression, CNAME chains, truncation, NXDOMAIN, forged IDs, random bytes) and a resolver that answers over UDP and TCP. |
| Certificates | The ACME client against a local CA that checks what a real one does (JWS signatures over its own nonces and the requested URL, HTTP-01 fetched with the domain as `Host`, a certificate request signed by its key and naming exactly the order's identifiers) and signs real X.509 certificates: issuance, a stale nonce retried but not forever, why validation failed, a rate limit's `Retry-After`, a certificate for another key refused, an order that never finishes, URLs that leave https, a lost account. In two running servers on Postgres: a domain gets a certificate once verified, with the CA's request answered by the other instance, and is renewed at two thirds of its lifetime with a fresh key; the instances never order the same domain at once and keep one account; failures back off (5 then 10 minutes) and show in the domain until an attempt succeeds; the challenge answer is per host, reaches every instance by notification or a database lookup, and is withdrawn after use. Tenants cannot read certificate keys. TLS: both instances serve the domain's certificate by SNI (any case, a final dot) to a client that checks it against the CA, redirect on it and count the click; a renewal on either instance is served by both on the next connection; a name without a certificate gets no handshake; keys are sealed for their row and Postgres refuses one that is not; an instance with another encryption key counts the certificate it cannot open and serves its default certificate from files to clients without SNI, picks up new files and keeps the old ones when the new key does not match; a stalled handshake is cut off; a default certificate that cannot be read stops the start. The sealing rejects every flipped byte, another row and another key. The DER reader and base64 are property-tested on random bytes, and the request was checked with `openssl req -verify`. |
| Edge | Handler logic against an in-memory KV and a fake origin, including custom domains: a domain's own code in one read whatever the case, port or final dot; unknown hosts fall back to the default domain; a verified domain never serves a default-domain code; limited, broken and unreadable records go to the origin with the host forwarded. A property test sends random hosts and paths to the origin and to the edge in front of it, over random domains, settings and links, and requires the same response from both; it found a listed `Host` routed differently, now fixed. A local end-to-end run through `wrangler dev` (`examples/edge-local.sh`). KV publishing runs against a local fake of the Cloudflare KV and custom hostname APIs, including retries while either fails, domain records and links on a domain published once it is verified and removed with it, an operator's own hostnames left alone, and reconciliation of drift in links, domain records and hostnames. The origin routes by `x-forwarded-host` from trusted proxies only. |
| Health checks | Local HTTP servers flip between healthy and failing; private, loopback and metadata addresses are refused; redirects are not followed; probes to one host are paced. |
| The binary | Admin commands, config errors, and a real process stopped with SIGTERM whose log never contains the API key or database URL. |
| Parsers | cargo-fuzz targets for URLs, aliases, request headers and proxy lists, `Host` headers and hostnames, request bodies, edge click batches, KV records, cursors and change notifications. |

```console
$ docker run -d -e POSTGRES_PASSWORD=postgres -p 5439:5432 postgres:16-alpine
$ export RELINK_TEST_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5439/postgres
$ cargo test                         # 356 tests; database tests skip if the variable is unset
$ cargo llvm-cov --summary-only      # CI requires 90% of lines
$ cargo build -p relink-core --target wasm32-unknown-unknown
$ cargo +nightly fuzz run destination -- -max_total_time=60
$ cargo bench -p relink-server
```

## Load test results

Apple M4 Max. In-process with criterion:

| Case | Time |
|---|---|
| Origin redirect handler, cache hit, including click recording | 0.46 µs |
| The same for a new A/B visitor (weighted choice, signed cookie) | 0.92 µs |
| Full router: axum routing, request-ID middleware, handler | 1.43 µs |
| Unknown code, negative cache hit | 0.14 µs |

Over HTTP with [oha](https://github.com/hatoo/oha), 64 connections, client and
server on the same machine (`examples/loadtest.sh`):

| Case | Throughput | p50 | p99 |
|---|---|---|---|
| Origin, cached hit | 161,000 req/s | 0.39 ms | 0.90 ms |
| Origin, unknown code | 159,000 req/s | 0.40 ms | 0.64 ms |
| Origin, every request a Postgres lookup (Postgres in Docker Desktop) | 11,400 req/s | 5.4 ms | 9.7 ms |
| Edge under `wrangler dev`, KV hit, 32 connections | 1,540 req/s | 19 ms | 47 ms |

The edge row measures the local simulator (workerd behind wrangler's dev
proxy, simulated KV), not Cloudflare's network; it shows the Worker runs, not
how fast it is in production. The Worker bundle is 408 KB of wasm, 143 KB
gzipped.

Click limits under concurrency: three origin instances, 180,000 requests for
a 100,000-click link, served exactly 100,000. With one instance killed by
SIGKILL mid-run, 99,996 were served: the dead instance's unspent lease is
lost, at most `RELINK_LEASE_MAX` (100) clicks. Numbers move by about 20%
between runs on a busy machine.

## Crates

The workspace has three crates, plus fuzz targets and example scripts:

| Path | What it is |
|---|---|
| `crates/relink-core/` | The redirect rules with no I/O: code and URL validation, expiry, geo rules, A/B assignment and its signed cookie, the KV record format. Builds for `wasm32-unknown-unknown`. |
| `crates/relink-server/` | The origin: management API, Postgres, the in-memory redirect path, click analytics, health checks, and publishing link records to KV. Holds `src/`, `migrations/`, `tests/` and `benches/`. |
| `crates/relink-edge/` | A Cloudflare Worker (workers-rs) that answers redirects from KV with the same rules and sends everything else to the origin. `src/logic.rs` is tested natively, `src/worker.rs` is the wasm glue, next to `wrangler.toml`. |
| `fuzz/` | cargo-fuzz targets. |
| `examples/` | `demo.sh`, `edge-local.sh`, `loadtest.sh`, and `txt-dns.py` (the one-record DNS server the demo proves its domain against). |

[docs/DESIGN.md](docs/DESIGN.md) explains why the crates split where they do,
the cache and its consistency, the click-lease algorithm and its bounds, what
the edge can and cannot enforce given KV's propagation delay, the analytics
pipeline, SSRF defences, failure modes and limits.

## License

MIT
