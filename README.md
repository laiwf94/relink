# relink

A URL shortener. You create short links through an API; visitors who open
`/{code}` get redirected. The redirect is answered from memory on the origin
and can also run as a Cloudflare Worker reading from Workers KV, and it keeps
working while Postgres is down.

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
and KV errors go to the origin. Edge clicks are batched per isolate and posted
to the origin in the background.

On the origin, clicks go through a bounded queue into daily aggregates. Client
addresses are never stored, and unique visitors are counted with a keyed hash
whose salt is destroyed after two days.

## Running it

```console
$ docker run -d --name pg -e POSTGRES_PASSWORD=pg -p 5432:5432 postgres:16-alpine
$ export RELINK_DATABASE_URL=postgres://postgres:pg@localhost:5432/postgres
$ cargo run --release -p relink-server -- create-key alice   # prints id=1 owner=alice key=rlk_...
$ cargo run --release -p relink-server                       # :8080, metrics on 127.0.0.1:9090
$ ./examples/demo.sh          # the tour, including stopping Postgres mid-way
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
from those peers, so a visitor cannot pick their own country. `RELINK_KV_*`
turns on publishing to Workers KV; without it the origin works alone.

## Endpoints

The management API uses hashed API keys checked in constant time, per-key rate
limits, owner scoping, cursor pagination, strict JSON with body limits, stable
error codes and request IDs. `/v1/links` endpoints take
`Authorization: Bearer <key>` and JSON bodies; the full schema is at
`/openapi.json`, an OpenAPI 3.1 document that a test checks against the router.

| Endpoint | Purpose |
|---|---|
| `GET /{code}` | Redirect. 404 unknown or disabled, 410 expired or over its limit, 451 geo-blocked without a fallback, 503 when not cached and the database is down. |
| `POST /v1/links` | Create: `url` or `destinations`, optional `alias`, `redirect_type`, `expires_at`, `max_clicks`, `geo`, `fallback_url`, `enabled`, `health_check`. |
| `GET /v1/links?limit=&cursor=` | Your links, newest first. |
| `GET /v1/links/{code}` | One link, with per-destination health. |
| `PATCH /v1/links/{code}` | Change fields; `null` clears optional ones. |
| `DELETE /v1/links/{code}` | Delete the link and its statistics. |
| `GET /v1/links/{code}/stats?from=&to=` | Clicks per UTC day with unique visitors, top countries, devices and referrers. |
| `POST /v1/edge/clicks` | Click batches from the Worker, authenticated with `RELINK_EDGE_TOKEN`. Absent unless that is set. |
| `GET /healthz`, `/readyz`, `/openapi.json` | Liveness, readiness (stays ready with the database down, and says so), the API document. |
| `GET /metrics` (admin listener) | Prometheus metrics. |

Errors are `{"error":{"code":"invalid_argument","message":"...","request_id":"..."}}`.
The codes are `invalid_argument` 400, `unauthenticated` 401, `not_found` 404,
`method_not_allowed` 405, `already_exists` 409, `payload_too_large` 413,
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
| Edge | Handler logic against an in-memory KV and a fake origin; a local end-to-end run through `wrangler dev` (`examples/edge-local.sh`). KV publishing runs against a local fake of the Cloudflare KV API, including retries while it fails and reconciliation of drift. |
| Health checks | Local HTTP servers flip between healthy and failing; private, loopback and metadata addresses are refused; redirects are not followed; probes to one host are paced. |
| The binary | Admin commands, config errors, and a real process stopped with SIGTERM whose log never contains the API key or database URL. |
| Parsers | cargo-fuzz targets for URLs, aliases, request headers and proxy lists, request bodies, edge click batches, KV records, cursors and change notifications. |

```console
$ docker run -d -e POSTGRES_PASSWORD=postgres -p 5439:5432 postgres:16-alpine
$ export RELINK_TEST_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5439/postgres
$ cargo test                         # 167 tests; database tests skip if the variable is unset
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
| `examples/` | `demo.sh`, `edge-local.sh`, `loadtest.sh`. |

[docs/DESIGN.md](docs/DESIGN.md) explains why the crates split where they do,
the cache and its consistency, the click-lease algorithm and its bounds, what
the edge can and cannot enforce given KV's propagation delay, the analytics
pipeline, SSRF defences, failure modes and limits.

## License

MIT
