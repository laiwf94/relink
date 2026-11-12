#!/usr/bin/env bash
# Walks through relink end to end: starts Postgres in Docker and a release
# build of relink, creates links of every kind, follows them with curl, shows
# stats, then workspace isolation, scoped and rotated API keys, a plan limit
# and the audit chain, then a custom domain proved by a DNS TXT record (from
# a one-record DNS server, examples/txt-dns.py) with its own codes, root
# redirect, path prefix, case-free codes and 404 and 410 pages, then stops
# Postgres to show redirects still being
# served from memory while writes fail cleanly, and finally restarts Postgres
# to show recovery.
#
# Needs: docker, cargo, curl, python3. Uses ports 18080, 19090 and 55432 by
# default (RELINK_DEMO_PORT, RELINK_DEMO_ADMIN_PORT, RELINK_DEMO_PG_PORT),
# and UDP port 15353 for DNS (RELINK_DEMO_DNS_PORT).
set -euo pipefail

PORT="${RELINK_DEMO_PORT:-18080}"
ADMIN_PORT="${RELINK_DEMO_ADMIN_PORT:-19090}"
PG_PORT="${RELINK_DEMO_PG_PORT:-55432}"
DNS_PORT="${RELINK_DEMO_DNS_PORT:-15353}"
DOMAIN="go.relink-demo.net"
PG_NAME="relink-demo-pg"
URL="http://127.0.0.1:$PORT"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/release/relink"
LOG="$(mktemp -t relink-demo.XXXXXX)"
RELINK_PID=""
DNS_PID=""

export RELINK_DATABASE_URL="postgres://postgres:demo@127.0.0.1:$PG_PORT/postgres"
export RELINK_ADDR="127.0.0.1:$PORT"
export RELINK_ADMIN_ADDR="127.0.0.1:$ADMIN_PORT"
export RELINK_PUBLIC_BASE_URL="$URL"
export RELINK_COOKIE_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export RELINK_COOKIE_SECURE=false
export RELINK_DB_TIMEOUT_MS=1000
# curl plays the CDN here, so loopback is the trusted proxy.
export RELINK_TRUSTED_PROXIES="127.0.0.1,::1"
export RELINK_COUNTRY_HEADER=cf-ipcountry
# Custom domains are proved against the demo's own DNS server.
export RELINK_DNS_SERVERS="127.0.0.1:$DNS_PORT"

cleanup() {
  [ -n "$RELINK_PID" ] && kill "$RELINK_PID" 2>/dev/null && wait "$RELINK_PID" 2>/dev/null || true
  [ -n "$DNS_PID" ] && kill "$DNS_PID" 2>/dev/null || true
  docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
  echo "(server log: $LOG)"
}
trap cleanup EXIT

field() { python3 -c "import sys, json; print(json.load(sys.stdin)$1)"; }
api() { # method path [json]
  curl -sS -X "$1" "$URL$2" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' ${3:+-d "$3"}
}
status() { # method path [json] -> HTTP status only
  curl -sS -o /dev/null -w '%{http_code}' -X "$1" "$URL$2" -H "Authorization: Bearer $KEY" \
    -H 'Content-Type: application/json' ${3:+-d "$3"}
}
on_domain() { # path -> "status location-or-body" as seen on $DOMAIN
  curl -sS -w ' %{http_code} %{redirect_url}' -H "Host: $DOMAIN" "$URL/$1" | python3 -c '
import sys
out = sys.stdin.read().rsplit(" ", 2)
print(out[1], out[2] or out[0])'
}
follow() { # code [curl args...] -> "status location"
  local code="$1"; shift
  curl -sS -o /dev/null -w '%{http_code} %{redirect_url}' "$@" "$URL/$code"
}
wait_for() { # url
  for _ in $(seq 1 100); do curl -fsS -o /dev/null "$1" 2>/dev/null && return 0; sleep 0.2; done
  echo "timed out waiting for $1" >&2; return 1
}

echo "== 1. Start Postgres and relink"
docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
docker run -d --name "$PG_NAME" -e POSTGRES_PASSWORD=demo -p "127.0.0.1:$PG_PORT:5432" postgres:16-alpine >/dev/null
for _ in $(seq 1 60); do docker exec "$PG_NAME" pg_isready -U postgres >/dev/null 2>&1 && break; sleep 0.5; done
(cd "$ROOT" && cargo build --release --quiet -p relink-server)
"$BIN" migrate
KEY=$("$BIN" create-key alice demo | sed -n 's/.*key=\(rlk_[0-9a-f]*\).*/\1/p')
echo "   API key for alice: ${KEY:0:12}..."
"$BIN" >"$LOG" 2>&1 &
RELINK_PID=$!
wait_for "$URL/healthz"
kill -0 "$RELINK_PID" 2>/dev/null || { echo "relink exited; see $LOG" >&2; exit 1; }

echo "== 2. Create links"
RANDOM_CODE=$(api POST /v1/links '{"url":"https://example.com/docs/getting-started"}' | field "['code']")
echo "   random code:  $RANDOM_CODE"
api POST /v1/links '{"url":"https://example.com/sale","alias":"summer-sale","redirect_type":301}' >/dev/null
echo "   alias:        summer-sale (301)"
api POST /v1/links '{"alias":"pricing-test","destinations":[
  {"url":"https://example.com/pricing-a","weight":3},
  {"url":"https://example.com/pricing-b","weight":1}]}' >/dev/null
echo "   A/B 3:1:      pricing-test"
api POST /v1/links '{"url":"https://example.com/launch","alias":"first-three","max_clicks":3}' >/dev/null
echo "   max clicks 3: first-three"
api POST /v1/links '{"url":"https://example.com/us-store","alias":"us-only",
  "geo":{"mode":"allow","countries":["US"]},"fallback_url":"https://example.com/intl"}' >/dev/null
echo "   US only:      us-only (others go to the fallback)"
echo "   invalid destination -> $(status POST /v1/links '{"url":"http://169.254.169.254/latest/meta-data"}')"

echo "== 3. Follow them"
echo "   $RANDOM_CODE          -> $(follow "$RANDOM_CODE")"
echo "   summer-sale      -> $(follow summer-sale)"
A=0; B=0
for _ in $(seq 1 40); do
  case "$(follow pricing-test)" in *pricing-a) A=$((A+1));; *pricing-b) B=$((B+1));; esac
done
echo "   pricing-test x40 -> a=$A b=$B (new visitors, weights 3:1)"
COOKIE=$(curl -sS -o /dev/null -D - "$URL/pricing-test" | sed -n 's/^set-cookie: \([^;]*\).*/\1/Ip')
FIRST=$(follow pricing-test -H "Cookie: $COOKIE")
SAME=1; for _ in $(seq 1 10); do [ "$(follow pricing-test -H "Cookie: $COOKIE")" = "$FIRST" ] || SAME=0; done
echo "   with its cookie  -> $FIRST (same 10/10: $([ $SAME = 1 ] && echo yes || echo no))"
for i in 1 2 3 4; do echo "   first-three #$i   -> $(follow first-three)"; done
echo "   us-only from US  -> $(follow us-only -H 'CF-IPCountry: US')"
echo "   us-only from DE  -> $(follow us-only -H 'CF-IPCountry: DE')"
echo "   unknown code     -> $(follow does-not-exist)"

echo "== 4. Stats (clicks are batched; wait for one flush)"
sleep 1.5
api GET /v1/links/pricing-test/stats | python3 -c '
import sys, json
s = json.load(sys.stdin)
print("   pricing-test total_clicks=%d unique_visitors=%d devices=%s" % (
    s["total_clicks"], s["days"][0]["unique_visitors"] if s["days"] else 0,
    {b["value"]: b["clicks"] for b in s["devices"]}))'

echo "== 5. Workspaces: scoped keys, isolation, a plan and the audit log"
WS=$(api GET /v1/usage | field "['workspace_id']")
echo "   alice's workspace: $WS"
LINE=$("$BIN" create-key alice dashboard --scopes links:read,stats:read --expires-in 1h)
RO_ID=$(echo "$LINE" | sed -n 's/^id=\([0-9]*\).*/\1/p')
RO=$(echo "$LINE" | sed -n 's/.*key=\(rlk_[0-9a-f]*\).*/\1/p')
ro() { curl -sS -o /dev/null -w '%{http_code}' -X "$1" "$URL$2" -H "Authorization: Bearer $RO" \
  -H 'Content-Type: application/json' ${3:+-d "$3"}; }
echo "   read-only key: list links -> HTTP $(ro GET /v1/links), create -> HTTP $(ro POST /v1/links '{"url":"https://example.com/x"}')"
NEW=$("$BIN" rotate-key "$RO_ID" --overlap 1h | sed -n 's/.*key=\(rlk_[0-9a-f]*\).*/\1/p')
echo "   rotated: old key -> HTTP $(ro GET /v1/usage), new key -> HTTP $(RO=$NEW ro GET /v1/usage) (1 h overlap)"
BOB=$("$BIN" create-key bob demo | sed -n 's/.*key=\(rlk_[0-9a-f]*\).*/\1/p')
echo "   bob's key sees $(curl -sS "$URL/v1/links" -H "Authorization: Bearer $BOB" | field "['links'].__len__()") of alice's links; summer-sale for bob -> HTTP $(KEY=$BOB status GET /v1/links/summer-sale)"
"$BIN" plan-set demo --links 5 --monthly-clicks 100000 | sed 's/^/   /'
"$BIN" plan-assign "$WS" demo | sed 's/^/   /'
echo "   6th link on a 5-link plan -> $(api POST /v1/links '{"url":"https://example.com/six"}' | field "['error']['code']")"
echo "   usage: $(api GET /v1/usage | python3 -c 'import sys, json; u = json.load(sys.stdin); print("links %d/%s, clicks this month %d" % (u["links"]["used"], u["links"]["limit"], u["clicks"]["used"]))')"
"$BIN" plan-assign "$WS" unlimited >/dev/null
echo "   back on the unlimited plan"
"$BIN" audit-verify --workspace "$WS" | sed 's/^/   audit chain /'

echo "== 6. A custom domain: DNS proof, its own codes and its own pages"
api POST /v1/domains "{\"hostname\":\"$DOMAIN\"}" >/dev/null
api POST "/v1/domains/$DOMAIN/verify" | field "['check_error']" | sed 's/^/   verify before the TXT record is served: /'
PROOF=$(api GET "/v1/domains/$DOMAIN" | field "['verification']['value']")
python3 "$ROOT/examples/txt-dns.py" "$DNS_PORT" "_relink-challenge.$DOMAIN" "$PROOF" &
DNS_PID=$!
sleep 0.5
echo "   TXT _relink-challenge.$DOMAIN = ${PROOF:0:40}..."
echo "   verify now: verified=$(api POST "/v1/domains/$DOMAIN/verify" | field "['verified']" | tr 'TF' 'tf')"
api POST /v1/links "{\"url\":\"https://example.com/brand-sale\",\"alias\":\"summer-sale\",\"domain\":\"$DOMAIN\"}" | field "['short_url']" | sed 's/^/   same code, its own link: /'
api PATCH "/v1/domains/$DOMAIN" '{"root_url":"https://example.com/","prefixes":["campaign"],
  "case_insensitive":true,"not_found_page":"<h1>{{code}} is not on {{host}}</h1>",
  "gone_page":"<p>{{code}} has ended</p>"}' >/dev/null
api POST /v1/links "{\"url\":\"https://example.com/flash\",\"alias\":\"flash\",\"domain\":\"$DOMAIN\",\"max_clicks\":1}" >/dev/null
echo "   /                      -> $(on_domain '')   (root redirect)"
echo "   /summer-sale           -> $(on_domain summer-sale)"
echo "   /campaign/SUMMER-SALE  -> $(on_domain campaign/SUMMER-SALE)   (prefix, any case)"
echo "   default /summer-sale   -> $(follow summer-sale)"
echo "   /nope                  -> $(on_domain nope)"
on_domain flash >/dev/null
echo "   /flash after its click -> $(on_domain flash)"
echo "   certificate: $(api GET "/v1/domains/$DOMAIN" | field "['certificate']['status']") (set RELINK_ACME_DIRECTORY to have one issued)"

echo "== 7. Stop Postgres"
docker stop "$PG_NAME" >/dev/null
echo "   $RANDOM_CODE          -> $(follow "$RANDOM_CODE")   (served from memory)"
echo "   summer-sale      -> $(follow summer-sale)"
echo "   pricing-test     -> $(follow pricing-test -H "Cookie: $COOKIE")"
echo "   create link      -> HTTP $(status POST /v1/links '{"url":"https://example.com/new"}') (fails cleanly)"
echo "   not cached       -> $(follow never-seen)"
echo "   readyz           -> $(curl -sS "$URL/readyz")"

echo "== 8. Start Postgres again"
docker start "$PG_NAME" >/dev/null
for _ in $(seq 1 60); do docker exec "$PG_NAME" pg_isready -U postgres >/dev/null 2>&1 && break; sleep 0.5; done
for _ in $(seq 1 40); do [ "$(status POST /v1/links '{"url":"https://example.com/new"}')" = 201 ] && break; sleep 0.5; done
echo "   create link      -> HTTP 201"
sleep 2
echo "   $RANDOM_CODE total_clicks (includes clicks during the outage): $(api GET "/v1/links/$RANDOM_CODE/stats" | field "['total_clicks']")"
echo "   metrics:"
curl -sS "http://127.0.0.1:$ADMIN_PORT/metrics" | grep -E '^relink_(cache_requests_total|clicks_dropped_total|redirects_total)' | sed 's/^/     /'
