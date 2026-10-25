#!/usr/bin/env bash
# Runs the edge worker locally in front of a local origin and walks through
# what it does. Nothing here talks to Cloudflare: wrangler runs the Worker in
# workerd on this machine with a simulated KV namespace, and the cf object
# comes from wrangler's built-in placeholder (country US).
#
# Needs: docker, cargo, worker-build (cargo install worker-build --version
# 0.8.7), Node 22+, curl, python3, and oha for the latency numbers.
set -euo pipefail

PG_PORT="${RELINK_EDGE_PG_PORT:-55434}"
ORIGIN_PORT="${RELINK_EDGE_ORIGIN_PORT:-18280}"
EDGE_PORT="${RELINK_EDGE_PORT:-18787}"
PG_NAME="relink-edge-pg"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EDGE_DIR="$ROOT/crates/relink-edge"
BIN="$ROOT/target/release/relink"
ORIGIN="http://127.0.0.1:$ORIGIN_PORT"
EDGE="http://127.0.0.1:$EDGE_PORT"
WRANGLER=(npx --yes wrangler@4.151.2)
PIDS=()

COOKIE_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
EDGE_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(24))')"
export RELINK_DATABASE_URL="postgres://postgres:edge@127.0.0.1:$PG_PORT/postgres"
export RELINK_ADDR="127.0.0.1:$ORIGIN_PORT"
export RELINK_ADMIN_ADDR="127.0.0.1:$((ORIGIN_PORT + 1))"
export RELINK_COOKIE_KEY="$COOKIE_KEY"
export RELINK_EDGE_TOKEN="$EDGE_TOKEN"
# The edge forwards the visitor's address and country; trust it from loopback.
export RELINK_TRUSTED_PROXIES="127.0.0.1,::1"
export RELINK_CLIENT_IP_HEADER="x-forwarded-for"
export RELINK_COUNTRY_HEADER="cf-ipcountry"
export RELINK_LOG=warn
export WRANGLER_SEND_METRICS=false
export CLOUDFLARE_CF_FETCH_ENABLED=false

cleanup() {
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  rm -f "$EDGE_DIR/.dev.vars"
  docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for() { for _ in $(seq 1 150); do curl -fsS -o /dev/null "$1" 2>/dev/null && return 0; sleep 0.2; done; echo "timed out: $1" >&2; return 1; }
api() { curl -sS -X "$1" "$ORIGIN$2" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' ${3:+-d "$3"}; }
follow() { local u="$1"; shift; curl -sS -o /dev/null -D - "$@" "$u" | tr -d '\r' | awk 'NR==1{s=$2} tolower($1)=="location:"{l=$2} tolower($1)=="x-relink-served-by:"{b=$2} END{print s, l, "(" b ")"}'; }
publish() { # code: what the KV sync would write, into the local KV simulator
  (cd "$EDGE_DIR" && "${WRANGLER[@]}" kv key put "link:$1" "$("$BIN" kv-record "$1")" --binding LINKS --local >/dev/null 2>&1)
}

echo "== 1. Origin: Postgres and relink"
docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
docker run -d --name "$PG_NAME" -e POSTGRES_PASSWORD=edge -p "127.0.0.1:$PG_PORT:5432" postgres:16-alpine >/dev/null
for _ in $(seq 1 60); do docker exec "$PG_NAME" pg_isready -U postgres >/dev/null 2>&1 && break; sleep 0.5; done
(cd "$ROOT" && cargo build --release --quiet -p relink-server)
"$BIN" migrate >/dev/null
KEY=$("$BIN" create-key alice | sed -n 's/.*key=\(rlk_[0-9a-f]*\).*/\1/p')
"$BIN" & PIDS+=($!)
wait_for "$ORIGIN/healthz"

echo "== 2. Edge: build the Worker and start wrangler dev (local only)"
(cd "$EDGE_DIR" && worker-build --release >/dev/null 2>&1)
printf 'COOKIE_KEY=%s\nEDGE_TOKEN=%s\n' "$COOKIE_KEY" "$EDGE_TOKEN" > "$EDGE_DIR/.dev.vars"
rm -rf "$EDGE_DIR/.wrangler"
WASM="$EDGE_DIR/build/index_bg.wasm"
echo "   wasm: $(wc -c < "$WASM" | tr -d ' ') bytes, $(gzip -9 -c "$WASM" | wc -c | tr -d ' ') gzipped"

api POST /v1/links '{"url":"https://example.com/docs","alias":"guide"}' >/dev/null
api POST /v1/links '{"alias":"pricing","destinations":[{"url":"https://example.com/a"},{"url":"https://example.com/b"}]}' >/dev/null
api POST /v1/links '{"url":"https://example.com/launch","alias":"limited","max_clicks":2}' >/dev/null
api POST /v1/links '{"url":"https://example.com/new","alias":"not-yet-in-kv"}' >/dev/null
for code in guide pricing limited; do publish "$code"; done

(cd "$EDGE_DIR" && "${WRANGLER[@]}" dev --local --ip 127.0.0.1 --port "$EDGE_PORT" \
  --var "ORIGIN_URL:$ORIGIN" --var COOKIE_SECURE:false >/dev/null 2>&1) & PIDS+=($!)
wait_for "$EDGE/healthz"

echo "== 3. Requests through the edge"
echo "   guide           -> $(follow "$EDGE/guide")"
echo "   not-yet-in-kv   -> $(follow "$EDGE/not-yet-in-kv")"
echo "   limited #1..3   -> $(follow "$EDGE/limited") | $(follow "$EDGE/limited") | $(follow "$EDGE/limited")"
echo "   bad/path        -> $(follow "$EDGE/bad%2Fpath")"
COOKIE=$(curl -sS -o /dev/null -D - "$EDGE/pricing" | tr -d '\r' | sed -n 's/^set-cookie: \([^;]*\).*/\1/Ip')
AT_EDGE=$(follow "$EDGE/pricing" -H "Cookie: $COOKIE")
AT_ORIGIN=$(follow "$ORIGIN/pricing" -H "Cookie: $COOKIE")
echo "   pricing, edge cookie at edge   -> $AT_EDGE"
echo "   pricing, edge cookie at origin -> $AT_ORIGIN"
[ "$(echo "$AT_EDGE" | cut -d' ' -f2)" = "$(echo "$AT_ORIGIN" | cut -d' ' -f2)" ] && echo "   same variant on both: yes" || { echo "   same variant on both: NO"; exit 1; }

echo "== 4. Disable at the origin; the edge follows once KV has the new record"
api PATCH /v1/links/guide '{"enabled":false}' >/dev/null
echo "   origin          -> $(follow "$ORIGIN/guide")"
publish guide
echo "   edge (after KV) -> $(follow "$EDGE/guide" -H 'Cache-Control: no-cache')"

echo "== 5. Clicks served at the edge reach the origin in a batch"
sleep 6
api GET /v1/links/pricing/stats | python3 -c 'import sys, json; s = json.load(sys.stdin); print("   pricing total_clicks:", s["total_clicks"])'
curl -sS "http://127.0.0.1:$((ORIGIN_PORT + 1))/metrics" | grep -E '^relink_edge_clicks_total' | sed 's/^/   /'

if command -v oha >/dev/null; then
  echo "== 6. Latency, local workerd (one KV-cached link, 32 connections, 10 s)"
  api POST /v1/links '{"url":"https://example.com/fast","alias":"fast"}' >/dev/null
  publish fast
  follow "$EDGE/fast" >/dev/null
  oha -z 10s -c 32 -r 0 --no-tui --output-format json -o /tmp/relink-edge-oha.json "$EDGE/fast" >/dev/null
  python3 - <<'PY'
import json
d = json.load(open("/tmp/relink-edge-oha.json"))
s, p = d["summary"], d["latencyPercentiles"]
print(f"   edge hit: {s['requestsPerSec']:,.0f} req/s  p50 {p['p50']*1e3:.2f} ms  p99 {p['p99']*1e3:.2f} ms  statuses {d.get('statusCodeDistribution')}")
PY
fi
