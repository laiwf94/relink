#!/usr/bin/env bash
# Measures the redirect path with oha (https://github.com/hatoo/oha):
#   1. cached hits: one hot link, served from memory;
#   2. cache misses: 200,000 links, cache disabled, every request is a
#      coalesced Postgres lookup;
#   3. max-clicks overshoot: three instances share one link with
#      max_clicks=100000 and are hammered concurrently; then the same with one
#      instance killed with SIGKILL half way.
#
# Needs: docker, cargo, oha, curl, python3. Client and server share the
# machine, so the numbers are a floor for the server, not a ceiling.
set -euo pipefail

DURATION="${RELINK_LOAD_DURATION:-15s}"
CONC="${RELINK_LOAD_CONCURRENCY:-64}"
PG_PORT="${RELINK_LOAD_PG_PORT:-55433}"
PG_NAME="relink-load-pg"
BASE_PORT="${RELINK_LOAD_PORT:-18180}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/release/relink"
PIDS=()

export RELINK_DATABASE_URL="postgres://postgres:load@127.0.0.1:$PG_PORT/postgres"
export RELINK_LOG=warn
export RELINK_HEALTH_ENABLED=false
export RELINK_COOKIE_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export RELINK_API_RATE=1000 RELINK_API_BURST=1000

cleanup() {
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

start() { # port admin_port [VAR=value...] -> pid in $LAST_PID
  local port="$1" admin="$2"; shift 2
  env RELINK_ADDR="127.0.0.1:$port" RELINK_ADMIN_ADDR="127.0.0.1:$admin" "$@" "$BIN" >/dev/null 2>&1 &
  LAST_PID=$!
  PIDS+=("$LAST_PID")
  for _ in $(seq 1 100); do curl -fsS -o /dev/null "http://127.0.0.1:$port/healthz" 2>/dev/null && break; sleep 0.1; done
  kill -0 "$LAST_PID"
}
summary() { # label json-file
  python3 - "$1" "$2" <<'PY'
import json, sys
label, path = sys.argv[1], sys.argv[2]
d = json.load(open(path))
s, p = d["summary"], d["latencyPercentiles"]
codes = d.get("statusCodeDistribution", {})
print(f"{label:<28} {s['requestsPerSec']:>10,.0f} req/s   p50 {p['p50']*1e3:7.3f} ms   p99 {p['p99']*1e3:7.3f} ms   statuses {codes}")
PY
}

docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
docker run -d --name "$PG_NAME" -e POSTGRES_PASSWORD=load -p "127.0.0.1:$PG_PORT:5432" postgres:16-alpine >/dev/null
for _ in $(seq 1 60); do docker exec "$PG_NAME" pg_isready -U postgres >/dev/null 2>&1 && break; sleep 0.5; done
(cd "$ROOT" && cargo build --release --quiet -p relink-server)
"$BIN" migrate >/dev/null
KEY=$("$BIN" create-key loadtest | sed -n 's/.*key=\(rlk_[0-9a-f]*\).*/\1/p')
OUT="$(mktemp -d -t relink-load.XXXXXX)"

echo "== seeding 200,000 links"
docker exec "$PG_NAME" psql -q -U postgres -c "
  INSERT INTO links (code, owner, destinations)
  SELECT 'load-' || lpad(i::text, 6, '0'), 'loadtest',
         jsonb_build_array(jsonb_build_object('url', 'https://example.com/p/' || i, 'weight', 1))
    FROM generate_series(0, 199999) i;
  INSERT INTO links (code, owner, destinations)
  VALUES ('hot', 'loadtest', '[{\"url\":\"https://example.com/hot\",\"weight\":1}]');"

echo "== 1. cached hits"
start "$BASE_PORT" $((BASE_PORT + 1))
curl -fsS -o /dev/null "http://127.0.0.1:$BASE_PORT/hot" -w '' || true
oha -z "$DURATION" -c "$CONC" -r 0 --no-tui --output-format json -o "$OUT/hit.json" "http://127.0.0.1:$BASE_PORT/hot"
summary "cached hit" "$OUT/hit.json"
oha -z "$DURATION" -c "$CONC" -r 0 --no-tui --output-format json -o "$OUT/neg.json" \
  --rand-regex-url "http://127.0.0.1:$BASE_PORT/nope-[0-9]{2}"
summary "unknown code (negative hit)" "$OUT/neg.json"

echo "== 2. cache misses (cache disabled)"
start $((BASE_PORT + 2)) $((BASE_PORT + 3)) RELINK_CACHE_CAPACITY=0
oha -z "$DURATION" -c "$CONC" -r 0 --no-tui --output-format json -o "$OUT/miss.json" \
  --rand-regex-url "http://127.0.0.1:$((BASE_PORT + 2))/load-[01][0-9]{5}"
summary "cache miss (Postgres)" "$OUT/miss.json"

echo "== 3. max-clicks overshoot, three instances, 180,000 requests"
overshoot() { # alias kill_one
  local alias="$1" kill_one="$2" ports=() pids=() ohas=()
  curl -fsS -o /dev/null -X POST "http://127.0.0.1:$BASE_PORT/v1/links" -H "Authorization: Bearer $KEY" \
    -H 'Content-Type: application/json' -d "{\"url\":\"https://example.com/limited\",\"alias\":\"$alias\",\"max_clicks\":100000}"
  for i in 0 1 2; do
    local port=$((BASE_PORT + 10 + i * 2 + ${3:-0}))
    start "$port" $((port + 1))
    ports+=("$port"); pids+=("$LAST_PID")
  done
  for i in 0 1 2; do
    oha -n 60000 -c 32 -r 0 --no-tui --output-format json -o "$OUT/$alias-$i.json" \
      "http://127.0.0.1:${ports[$i]}/$alias" &
    ohas+=($!)
  done
  if [ "$kill_one" = yes ]; then sleep 0.3; kill -9 "${pids[2]}"; fi
  wait "${ohas[@]}" || true
  python3 - "$OUT" "$alias" <<'PY'
import json, sys
out, alias = sys.argv[1], sys.argv[2]
served = gone = other = 0
for i in range(3):
    d = json.load(open(f"{out}/{alias}-{i}.json"))
    c = d.get("statusCodeDistribution", {})
    served += c.get("302", 0); gone += c.get("410", 0)
    other += sum(v for k, v in c.items() if k not in ("302", "410"))
errors = 0
for i in range(3):
    errors += sum(json.load(open(f"{out}/{alias}-{i}.json")).get("errorDistribution", {}).values())
print(f"   max_clicks=100000 served={served} gone={gone} other={other} errors={errors} "
      f"overshoot={max(0, served - 100000)} undershoot={max(0, 100000 - served)}")
PY
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  sleep 1
}
overshoot limited-a no
echo "== 3b. same, one instance killed with SIGKILL mid-run (its unspent lease is lost)"
overshoot limited-b yes 6
