#!/usr/bin/env bash
# Local dual-listener smoke test for Data Nexus v2.
# Requires: docker, cargo
# Clients: uses docker exec mysql/psql when host clients are missing.
set -euo pipefail

export PATH="/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:${PATH:-}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$ROOT/examples/docker-compose.dev.yml"
CONFIG_FILE="$ROOT/examples/dual-listener-gateway-config.toml"
PROXY_LOG="${TMPDIR:-/tmp}/data-nexus-smoke.log"
COMPOSE=(docker compose -f "$COMPOSE_FILE")

cleanup() {
  if [[ -n "${PROXY_PID:-}" ]] && kill -0 "$PROXY_PID" 2>/dev/null; then
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

need docker
need cargo
need curl

echo "==> starting backend containers"
"${COMPOSE[@]}" up -d

echo "==> waiting for MySQL"
for _ in $(seq 1 90); do
  if "${COMPOSE[@]}" exec -T mysql-primary \
    mysqladmin ping -h 127.0.0.1 -uroot -proot --silent 2>/dev/null; then
    break
  fi
  sleep 2
done
"${COMPOSE[@]}" exec -T mysql-primary mysqladmin ping -h 127.0.0.1 -uroot -proot --silent

echo "==> waiting for PostgreSQL"
for _ in $(seq 1 90); do
  if "${COMPOSE[@]}" exec -T postgres-primary \
    pg_isready -U postgres -d analytics >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
"${COMPOSE[@]}" exec -T postgres-primary pg_isready -U postgres -d analytics >/dev/null

echo "==> building and starting gateway"
# Prefer prebuilt binary when available (shared cargo target).
PROXY_BIN=""
for candidate in \
  "${CARGO_TARGET_DIR:-}/debug/proxy" \
  /Volumes/fushilu/.caches/data-nexus-target/debug/proxy \
  "$ROOT/target/debug/proxy"
do
  if [[ -n "$candidate" && -x "$candidate" ]]; then
    PROXY_BIN="$candidate"
    break
  fi
done
(
  cd "$ROOT"
  if [[ -n "$PROXY_BIN" ]]; then
    echo "using binary: $PROXY_BIN" >>"$PROXY_LOG"
    "$PROXY_BIN" daemon -c "$CONFIG_FILE"
  else
    cargo run -p data-proxy --bin proxy -- daemon -c "$CONFIG_FILE"
  fi
) >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!

echo "==> waiting for listeners (9088/9089) and admin (8082)"
for _ in $(seq 1 120); do
  if curl -fsS "http://127.0.0.1:8082/admin/listeners" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "gateway exited early; log:"
    cat "$PROXY_LOG"
    exit 1
  fi
  sleep 1
done
curl -fsS "http://127.0.0.1:8082/admin/listeners" >/tmp/data-nexus-listeners.json
python3 - <<'PY'
import json
data=json.load(open("/tmp/data-nexus-listeners.json"))
names=sorted(x["name"] for x in data)
assert names==["analytics-postgresql","orders-mysql"], names
print("listeners:", names)
PY

mysql_via_gateway() {
  local sql="$1"
  # Reach host gateway from container network via host.docker.internal.
  # Gateway does not terminate TLS; force plaintext mysql protocol.
  docker run --rm --add-host=host.docker.internal:host-gateway mysql:8.0 \
    mysql --ssl-mode=DISABLED -h host.docker.internal -P 9088 -uroot -proot -N -e "$sql"
}

psql_via_gateway() {
  local sql="$1"
  docker run --rm --add-host=host.docker.internal:host-gateway postgres:16-alpine \
    env PGPASSWORD=postgres \
    psql -h host.docker.internal -p 9089 -U postgres -d analytics -tAc "$sql"
}

echo "==> MySQL SELECT via gateway"
out="$(mysql_via_gateway 'SELECT 1 AS ok;')"
echo "$out" | tr -d '[:space:]' | grep -qx '1'

echo "==> MySQL write + read via gateway"
mysql_via_gateway 'CREATE TABLE IF NOT EXISTS smoke_t (id INT PRIMARY KEY, name VARCHAR(32));'
mysql_via_gateway 'DELETE FROM smoke_t;'
mysql_via_gateway "INSERT INTO smoke_t VALUES (1, 'alice');"
out="$(mysql_via_gateway 'SELECT name FROM smoke_t WHERE id=1;')"
echo "$out" | tr -d '[:space:]' | grep -qx 'alice'

echo "==> MySQL transaction via gateway"
mysql_via_gateway 'BEGIN; INSERT INTO smoke_t VALUES (2, "bob"); COMMIT;'
out="$(mysql_via_gateway 'SELECT name FROM smoke_t WHERE id=2;')"
echo "$out" | tr -d '[:space:]' | grep -qx 'bob'

echo "==> PostgreSQL SELECT via gateway"
out="$(psql_via_gateway 'SELECT 1;')"
echo "$out" | tr -d '[:space:]' | grep -qx '1'

echo "==> PostgreSQL write + read via gateway"
psql_via_gateway 'CREATE TABLE IF NOT EXISTS smoke_t (id INT PRIMARY KEY, name TEXT);'
psql_via_gateway 'DELETE FROM smoke_t;'
psql_via_gateway "INSERT INTO smoke_t VALUES (1, 'alice');"
out="$(psql_via_gateway 'SELECT name FROM smoke_t WHERE id=1;')"
echo "$out" | tr -d '[:space:]' | grep -qx 'alice'

echo "==> PostgreSQL transaction via gateway"
psql_via_gateway "BEGIN; INSERT INTO smoke_t VALUES (2, 'bob'); COMMIT;"
out="$(psql_via_gateway 'SELECT name FROM smoke_t WHERE id=2;')"
echo "$out" | tr -d '[:space:]' | grep -qx 'bob'

echo "==> error SQL should return client error, process stays up"
set +e
mysql_via_gateway 'SELECT * FROM definitely_missing_table_xyz;' >/tmp/data-nexus-mysql-err.txt 2>&1
mysql_rc=$?
psql_via_gateway 'SELECT * FROM definitely_missing_table_xyz;' >/tmp/data-nexus-pg-err.txt 2>&1
pg_rc=$?
set -e
[[ $mysql_rc -ne 0 ]]
[[ $pg_rc -ne 0 ]]
kill -0 "$PROXY_PID"

echo "==> metrics labels present"
metrics="$(curl -fsS "http://127.0.0.1:8082/metrics")"
echo "$metrics" | grep -E 'frontend_protocol|backend_protocol|service' >/dev/null
echo "$metrics" | grep -E 'mysql|postgresql' >/dev/null || true

echo "smoke dual-listener: OK"
