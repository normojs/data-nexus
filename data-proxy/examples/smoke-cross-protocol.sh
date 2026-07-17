#!/usr/bin/env bash
# Cross-protocol smoke: MySQL client -> Data Nexus -> PostgreSQL backend.
# Requires: docker, cargo, curl
# DDL is rejected by translation_policy; seed tables via backend container.
set -euo pipefail

export PATH="/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:${HOME}/.cargo/bin:/Volumes/fushilu/.rustup/toolchains/nightly-2025-01-07-aarch64-apple-darwin/bin:${PATH:-}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$ROOT/examples/docker-compose.dev.yml"
CONFIG_FILE="$ROOT/examples/cross-protocol-mysql-to-pg.toml"
PROXY_LOG="${TMPDIR:-/tmp}/data-nexus-cross-smoke.log"
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

pkill -f '/debug/proxy' 2>/dev/null || true
sleep 1

echo "==> starting PostgreSQL backend"
"${COMPOSE[@]}" up -d postgres-primary

echo "==> waiting for PostgreSQL"
for _ in $(seq 1 90); do
  if "${COMPOSE[@]}" exec -T postgres-primary \
    pg_isready -U postgres -d analytics >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
"${COMPOSE[@]}" exec -T postgres-primary pg_isready -U postgres -d analytics >/dev/null

echo "==> seed table on PostgreSQL backend (DDL not allowed via translation)"
"${COMPOSE[@]}" exec -T postgres-primary \
  psql -U postgres -d analytics -v ON_ERROR_STOP=1 -c \
  "CREATE TABLE IF NOT EXISTS xproto_t (id INT PRIMARY KEY, name TEXT);
   DELETE FROM xproto_t;"

echo "==> building and starting gateway (cross-protocol; security off)"
PROXY_BIN=""
for candidate in \
  "${CARGO_TARGET_DIR}/debug/proxy" \
  /Volumes/fushilu/.caches/data-nexus/cargo-target/debug/proxy \
  "$ROOT/target/debug/proxy"
do
  if [[ -n "$candidate" && -x "$candidate" ]]; then
    PROXY_BIN="$candidate"
    break
  fi
done
(
  cd "$ROOT"
  if [[ -z "$PROXY_BIN" ]]; then
    cargo build -p data-proxy --bin proxy
    PROXY_BIN="${CARGO_TARGET_DIR}/debug/proxy"
  fi
  echo "using binary: $PROXY_BIN" >>"$PROXY_LOG"
  "$PROXY_BIN" daemon -c "$CONFIG_FILE"
) >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!

echo "==> waiting for listener 9090 and admin 8082"
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
curl -fsS "http://127.0.0.1:8082/admin/listeners" >/tmp/data-nexus-xproto-listeners.json
python3 - <<'PY'
import json
data=json.load(open("/tmp/data-nexus-xproto-listeners.json"))
names=sorted(x["name"] for x in data)
assert names==["mysql-to-pg"], names
print("listeners:", names)
PY

mysql_via_gateway() {
  local sql="$1"
  docker run --rm --add-host=host.docker.internal:host-gateway mysql:8.0 \
    mysql --ssl-mode=DISABLED -h host.docker.internal -P 9090 -uroot -proot -N -e "$sql"
}

echo "==> MySQL client SELECT 1 via gateway -> PG"
out="$(mysql_via_gateway 'SELECT 1 AS ok;')"
echo "$out" | tr -d '[:space:]' | grep -qx '1'

echo "==> MySQL client write/read with identifier rewrite"
mysql_via_gateway "INSERT INTO xproto_t (\`id\`, \`name\`) VALUES (1, 'alice');"
out="$(mysql_via_gateway 'SELECT name FROM xproto_t WHERE id=1;')"
echo "$out" | tr -d '[:space:]' | grep -qx 'alice'

echo "==> MySQL client IFNULL rewrite + LIMIT offset form"
mysql_via_gateway "INSERT INTO xproto_t VALUES (2, 'bob'), (3, 'carol');"
out="$(mysql_via_gateway "SELECT IFNULL(name, '') FROM xproto_t ORDER BY id LIMIT 1, 1;")"
echo "$out" | tr -d '[:space:]' | grep -qx 'bob'

echo "==> MySQL client UPDATE/DELETE subset"
mysql_via_gateway "UPDATE xproto_t SET name='bobby' WHERE id=2;"
out="$(mysql_via_gateway 'SELECT name FROM xproto_t WHERE id=2;')"
echo "$out" | tr -d '[:space:]' | grep -qx 'bobby'
mysql_via_gateway 'DELETE FROM xproto_t WHERE id=3;'

echo "==> DDL must be rejected by translation policy; process stays up"
set +e
mysql_via_gateway 'DROP TABLE xproto_t;' >/tmp/data-nexus-xproto-ddl-err.txt 2>&1
ddl_rc=$?
set -e
[[ $ddl_rc -ne 0 ]]
kill -0 "$PROXY_PID"
grep -qiE 'DDL|not supported|translation' /tmp/data-nexus-xproto-ddl-err.txt \
  || grep -qiE 'error|denied|unsupported' /tmp/data-nexus-xproto-ddl-err.txt

echo "==> metrics show mysql frontend + postgresql backend"
metrics="$(curl -fsS "http://127.0.0.1:8082/metrics")"
echo "$metrics" | grep -E 'frontend_protocol' >/dev/null
echo "$metrics" | grep -E 'backend_protocol' >/dev/null

echo "smoke cross-protocol mysql->pg: OK"
