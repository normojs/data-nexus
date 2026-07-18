#!/usr/bin/env bash
# A06: streaming max_rows truncates on MySQL and PostgreSQL protocol paths.
# security.streaming.max_rows=1, window_rows=2 (config: security-stream-gateway-config.toml).
set -euo pipefail

export PATH="/Volumes/fushilu/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin:/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:${HOME}/.cargo/bin:/Volumes/fushilu/.rustup/toolchains/nightly-2025-01-07-aarch64-apple-darwin/bin:${PATH:-}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.94.1}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$ROOT/examples/docker-compose.dev.yml"
CONFIG_FILE="$ROOT/examples/security-stream-gateway-config.toml"
PROXY_LOG="${TMPDIR:-/tmp}/data-nexus-security-stream.log"
COMPOSE=(docker compose -f "$COMPOSE_FILE")

cleanup() {
  if [[ -n "${PROXY_PID:-}" ]] && kill -0 "$PROXY_PID" 2>/dev/null; then
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing $1" >&2; exit 1; }; }
need docker; need cargo; need curl

pkill -f '/debug/proxy' 2>/dev/null || true
sleep 1

echo "==> start backends"
"${COMPOSE[@]}" up -d
for _ in $(seq 1 90); do
  "${COMPOSE[@]}" exec -T mysql-primary mysqladmin ping -h 127.0.0.1 -uroot -proot --silent 2>/dev/null && break
  sleep 2
done
for _ in $(seq 1 90); do
  "${COMPOSE[@]}" exec -T postgres-primary pg_isready -U postgres -d analytics >/dev/null 2>&1 && break
  sleep 2
done

echo "==> seed multi-row MySQL table"
"${COMPOSE[@]}" exec -T mysql-primary mysql -uroot -proot -e "
CREATE DATABASE IF NOT EXISTS orders;
USE orders;
DROP TABLE IF EXISTS stream_smoke;
CREATE TABLE stream_smoke (id INT PRIMARY KEY, name VARCHAR(32));
INSERT INTO stream_smoke VALUES (1,'a'),(2,'b'),(3,'c');
"

echo "==> seed multi-row PostgreSQL table"
"${COMPOSE[@]}" exec -T postgres-primary \
  psql -U postgres -d analytics -v ON_ERROR_STOP=1 -c \
  "DROP TABLE IF EXISTS stream_smoke;
   CREATE TABLE stream_smoke (id INT PRIMARY KEY, name TEXT);
   INSERT INTO stream_smoke VALUES (1,'a'),(2,'b'),(3,'c');"

echo "==> start gateway (max_rows=1, window_rows=2, MySQL+PG)"
PROXY_BIN="${CARGO_TARGET_DIR}/debug/proxy"
(
  cd "$ROOT"
  if [[ ! -x "$PROXY_BIN" ]] \
    || [[ "$ROOT/runtime/gateway/src/backend/mysql.rs" -nt "$PROXY_BIN" ]] \
    || [[ "$ROOT/runtime/gateway/src/backend/postgresql.rs" -nt "$PROXY_BIN" ]] \
    || [[ "$ROOT/gateway/core/src/model.rs" -nt "$PROXY_BIN" ]]; then
    cargo build -p data-proxy --bin proxy
  fi
  "$PROXY_BIN" daemon -c "$CONFIG_FILE"
) >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!

for _ in $(seq 1 120); do
  curl -fsS "http://127.0.0.1:8082/healthz" >/dev/null 2>&1 && break
  kill -0 "$PROXY_PID" 2>/dev/null || { cat "$PROXY_LOG"; exit 1; }
  sleep 1
done

mysql_via_gateway() {
  docker run --rm --add-host=host.docker.internal:host-gateway mysql:8.0 \
    mysql --ssl-mode=DISABLED -h host.docker.internal -P 9088 -uroot -proot -N -e "$1"
}

psql_via_gateway() {
  # PG frontend currently accepts startup without password check; use postgres/postgres
  # like dual-listener smoke (backend endpoint credentials).
  docker run --rm --add-host=host.docker.internal:host-gateway postgres:16-alpine \
    env PGPASSWORD=postgres \
    psql -h host.docker.internal -p 9089 -U postgres -d analytics -tAc "$1"
}

echo "==> MySQL SELECT * should return only 1 row (max_rows=1)"
out="$(mysql_via_gateway 'SELECT id, name FROM stream_smoke ORDER BY id;')"
echo "$out"
lines="$(echo "$out" | sed '/^$/d' | wc -l | tr -d ' ')"
[[ "$lines" == "1" ]] || { echo "mysql: expected 1 row, got $lines: $out" >&2; exit 1; }
echo "$out" | grep -qE $'1[[:space:]]+a'

echo "==> PostgreSQL SELECT * should return only 1 row (max_rows=1, A06 path)"
out_pg="$(psql_via_gateway 'SELECT id, name FROM stream_smoke ORDER BY id;')"
echo "$out_pg"
lines_pg="$(echo "$out_pg" | sed '/^$/d' | wc -l | tr -d ' ')"
[[ "$lines_pg" == "1" ]] || { echo "pg: expected 1 row, got $lines_pg: $out_pg" >&2; exit 1; }
echo "$out_pg" | grep -qE '1.*a'

echo "==> metrics execute_path present after traffic"
metrics="$(curl -fsS http://127.0.0.1:8082/metrics || true)"
if echo "$metrics" | grep -q 'gateway_execute_path_total'; then
  echo "$metrics" | grep 'gateway_execute_path_total' | head -8 || true
  # max_rows obligation forces Streaming (not wire passthrough).
  if echo "$metrics" | grep -q 'execute_path="streaming"'; then
    echo "streaming path counter observed"
  else
    echo "note: streaming label not present (counter naming may differ); continuing"
  fi
fi

echo "smoke-security-stream: OK"
