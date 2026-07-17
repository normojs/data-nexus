#!/usr/bin/env bash
# A4: MySQL client -> PG backend with streaming window encode (window_rows=2).
set -euo pipefail

export PATH="/Volumes/fushilu/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin:/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:${HOME}/.cargo/bin:/Volumes/fushilu/.rustup/toolchains/nightly-2025-01-07-aarch64-apple-darwin/bin:${PATH:-}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.94.1}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$ROOT/examples/docker-compose.dev.yml"
CONFIG_FILE="$ROOT/examples/cross-protocol-mysql-to-pg.toml"
PROXY_LOG="${TMPDIR:-/tmp}/data-nexus-cross-stream-smoke.log"
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

echo "==> start PostgreSQL"
"${COMPOSE[@]}" up -d postgres-primary
for _ in $(seq 1 90); do
  "${COMPOSE[@]}" exec -T postgres-primary pg_isready -U postgres -d analytics >/dev/null 2>&1 && break
  sleep 2
done

echo "==> seed multi-row table"
"${COMPOSE[@]}" exec -T postgres-primary \
  psql -U postgres -d analytics -v ON_ERROR_STOP=1 -c \
  "CREATE TABLE IF NOT EXISTS xproto_stream (id INT PRIMARY KEY, name TEXT);
   DELETE FROM xproto_stream;
   INSERT INTO xproto_stream VALUES (1,'a'),(2,'b'),(3,'c');"

echo "==> start gateway"
PROXY_BIN="${CARGO_TARGET_DIR}/debug/proxy"
(
  cd "$ROOT"
  if [[ ! -x "$PROXY_BIN" ]] || [[ "$ROOT/runtime/gateway/src/core_engine.rs" -nt "$PROXY_BIN" ]]; then
    cargo build -p data-proxy --bin proxy
  fi
  "$PROXY_BIN" daemon -c "$CONFIG_FILE"
) >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!

for _ in $(seq 1 120); do
  curl -fsS "http://127.0.0.1:8082/admin/listeners" >/dev/null 2>&1 && break
  kill -0 "$PROXY_PID" 2>/dev/null || { cat "$PROXY_LOG"; exit 1; }
  sleep 1
done

mysql_via_gateway() {
  docker run --rm --add-host=host.docker.internal:host-gateway mysql:8.0 \
    mysql --ssl-mode=DISABLED -h host.docker.internal -P 9090 -uroot -proot -N -e "$1"
}

echo "==> cross-protocol SELECT (window encode path)"
out="$(mysql_via_gateway 'SELECT id, name FROM xproto_stream ORDER BY id;')"
echo "$out"
echo "$out" | grep -q $'1\ta\|1\ta'
echo "$out" | grep -q 'c'
lines="$(echo "$out" | sed '/^$/d' | wc -l | tr -d ' ')"
[[ "$lines" == "3" ]] || { echo "expected 3 rows got $lines" >&2; exit 1; }

# INSERT/UPDATE still work through translation
echo "==> write path"
mysql_via_gateway "INSERT INTO xproto_stream (id, name) VALUES (4, 'd');" >/dev/null
out2="$(mysql_via_gateway 'SELECT name FROM xproto_stream WHERE id=4;')"
echo "$out2" | grep -qi d

if rg -q 'xproto_stream' "$PROXY_LOG"; then
  echo "log contains xproto_stream outcome"
else
  echo "warn: xproto_stream outcome not in log (check tracing level)"
  rg -n 'outcome|gateway command audited' "$PROXY_LOG" | tail -5 || true
fi

echo "smoke-cross-protocol-stream: OK"
