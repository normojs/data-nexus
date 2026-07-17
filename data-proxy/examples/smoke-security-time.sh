#!/usr/bin/env bash
# F27: time-window policy — writes denied outside business hours; SELECT allowed.
set -euo pipefail

export PATH="/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:${HOME}/.cargo/bin:/Volumes/fushilu/.rustup/toolchains/nightly-2025-01-07-aarch64-apple-darwin/bin:${PATH:-}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$ROOT/examples/docker-compose.dev.yml"
CONFIG_FILE="$ROOT/examples/security-time-gateway-config.toml"
PROXY_LOG="${TMPDIR:-/tmp}/data-nexus-security-time.log"
COMPOSE=(docker compose -f "$COMPOSE_FILE")

# Pin wall clock to Fri 2026-07-17 20:00:00 UTC (outside 09–18 window).
OUTSIDE_TS="$(python3 - <<'PY'
from datetime import datetime, timezone
print(int(datetime(2026, 7, 17, 20, 0, 0, tzinfo=timezone.utc).timestamp()))
PY
)"
INSIDE_TS="$(python3 - <<'PY'
from datetime import datetime, timezone
print(int(datetime(2026, 7, 17, 10, 0, 0, tzinfo=timezone.utc).timestamp()))
PY
)"

cleanup() {
  if [[ -n "${PROXY_PID:-}" ]] && kill -0 "$PROXY_PID" 2>/dev/null; then
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing $1" >&2; exit 1; }; }
need docker; need cargo; need curl; need python3

pkill -f '/debug/proxy' 2>/dev/null || true
sleep 1

echo "==> start backends"
"${COMPOSE[@]}" up -d
for _ in $(seq 1 90); do
  "${COMPOSE[@]}" exec -T mysql-primary mysqladmin ping -h 127.0.0.1 -uroot -proot --silent 2>/dev/null && break
  sleep 2
done

echo "==> start gateway (outside business hours, now=$OUTSIDE_TS)"
PROXY_BIN="${CARGO_TARGET_DIR}/debug/proxy"
(
  cd "$ROOT"
  if [[ ! -x "$PROXY_BIN" ]] \
    || [[ "$ROOT/gateway/core/src/time_rules.rs" -nt "$PROXY_BIN" ]] \
    || [[ "$ROOT/gateway/core/src/pdp.rs" -nt "$PROXY_BIN" ]]; then
    cargo build -p data-proxy --bin proxy
  fi
  # exec so PROXY_PID is the real proxy (pkill/kill both work).
  exec env DATA_NEXUS_SECURITY_NOW_UNIX="$OUTSIDE_TS" "$PROXY_BIN" daemon -c "$CONFIG_FILE"
) >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!

for _ in $(seq 1 120); do
  curl -fsS "http://127.0.0.1:8082/admin/security-policies" >/dev/null 2>&1 && break
  kill -0 "$PROXY_PID" 2>/dev/null || { cat "$PROXY_LOG"; exit 1; }
  sleep 1
done

mysql_via_gateway() {
  local sql="$1"
  docker run --rm --add-host=host.docker.internal:host-gateway mysql:8.0 \
    mysql --ssl-mode=DISABLED -h host.docker.internal -P 9088 -uroot -proot -N -e "$sql"
}

echo "==> SELECT 1 allowed outside hours"
out="$(mysql_via_gateway 'SELECT 1;')"
echo "$out" | tr -d '[:space:]' | grep -qx '1'

echo "==> INSERT denied outside hours"
set +e
mysql_via_gateway "INSERT INTO smoke_time_t VALUES (1);" >/tmp/dn-time-deny.txt 2>&1
rc=$?
set -e
[[ $rc -ne 0 ]]
grep -qiE 'time|business|work-hours|security|denied|ERROR' /tmp/dn-time-deny.txt
cat /tmp/dn-time-deny.txt || true

echo "==> DDL denied outside hours"
set +e
mysql_via_gateway "CREATE TABLE IF NOT EXISTS smoke_time_t (id INT PRIMARY KEY);" >/tmp/dn-time-ddl.txt 2>&1
rc2=$?
set -e
[[ $rc2 -ne 0 ]]

echo "==> restart gateway inside business hours (now=$INSIDE_TS)"
if [[ -n "${PROXY_PID:-}" ]]; then
  kill "$PROXY_PID" 2>/dev/null || true
  wait "$PROXY_PID" 2>/dev/null || true
fi
# Subshell PID may not own the binary if it re-execs; free the ports hard.
pkill -f '/debug/proxy' 2>/dev/null || true
sleep 1
: >"$PROXY_LOG"
(
  cd "$ROOT"
  export DATA_NEXUS_SECURITY_NOW_UNIX="$INSIDE_TS"
  exec env DATA_NEXUS_SECURITY_NOW_UNIX="$INSIDE_TS" "$PROXY_BIN" daemon -c "$CONFIG_FILE"
) >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!
for _ in $(seq 1 120); do
  curl -fsS "http://127.0.0.1:8082/admin/security-policies" >/dev/null 2>&1 && break
  kill -0 "$PROXY_PID" 2>/dev/null || { cat "$PROXY_LOG"; exit 1; }
  sleep 1
done

echo "==> DDL allowed inside hours"
mysql_via_gateway "CREATE TABLE IF NOT EXISTS smoke_time_t (id INT PRIMARY KEY);" >/tmp/dn-time-ok.txt 2>&1 || {
  cat /tmp/dn-time-ok.txt
  exit 1
}
mysql_via_gateway "INSERT INTO smoke_time_t VALUES (1) ON DUPLICATE KEY UPDATE id=id;" >/tmp/dn-time-ins.txt 2>&1 || {
  cat /tmp/dn-time-ins.txt
  exit 1
}
out="$(mysql_via_gateway 'SELECT id FROM smoke_time_t WHERE id=1;')"
echo "$out" | tr -d '[:space:]' | grep -qx '1'

echo "smoke-security-time: OK"
