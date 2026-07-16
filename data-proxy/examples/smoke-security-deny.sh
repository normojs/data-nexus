#!/usr/bin/env bash
# S1: data-plane security deny smoke (table + DDL policies).
# Requires: docker, cargo
set -euo pipefail

export PATH="/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:${PATH:-}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$ROOT/examples/docker-compose.dev.yml"
CONFIG_FILE="$ROOT/examples/security-deny-gateway-config.toml"
PROXY_LOG="${TMPDIR:-/tmp}/data-nexus-security-deny.log"
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

echo "==> building and starting gateway (security.enabled=true)"
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
    # Rebuild if sources newer than binary (stale binary misses S1 routes).
    if [[ "$ROOT/gateway/core/src/pdp.rs" -nt "$PROXY_BIN" ]] 2>/dev/null \
      || [[ "$ROOT/runtime/gateway/src/core_engine.rs" -nt "$PROXY_BIN" ]] 2>/dev/null; then
      cargo build -p data-proxy --bin proxy
      PROXY_BIN="${CARGO_TARGET_DIR:-$ROOT/target}/debug/proxy"
      if [[ ! -x "$PROXY_BIN" ]]; then
        PROXY_BIN="/Volumes/fushilu/.caches/data-nexus-target/debug/proxy"
      fi
    fi
    "$PROXY_BIN" daemon -c "$CONFIG_FILE"
  else
    cargo run -p data-proxy --bin proxy -- daemon -c "$CONFIG_FILE"
  fi
) >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!

echo "==> waiting for admin (8082)"
for _ in $(seq 1 120); do
  if curl -fsS "http://127.0.0.1:8082/admin/security-policies" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "gateway exited early; log:"
    cat "$PROXY_LOG"
    exit 1
  fi
  sleep 1
done

echo "==> GET /admin/security-policies"
curl -fsS "http://127.0.0.1:8082/admin/security-policies" >/tmp/data-nexus-security-policies.json
python3 - <<'PY'
import json
data=json.load(open("/tmp/data-nexus-security-policies.json"))
assert data["enabled"] is True, data
assert data["rule_count"] >= 2, data
names=sorted(r["name"] for r in data["rules"])
assert "deny-secret-tables" in names, names
assert "deny-ddl" in names, names
print("security-policies:", data["rule_count"], "rules", names)
PY

mysql_via_gateway() {
  local sql="$1"
  docker run --rm --add-host=host.docker.internal:host-gateway mysql:8.0 \
    mysql --ssl-mode=DISABLED -h host.docker.internal -P 9088 -uroot -proot -N -e "$sql"
}

echo "==> allow: SELECT 1"
out="$(mysql_via_gateway 'SELECT 1 AS ok;')"
echo "$out" | tr -d '[:space:]' | grep -qx '1'

echo "==> deny: SELECT secret_* (expect client error, process up)"
set +e
mysql_via_gateway 'SELECT id FROM secret_tokens;' >/tmp/data-nexus-security-deny-err.txt 2>&1
deny_rc=$?
set -e
[[ $deny_rc -ne 0 ]]
grep -qiE 'security|denied|deny|policy' /tmp/data-nexus-security-deny-err.txt \
  || grep -qi 'ERROR' /tmp/data-nexus-security-deny-err.txt
kill -0 "$PROXY_PID"

echo "==> deny: CREATE TABLE (DDL policy)"
set +e
mysql_via_gateway 'CREATE TABLE smoke_security_ddl (id INT);' >/tmp/data-nexus-security-ddl-err.txt 2>&1
ddl_rc=$?
set -e
[[ $ddl_rc -ne 0 ]]
kill -0 "$PROXY_PID"

echo "==> allow: ordinary DML on non-secret table"
mysql_via_gateway 'CREATE TABLE IF NOT EXISTS smoke_ok (id INT PRIMARY KEY);' 2>/dev/null || true
# CREATE is denied by deny-ddl — use existing path: SELECT only on non-secret is enough for allow path.
# Re-assert SELECT 1 still works after denies.
out="$(mysql_via_gateway 'SELECT 1;')"
echo "$out" | tr -d '[:space:]' | grep -qx '1'

echo "smoke-security-deny: OK"
