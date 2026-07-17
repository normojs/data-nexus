#!/usr/bin/env bash
# S2: data-plane column ACL smoke (rewrite strip + SELECT * deny).
# Requires: docker, cargo
set -euo pipefail

export PATH="/Volumes/fushilu/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin:/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:${HOME}/.cargo/bin:/Volumes/fushilu/.rustup/toolchains/nightly-2025-01-07-aarch64-apple-darwin/bin:${PATH:-}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
# Prefer local disk when external target volume is full.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.94.1}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$ROOT/examples/docker-compose.dev.yml"
CONFIG_FILE="$ROOT/examples/security-column-gateway-config.toml"
PROXY_LOG="${TMPDIR:-/tmp}/data-nexus-security-column.log"
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

echo "==> seed employees table on backend (bypass gateway)"
"${COMPOSE[@]}" exec -T mysql-primary mysql -uroot -proot -e "
CREATE DATABASE IF NOT EXISTS orders;
USE orders;
-- Recreate so schema matches column ACL smoke (ssn may be missing on older volumes).
DROP TABLE IF EXISTS employees;
CREATE TABLE employees (
  id INT PRIMARY KEY,
  name VARCHAR(64) NOT NULL,
  salary INT NOT NULL,
  ssn VARCHAR(32) NOT NULL
);
INSERT INTO employees (id, name, salary, ssn) VALUES
  (1, 'alice', 90000, '111-22-3333');
"

echo "==> building and starting gateway (security column ACL)"
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
  NEED_BUILD=1
  if [[ -n "$PROXY_BIN" ]]; then
    if [[ ! "$ROOT/gateway/core/src/pdp.rs" -nt "$PROXY_BIN" ]] \
      && [[ ! "$ROOT/runtime/gateway/src/object_extract.rs" -nt "$PROXY_BIN" ]] \
      && [[ ! "$ROOT/runtime/gateway/src/core_engine.rs" -nt "$PROXY_BIN" ]]; then
      NEED_BUILD=0
    fi
  fi
  if [[ "$NEED_BUILD" -eq 1 ]]; then
    cargo build -p data-proxy --bin proxy
    PROXY_BIN="${CARGO_TARGET_DIR}/debug/proxy"
  fi
  echo "using binary: $PROXY_BIN" >>"$PROXY_LOG"
  "$PROXY_BIN" daemon -c "$CONFIG_FILE"
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
curl -fsS "http://127.0.0.1:8082/admin/security-policies" >/tmp/data-nexus-security-column-policies.json
python3 - <<'PY'
import json
data=json.load(open("/tmp/data-nexus-security-column-policies.json"))
assert data["enabled"] is True, data
names=sorted(r["name"] for r in data["rules"])
assert "deny-employee-pii" in names, names
print("security-policies:", names)
PY

mysql_via_gateway() {
  local sql="$1"
  docker run --rm --add-host=host.docker.internal:host-gateway mysql:8.0 \
    mysql --ssl-mode=DISABLED -h host.docker.internal -P 9088 -uroot -proot -N -e "$sql"
}

echo "==> allow: SELECT 1"
out="$(mysql_via_gateway 'SELECT 1 AS ok;')"
echo "$out" | tr -d '[:space:]' | grep -qx '1'

echo "==> rewrite: SELECT id,name,salary → salary stripped"
out="$(mysql_via_gateway 'SELECT id, name, salary FROM employees WHERE id=1;')"
# Expect two fields: 1 and alice — no salary value 90000.
echo "$out"
echo "$out" | tr '\t' ' ' | grep -q '1'
echo "$out" | tr '\t' ' ' | grep -qi 'alice'
if echo "$out" | grep -q '90000'; then
  echo "salary leaked through column ACL rewrite" >&2
  exit 1
fi

echo "==> deny: SELECT * FROM employees (star_policy=deny)"
set +e
mysql_via_gateway 'SELECT * FROM employees;' >/tmp/data-nexus-security-column-star-err.txt 2>&1
star_rc=$?
set -e
[[ $star_rc -ne 0 ]]
grep -qiE 'security|denied|deny|policy|wildcard' /tmp/data-nexus-security-column-star-err.txt \
  || grep -qi 'ERROR' /tmp/data-nexus-security-column-star-err.txt
kill -0 "$PROXY_PID"

echo "==> deny: secret table still blocked"
set +e
mysql_via_gateway 'SELECT id FROM secret_tokens;' >/tmp/data-nexus-security-column-secret-err.txt 2>&1
sec_rc=$?
set -e
[[ $sec_rc -ne 0 ]]
kill -0 "$PROXY_PID"

echo "smoke-security-column: OK"
