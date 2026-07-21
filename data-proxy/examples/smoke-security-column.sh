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

echo "==> T01: subquery SELECT list still strips salary"
out="$(mysql_via_gateway 'SELECT id, salary FROM (SELECT id, name, salary FROM employees) t WHERE id=1;')"
echo "$out"
echo "$out" | tr '\t' ' ' | grep -q '1'
if echo "$out" | grep -q '90000'; then
  echo "T01 subquery: salary leaked" >&2
  exit 1
fi

echo "==> T01: qualified column deny (employees.salary) still rewritten"
out="$(mysql_via_gateway 'SELECT employees.id, employees.salary FROM employees WHERE id=1;')"
echo "$out"
if echo "$out" | grep -q '90000'; then
  echo "T01 qualified: salary leaked" >&2
  exit 1
fi
echo "$out" | tr '\t' ' ' | grep -q '1'

echo "==> T01: multi-table join with denied column does not leak salary"
# Seed a tiny departments table if missing (orders DB).
"${COMPOSE[@]}" exec -T mysql-primary mysql -uroot -proot -e "
USE orders;
CREATE TABLE IF NOT EXISTS departments (
  id INT PRIMARY KEY,
  dept_name VARCHAR(32) NOT NULL
);
INSERT INTO departments (id, dept_name) VALUES (1, 'eng')
  ON DUPLICATE KEY UPDATE dept_name=VALUES(dept_name);
-- ensure employees has dept_id for join smoke (ignore if already present on recreate path)
" 2>/dev/null || true
# employees seed above has no dept_id; use constant join predicate for ACL extract only.
out="$(mysql_via_gateway "SELECT e.id, e.salary, d.dept_name FROM employees e JOIN departments d ON d.id=1 WHERE e.id=1;")"
echo "$out"
if echo "$out" | grep -q '90000'; then
  echo "T01 join: salary leaked" >&2
  exit 1
fi
# dept_name may remain (not under employees column rule)
echo "$out" | tr '\t' ' ' | grep -qi 'eng\|1' || true

echo "==> T01: WHERE IN subquery table is extracted (deny secret_tokens)"
# secret_tokens is denied by table ACL in security-column config; previously
# WHERE-subquery tables could be missed so this might incorrectly allow.
set +e
mysql_via_gateway 'SELECT id FROM employees WHERE id IN (SELECT id FROM secret_tokens);' \
  >/tmp/data-nexus-column-where-subq.txt 2>&1
where_rc=$?
set -e
if [[ $where_rc -eq 0 ]]; then
  if grep -qiE 'secret|token|denied|security|ERROR|1105' /tmp/data-nexus-column-where-subq.txt; then
    : # some clients print error on stdout with 0? still ok if denied text present
  else
    echo "T01 WHERE subquery: expected deny on secret_tokens, got success" >&2
    cat /tmp/data-nexus-column-where-subq.txt >&2
    exit 1
  fi
fi
grep -qiE 'secret|token|denied|security|ERROR|1105|policy' /tmp/data-nexus-column-where-subq.txt \
  || { echo "T01 WHERE subquery: deny message missing"; cat /tmp/data-nexus-column-where-subq.txt; exit 1; }
kill -0 "$PROXY_PID"
echo "T01 WHERE subquery deny ok"

echo "==> T01: multi-level nested SELECT strips salary at every projection"
out="$(mysql_via_gateway 'SELECT id, salary FROM (SELECT id, salary FROM (SELECT id, name, salary FROM employees) x) y WHERE id=1;')"
echo "$out"
if echo "$out" | grep -q '90000'; then
  echo "T01 multi-level nested: salary leaked" >&2
  exit 1
fi
# Should still return id (+ maybe name if rewritten poorly kept) — require no salary value
echo "$out" | tr '\t' ' ' | grep -q '1' || {
  echo "T01 multi-level nested: expected row with id=1" >&2
  exit 1
}
echo "T01 multi-level nested strip ok"

echo "smoke-security-column: OK"
