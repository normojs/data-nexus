#!/usr/bin/env bash
# S5: high-risk ticket gate — no ticket blocked, with ticket allowed once.
set -euo pipefail

export PATH="/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:${HOME}/.cargo/bin:/Volumes/fushilu/.rustup/toolchains/nightly-2025-01-07-aarch64-apple-darwin/bin:${PATH:-}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Users/fushilu/workspace/revocloud/data-nexus/.cargo-target}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$ROOT/examples/docker-compose.dev.yml"
CONFIG_FILE="$ROOT/examples/security-ticket-gateway-config.toml"
PROXY_LOG="${TMPDIR:-/tmp}/data-nexus-security-ticket.log"
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

echo "==> start gateway"
PROXY_BIN="${CARGO_TARGET_DIR}/debug/proxy"
(
  cd "$ROOT"
  if [[ ! -x "$PROXY_BIN" ]] \
    || [[ "$ROOT/gateway/core/src/ticket.rs" -nt "$PROXY_BIN" ]] \
    || [[ "$ROOT/gateway/core/src/pdp.rs" -nt "$PROXY_BIN" ]]; then
    cargo build -p data-proxy --bin proxy
  fi
  "$PROXY_BIN" daemon -c "$CONFIG_FILE"
) >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!

for _ in $(seq 1 120); do
  curl -fsS "http://127.0.0.1:8082/admin/security-policies" >/dev/null 2>&1 && break
  kill -0 "$PROXY_PID" 2>/dev/null || { cat "$PROXY_LOG"; exit 1; }
  sleep 1
done

mysql_via_gateway() {
  local sql="$1"
  # --comments: keep /*dn_ticket:...*/ so the gateway can extract the ticket id.
  docker run --rm --add-host=host.docker.internal:host-gateway mysql:8.0 \
    mysql --comments --ssl-mode=DISABLED -h host.docker.internal -P 9088 -uroot -proot -N -e "$sql"
}

DDL_SQL="CREATE TABLE IF NOT EXISTS smoke_ticket_t (id INT PRIMARY KEY)"

echo "==> SELECT 1 still allowed"
out="$(mysql_via_gateway 'SELECT 1;')"
echo "$out" | tr -d '[:space:]' | grep -qx '1'

echo "==> DDL without ticket is blocked"
set +e
mysql_via_gateway "$DDL_SQL;" >/tmp/dn-ticket-deny.txt 2>&1
rc=$?
set -e
[[ $rc -ne 0 ]]
grep -qiE 'ticket|require|approval|security' /tmp/dn-ticket-deny.txt \
  || grep -qi 'ERROR' /tmp/dn-ticket-deny.txt
cat /tmp/dn-ticket-deny.txt || true

echo "==> issue ticket via Admin API"
curl -fsS -X POST "http://127.0.0.1:8082/admin/tickets" \
  -H 'content-type: application/json' \
  -d "$(python3 - <<PY
import json
print(json.dumps({
  "subject_id": "root",
  "sql": """$DDL_SQL""",
  "ticket_type": "ddl",
  "ttl_secs": 300,
  "max_uses": 1,
  "note": "smoke"
}))
PY
)" | tee /tmp/dn-ticket.json

TICKET_ID="$(python3 - <<'PY'
import json
print(json.load(open("/tmp/dn-ticket.json"))["id"])
PY
)"
echo "ticket_id=$TICKET_ID"

echo "==> DDL with ticket succeeds"
mysql_via_gateway "/*dn_ticket:${TICKET_ID}*/ ${DDL_SQL};" >/tmp/dn-ticket-ok.txt 2>&1 || {
  cat /tmp/dn-ticket-ok.txt
  exit 1
}

echo "==> same ticket cannot be reused"
set +e
mysql_via_gateway "/*dn_ticket:${TICKET_ID}*/ ${DDL_SQL};" >/tmp/dn-ticket-reuse.txt 2>&1
rc2=$?
set -e
[[ $rc2 -ne 0 ]]

echo "smoke-security-ticket: OK"
