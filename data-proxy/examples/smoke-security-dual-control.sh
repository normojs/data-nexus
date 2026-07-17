#!/usr/bin/env bash
# F18: dual-control vault — pending ticket not usable; second person approves.
set -euo pipefail

export PATH="/Volumes/fushilu/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin:/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:${HOME}/.cargo/bin:/Volumes/fushilu/.rustup/toolchains/nightly-2025-01-07-aarch64-apple-darwin/bin:${PATH:-}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.94.1}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$ROOT/examples/docker-compose.dev.yml"
CONFIG_FILE="$ROOT/examples/security-ticket-gateway-config.toml"
PROXY_LOG="${TMPDIR:-/tmp}/data-nexus-security-dual-control.log"
COMPOSE=(docker compose -f "$COMPOSE_FILE")

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

echo "==> start gateway"
PROXY_BIN="${CARGO_TARGET_DIR}/debug/proxy"
(
  cd "$ROOT"
  if [[ ! -x "$PROXY_BIN" ]] \
    || [[ "$ROOT/gateway/core/src/ticket.rs" -nt "$PROXY_BIN" ]] \
    || [[ "$ROOT/http/src/http/mod.rs" -nt "$PROXY_BIN" ]]; then
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
  docker run --rm --add-host=host.docker.internal:host-gateway mysql:8.0 \
    mysql --comments --ssl-mode=DISABLED -h host.docker.internal -P 9088 -uroot -proot -N -e "$sql"
}

DDL_SQL="CREATE TABLE IF NOT EXISTS smoke_dual_t (id INT PRIMARY KEY)"

echo "==> issue dual-control ticket (pending)"
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
  "note": "dual-control smoke",
  "issued_by": "issuer-alice",
  "dual_control": True
}))
PY
)" | tee /tmp/dn-dual-ticket.json

python3 - <<'PY'
import json
t=json.load(open("/tmp/dn-dual-ticket.json"))
assert t.get("dual_control") is True, t
assert t.get("status") == "pending", t
open("/tmp/dn-dual-ticket-id.txt","w").write(t["id"])
print("pending ticket", t["id"])
PY
TICKET_ID="$(cat /tmp/dn-dual-ticket-id.txt)"

echo "==> pending ticket cannot be consumed on data plane"
set +e
mysql_via_gateway "/*dn_ticket:${TICKET_ID}*/ ${DDL_SQL};" >/tmp/dn-dual-pending.txt 2>&1
rc=$?
set -e
[[ $rc -ne 0 ]]
grep -qiE 'ticket|pending|dual|approval|security|ERROR' /tmp/dn-dual-pending.txt
cat /tmp/dn-dual-pending.txt || true

echo "==> self-approve must fail"
set +e
curl -sS -X POST "http://127.0.0.1:8082/admin/tickets/${TICKET_ID}/approve" \
  -H 'content-type: application/json' \
  -d '{"approved_by":"issuer-alice"}' | tee /tmp/dn-dual-self.json
set -e
python3 - <<'PY'
import json
raw=open("/tmp/dn-dual-self.json").read().lower()
assert "error" in raw or "differ" in raw or "issuer" in raw or "failed" in raw, raw
print("self-approve blocked")
PY

echo "==> second person approves"
curl -fsS -X POST "http://127.0.0.1:8082/admin/tickets/${TICKET_ID}/approve" \
  -H 'content-type: application/json' \
  -d '{"approved_by":"approver-bob"}' | tee /tmp/dn-dual-approved.json
python3 - <<'PY'
import json
t=json.load(open("/tmp/dn-dual-approved.json"))
assert t.get("status") == "active", t
assert t.get("approved_by") == "approver-bob", t
print("approved", t["id"])
PY

echo "==> DDL with approved ticket succeeds"
mysql_via_gateway "/*dn_ticket:${TICKET_ID}*/ ${DDL_SQL};" >/tmp/dn-dual-ok.txt 2>&1 || {
  cat /tmp/dn-dual-ok.txt
  exit 1
}

echo "==> ticket cannot be reused"
set +e
mysql_via_gateway "/*dn_ticket:${TICKET_ID}*/ ${DDL_SQL};" >/tmp/dn-dual-reuse.txt 2>&1
rc2=$?
set -e
[[ $rc2 -ne 0 ]]

echo "==> reject path for a fresh dual ticket"
DDL2="CREATE TABLE IF NOT EXISTS smoke_dual_reject_t (id INT PRIMARY KEY)"
curl -fsS -X POST "http://127.0.0.1:8082/admin/tickets" \
  -H 'content-type: application/json' \
  -d "$(python3 - <<PY
import json
print(json.dumps({
  "subject_id": "root",
  "sql": """$DDL2""",
  "ticket_type": "ddl",
  "ttl_secs": 300,
  "issued_by": "issuer-alice",
  "dual_control": True
}))
PY
)" >/tmp/dn-dual-rej-ticket.json
REJ_ID="$(python3 -c 'import json;print(json.load(open("/tmp/dn-dual-rej-ticket.json"))["id"])')"
curl -fsS -X POST "http://127.0.0.1:8082/admin/tickets/${REJ_ID}/reject" \
  -H 'content-type: application/json' \
  -d '{"rejected_by":"approver-bob","reason":"too risky"}' | tee /tmp/dn-dual-rejected.json
python3 - <<'PY'
import json
t=json.load(open("/tmp/dn-dual-rejected.json"))
assert t.get("status") == "rejected", t
print("rejected", t["id"])
PY
set +e
mysql_via_gateway "/*dn_ticket:${REJ_ID}*/ ${DDL2};" >/tmp/dn-dual-rej-use.txt 2>&1
rc3=$?
set -e
[[ $rc3 -ne 0 ]]

echo "smoke-security-dual-control: OK"
