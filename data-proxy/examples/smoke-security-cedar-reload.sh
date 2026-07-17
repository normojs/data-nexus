#!/usr/bin/env bash
# Cedar hot-reload: swap policy epoch, keep-old on bad file, no listener restart.
# Requires rustc ≥1.88 (uses 1.94.1 when available) and --features security-cedar.
set -euo pipefail

export RUSTUP_HOME="${RUSTUP_HOME:-/Volumes/fushilu/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
if [[ -x /Volumes/fushilu/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/cargo ]]; then
  export PATH="/Volumes/fushilu/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin:${HOME}/.cargo/bin:/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:${PATH:-}"
elif [[ -x "$HOME/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/cargo" ]]; then
  export PATH="$HOME/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin:${HOME}/.cargo/bin:/usr/local/bin:${PATH:-}"
else
  export PATH="/usr/local/bin:/opt/homebrew/bin:${HOME}/.cargo/bin:${PATH:-}"
fi
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$ROOT/examples/docker-compose.dev.yml"
# Writable policy dir for hot-reload experiments
POLICY_DIR="${TMPDIR:-/tmp}/dn-cedar-reload-policies"
CONFIG_FILE="${TMPDIR:-/tmp}/dn-cedar-reload-gateway.toml"
PROXY_LOG="${TMPDIR:-/tmp}/data-nexus-security-cedar-reload.log"
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

echo "==> rustc $(rustc --version)"
pkill -f '/debug/proxy' 2>/dev/null || true
sleep 1

mkdir -p "$POLICY_DIR"
# Start with deny-secret policies (same as orders.cedar)
cp "$ROOT/examples/cedar-policies/orders.cedar" "$POLICY_DIR/orders.cedar"

# Config points at writable policy dir
cat >"$CONFIG_FILE" <<EOF
version = "2"

[admin]
host = "0.0.0.0"
port = 8082
log_level = "INFO"

[security]
enabled = true
fail_closed = true
star_policy = "allow"
default_audit_level = "L0"

[security.subject]
sources = ["protocol_user"]

[security.pdp]
backend = "cedar"
policy_dir = "$POLICY_DIR"
cache_epoch_reload = true

[security.streaming]
window_rows = 256
passthrough = true

[security.audit]
queue_capacity = 65536
overflow = "drop_new"
sinks = ["tracing"]

[[listeners]]
name = "orders-mysql"
listen_addr = "0.0.0.0:9088"
protocol = "mysql"
service = "orders"
auth_policy = "local-users"

[[services]]
name = "orders"
backend_protocol = "mysql"
endpoints = ["orders-primary"]
route_policy = "orders-balance"
plugin_policies = []

[[endpoints]]
name = "orders-primary"
protocol = "mysql"
address = "127.0.0.1:13306"
database = "orders"
username = "root"
password = "root"
weight = 1

[[route_policies]]
name = "orders-balance"
kind = "simple_load_balance"

[[auth_policies]]
name = "local-users"
kind = "static"
username = "root"
password = "root"
EOF

echo "==> backends"
"${COMPOSE[@]}" up -d
for _ in $(seq 1 90); do
  "${COMPOSE[@]}" exec -T mysql-primary mysqladmin ping -h 127.0.0.1 -uroot -proot --silent 2>/dev/null && break
  sleep 2
done

echo "==> seed"
"${COMPOSE[@]}" exec -T mysql-primary mysql -uroot -proot -e "
CREATE DATABASE IF NOT EXISTS orders;
USE orders;
CREATE TABLE IF NOT EXISTS portal_t (id INT PRIMARY KEY, name VARCHAR(32));
INSERT INTO portal_t VALUES (1,'portal') ON DUPLICATE KEY UPDATE name=VALUES(name);
CREATE TABLE IF NOT EXISTS secret_tokens (id INT PRIMARY KEY, token VARCHAR(64));
INSERT INTO secret_tokens VALUES (1,'x') ON DUPLICATE KEY UPDATE token=VALUES(token);
"

echo "==> build + start gateway (security-cedar)"
PROXY_BIN="${CARGO_TARGET_DIR}/debug/proxy"
(
  cd "$ROOT"
  if [[ ! -x "$PROXY_BIN" ]] || [[ "$ROOT/gateway/core/src/cedar_pdp.rs" -nt "$PROXY_BIN" ]] \
    || [[ "$ROOT/http/src/http/mod.rs" -nt "$PROXY_BIN" ]]; then
    cargo build -p data-proxy --bin proxy --features security-cedar
  fi
)
: >"$PROXY_LOG"
(
  cd "$ROOT"
  exec "$PROXY_BIN" daemon -c "$CONFIG_FILE"
) >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!

for _ in $(seq 1 120); do
  curl -fsS "http://127.0.0.1:8082/admin/security/cedar" >/dev/null 2>&1 && break
  if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "gateway exited early; log:"; cat "$PROXY_LOG"; exit 1
  fi
  sleep 1
done

mysql_via_gateway() {
  local sql="$1"
  docker run --rm --add-host=host.docker.internal:host-gateway mysql:8.0 \
    mysql --ssl-mode=DISABLED -h host.docker.internal -P 9088 -uroot -proot -N -e "$sql"
}

echo "==> status before"
curl -fsS "http://127.0.0.1:8082/admin/security/cedar" | tee /tmp/dn-cedar-st1.json
python3 - <<'PY'
import json
s=json.load(open("/tmp/dn-cedar-st1.json"))
assert s.get("ready") is True or s.get("files",0)>=1, s
assert s.get("epoch",0) >= 1, s
open("/tmp/dn-cedar-epoch1.txt","w").write(str(s["epoch"]))
print("epoch1", s["epoch"], "policies", s.get("policy_count"))
PY
EPOCH1="$(cat /tmp/dn-cedar-epoch1.txt)"

echo "==> secret denied under initial policies"
set +e
mysql_via_gateway 'SELECT id FROM secret_tokens;' >/tmp/dn-cedar-deny1.txt 2>&1
rc=$?
set -e
[[ $rc -ne 0 ]]
grep -qiE 'cedar|deny|secret|ERROR' /tmp/dn-cedar-deny1.txt

echo "==> write more-permissive policy and hot-reload"
cat >"$POLICY_DIR/orders.cedar" <<'CEDAR'
permit (principal, action == Action::"select", resource);
permit (principal, action == Action::"select", resource == Table::"__none__");
CEDAR
curl -fsS -X POST "http://127.0.0.1:8082/admin/security/cedar/reload" | tee /tmp/dn-cedar-reload-ok.json
python3 - <<PY
import json
r=json.load(open("/tmp/dn-cedar-reload-ok.json"))
assert r.get("swapped") is True, r
assert int(r["epoch"]) > int("$EPOCH1"), r
print("epoch after swap", r["epoch"])
open("/tmp/dn-cedar-epoch2.txt","w").write(str(r["epoch"]))
PY
EPOCH2="$(cat /tmp/dn-cedar-epoch2.txt)"

echo "==> secret SELECT now allowed (same process)"
out="$(mysql_via_gateway 'SELECT id FROM secret_tokens WHERE id=1;')"
echo "$out" | tr -d '[:space:]' | grep -qx '1'

echo "==> bad policy keep-old"
echo 'this is not valid cedar {{{' >"$POLICY_DIR/orders.cedar"
set +e
curl -sS -X POST "http://127.0.0.1:8082/admin/security/cedar/reload" | tee /tmp/dn-cedar-reload-bad.json
set -e
python3 - <<PY
import json
raw=open("/tmp/dn-cedar-reload-bad.json").read().lower()
assert "kept previous" in raw or "invalid" in raw or "failed" in raw, raw
print("bad reload rejected")
PY
curl -fsS "http://127.0.0.1:8082/admin/security/cedar" | tee /tmp/dn-cedar-st3.json
python3 - <<PY
import json
s=json.load(open("/tmp/dn-cedar-st3.json"))
assert int(s["epoch"]) == int("$EPOCH2"), s
print("epoch kept", s["epoch"])
PY

echo "==> still allowed (keep-old permissive snapshot)"
out="$(mysql_via_gateway 'SELECT id FROM secret_tokens WHERE id=1;')"
echo "$out" | tr -d '[:space:]' | grep -qx '1'

echo "==> process still up"
kill -0 "$PROXY_PID"

echo "smoke-security-cedar-reload: OK"
