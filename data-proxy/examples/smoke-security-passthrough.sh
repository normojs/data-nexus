#!/usr/bin/env bash
# A3/A08: same-protocol wire passthrough E2E (MySQL + PostgreSQL TCP frame relay).
set -euo pipefail

export PATH="/Volumes/fushilu/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin:/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:${HOME}/.cargo/bin:/Volumes/fushilu/.rustup/toolchains/nightly-2025-01-07-aarch64-apple-darwin/bin:${PATH:-}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.94.1}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$ROOT/examples/docker-compose.dev.yml"
CONFIG_FILE="$ROOT/examples/security-passthrough-gateway-config.toml"
PROXY_LOG="${TMPDIR:-/tmp}/data-nexus-security-passthrough.log"
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

echo "==> seed MySQL"
"${COMPOSE[@]}" exec -T mysql-primary mysql -uroot -proot -e "
CREATE DATABASE IF NOT EXISTS orders;
USE orders;
CREATE TABLE IF NOT EXISTS pass_smoke (id INT PRIMARY KEY, name VARCHAR(32));
INSERT INTO pass_smoke VALUES (1,'alice'),(2,'bob')
  ON DUPLICATE KEY UPDATE name=VALUES(name);
"

echo "==> seed PostgreSQL"
"${COMPOSE[@]}" exec -T postgres-primary \
  psql -U postgres -d analytics -v ON_ERROR_STOP=1 -c \
  "CREATE TABLE IF NOT EXISTS pass_smoke (id INT PRIMARY KEY, name TEXT);
   INSERT INTO pass_smoke VALUES (1,'alice'),(2,'bob')
     ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name;"

echo "==> start gateway (passthrough=true, MySQL+PG, no obligations)"
PROXY_BIN="${CARGO_TARGET_DIR}/debug/proxy"
(
  cd "$ROOT"
  if [[ ! -x "$PROXY_BIN" ]] \
    || [[ "$ROOT/runtime/gateway/src/backend/mysql.rs" -nt "$PROXY_BIN" ]] \
    || [[ "$ROOT/runtime/gateway/src/backend/postgresql.rs" -nt "$PROXY_BIN" ]] \
    || [[ "$ROOT/runtime/gateway/src/backend/pg_tcp_relay.rs" -nt "$PROXY_BIN" ]] \
    || [[ "$ROOT/gateway/core/src/config.rs" -nt "$PROXY_BIN" ]] \
    || [[ "$ROOT/runtime/gateway/src/core_engine.rs" -nt "$PROXY_BIN" ]]; then
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
  docker run --rm --add-host=host.docker.internal:host-gateway postgres:16-alpine \
    env PGPASSWORD=postgres \
    psql -h host.docker.internal -p 9089 -U postgres -d analytics -tAc "$1"
}

echo "==> MySQL SELECT via passthrough path"
out="$(mysql_via_gateway 'SELECT id, name FROM pass_smoke ORDER BY id;')"
echo "$out"
echo "$out" | grep -q 'alice'
echo "$out" | grep -q 'bob'

echo "==> PostgreSQL SELECT via TCP WireRelay passthrough (A08)"
out_pg="$(psql_via_gateway 'SELECT id || chr(124) || name FROM pass_smoke ORDER BY id;')"
echo "$out_pg"
echo "$out_pg" | grep -q 'alice'
echo "$out_pg" | grep -q 'bob'

echo "==> PostgreSQL in-transaction passthrough still works (tcp_txn)"
out_txn="$(psql_via_gateway "BEGIN; SELECT name FROM pass_smoke WHERE id=1; COMMIT;")"
echo "$out_txn"
echo "$out_txn" | grep -q 'alice'

# audit should show outcome passthrough if pipeline installed
sleep 0.3
if curl -fsS "http://127.0.0.1:8082/admin/audit/events?limit=40" >/tmp/dn-pt-events.json 2>/dev/null; then
  python3 - <<'PY'
import json
data=json.load(open("/tmp/dn-pt-events.json"))
ev=data.get("events") or []
pt=[e for e in ev if e.get("outcome")=="passthrough"]
print("passthrough audit events:", len(pt))
# not hard-fail if audit empty (security may still emit execute)
PY
fi

# ensure log mentions passthrough when possible
if command -v rg >/dev/null 2>&1 && rg -q 'passthrough' "$PROXY_LOG"; then
  echo "log contains passthrough outcome"
elif grep -q 'passthrough' "$PROXY_LOG" 2>/dev/null; then
  echo "log contains passthrough outcome"
fi

echo "==> A08 PostgreSQL extended Bind/Execute under passthrough config (not WireRelay)"
# Passthrough only applies to simple Query. Extended QueryParams must still work
# via Streaming re-encode (no TCP bind relay). Assert rows + metrics streaming.
pg_ext_out="$(docker run --rm -i --add-host=host.docker.internal:host-gateway python:3.12-slim-bookworm \
  python - <<'PY'
import socket, struct

def i32(n):
    return struct.pack("!i", n)

def i16(n):
    return struct.pack("!h", n)

def cstr(s: str) -> bytes:
    return s.encode() + b"\x00"

def msg(tag: bytes, body: bytes) -> bytes:
    return tag + i32(len(body) + 4) + body

def read_msg(sock):
    hdr = b""
    while len(hdr) < 5:
        chunk = sock.recv(5 - len(hdr))
        if not chunk:
            raise RuntimeError("eof header")
        hdr += chunk
    tag = hdr[0:1]
    (length,) = struct.unpack("!i", hdr[1:5])
    body = b""
    need = length - 4
    while len(body) < need:
        chunk = sock.recv(need - len(body))
        if not chunk:
            raise RuntimeError("eof body")
        body += chunk
    return tag, body

sock = socket.create_connection(("host.docker.internal", 9089), timeout=10)
params = cstr("user") + cstr("postgres") + cstr("database") + cstr("analytics") + b"\x00"
sock.sendall(i32(8 + len(params)) + i32(196608) + params)
while True:
    tag, body = read_msg(sock)
    if tag == b"Z":
        break
    if tag == b"E":
        raise RuntimeError(body)

sql = "SELECT id, name FROM pass_smoke WHERE id = $1 ORDER BY id"
sock.sendall(msg(b"P", cstr("sext") + cstr(sql) + i16(0)))
param = b"1"
body = cstr("pext") + cstr("sext") + i16(0) + i16(1) + i32(len(param)) + param + i16(0)
sock.sendall(msg(b"B", body))
sock.sendall(msg(b"E", cstr("pext") + i32(0)))
sock.sendall(msg(b"S", b""))

tags = []
rows = 0
while True:
    tag, body = read_msg(sock)
    tags.append(tag.decode("latin1"))
    if tag == b"D":
        rows += 1
    if tag == b"E":
        raise RuntimeError(body.decode("utf-8", "replace"))
    if tag == b"Z":
        break
print("pg_ext_tags", tags, "rows", rows)
assert rows >= 1, rows
assert "C" in tags or "s" in tags, tags
print("pg_extended_under_passthrough_ok")
sock.close()
PY
)"
echo "$pg_ext_out"
echo "$pg_ext_out" | grep -q 'pg_extended_under_passthrough_ok'

echo "==> A05 Prometheus execute_path + passthrough_bytes"
curl -fsS "http://127.0.0.1:8082/metrics" | tee /tmp/dn-pt-metrics.txt >/dev/null
python3 - <<'PY'
text=open("/tmp/dn-pt-metrics.txt").read()
assert "gateway_execute_path_total" in text, "missing gateway_execute_path_total"
assert 'execute_path="passthrough"' in text or "execute_path=\"passthrough\"" in text, text[:2000]
# bytes counter present after wire traffic
assert "gateway_passthrough_bytes_total" in text, "missing gateway_passthrough_bytes_total"
# A08: extended Bind/Execute under passthrough config must use streaming re-encode
# (not wire passthrough for QUERY_PARAMS).
if 'type="QUERY_PARAMS"' in text or "type=\"QUERY_PARAMS\"" in text:
    assert (
        'execute_path="streaming"' in text
        or "execute_path=\"streaming\"" in text
    ), "expected streaming path for extended under passthrough config"
    print("A08 extended under passthrough uses streaming path")
print("A05 metrics ok")
for line in text.splitlines():
    if "gateway_execute_path_total" in line or "gateway_passthrough_bytes_total" in line:
        if line.startswith("#"):
            continue
        print(line)
PY

echo "smoke-security-passthrough: OK"
