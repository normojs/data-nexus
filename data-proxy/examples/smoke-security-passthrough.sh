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
    || [[ "$ROOT/gateway/core/src/transport.rs" -nt "$PROXY_BIN" ]] \
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

echo "==> A08 PostgreSQL extended text-bind under passthrough (backend re-encoded P/B/E TCP)"
# Text-bindable $1 re-encodes as backend Parse/Bind/Execute/Sync (passthrough_extended).
# Still NOT original client Parse/Bind frame relay. Backend 1/2/Z stripped until Sync.
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

def drain_until(sock, stop):
    tags = []
    rows = 0
    while True:
        tag, body = read_msg(sock)
        tags.append(tag.decode("latin1"))
        if tag == b"D":
            rows += 1
        if tag == b"E":
            raise RuntimeError(body.decode("utf-8", "replace"))
        if tag in stop:
            return tags, rows, tag

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
# Parse/Bind complete locally as ClientWire; drain those before Execute.
tags_pb, _, _ = drain_until(sock, frozenset({b"2", b"E"}))  # BindComplete = '2'
print("after_bind", tags_pb)
assert "1" in tags_pb, tags_pb  # ParseComplete
assert "2" in tags_pb, tags_pb

sock.sendall(msg(b"E", cstr("pext") + i32(0)))
# Drain Execute result WITHOUT Sync: must end at CommandComplete/PortalSuspended, no Z.
# Backend re-encode includes Describe(portal) → expect RowDescription (T) before DataRow.
tags_ex, rows, end = drain_until(sock, frozenset({b"C", b"s", b"E"}))
print("after_execute", tags_ex, "rows", rows, "end", end)
assert rows >= 1, rows
assert end in (b"C", b"s"), tags_ex
assert "Z" not in tags_ex, f"backend ReadyForQuery leaked before Sync: {tags_ex}"
assert "1" not in tags_ex and "2" not in tags_ex, f"backend Parse/BindComplete leaked: {tags_ex}"
assert "T" in tags_ex, f"expected RowDescription from backend Describe(portal): {tags_ex}"
assert "D" in tags_ex, tags_ex

sock.sendall(msg(b"S", b""))
tags_sync, _, endz = drain_until(sock, frozenset({b"Z", b"E"}))
print("after_sync", tags_sync, "end", endz)
assert endz == b"Z", tags_sync
print("pg_extended_under_passthrough_ok")
print("a08_extended_wire_rowdesc_no_premature_ready_ok")
sock.close()
PY
)"
echo "$pg_ext_out"
echo "$pg_ext_out" | grep -q 'pg_extended_under_passthrough_ok'
echo "$pg_ext_out" | grep -q 'a08_extended_wire_rowdesc_no_premature_ready_ok'

echo "==> A08 MySQL COM_STMT under passthrough config (not WireRelay)"
# Prepared Execute must demote to Streaming (COM_STMT path), not Complete materialize.
mysql_prep_out="$(docker run --rm --add-host=host.docker.internal:host-gateway python:3.12-slim-bookworm \
  bash -lc 'pip install -q --disable-pip-version-check mysql-connector-python >/tmp/pip.log 2>&1 || { cat /tmp/pip.log; exit 1; }
python - <<"PY"
import mysql.connector
cnx = mysql.connector.connect(
    host="host.docker.internal",
    port=9088,
    user="root",
    password="root",
    database="orders",
    ssl_disabled=True,
    connection_timeout=10,
)
try:
    cur = cnx.cursor(prepared=True)
    cur.execute(
        "SELECT id, name FROM pass_smoke WHERE id = %s ORDER BY id",
        (1,),
    )
    rows = cur.fetchall()
    print("mysql_prep_rows", rows)
    assert len(rows) >= 1, rows
    assert rows[0][0] == 1 or str(rows[0][0]) == "1", rows
    assert "alice" in str(rows[0][1]), rows
    print("mysql_prepared_under_passthrough_ok")
    cur.close()
finally:
    cnx.close()
PY
')"
echo "$mysql_prep_out"
echo "$mysql_prep_out" | grep -q 'mysql_prepared_under_passthrough_ok'

echo "==> A05 Prometheus execute_path + passthrough_bytes"
curl -fsS "http://127.0.0.1:8082/metrics" | tee /tmp/dn-pt-metrics.txt >/dev/null
python3 - <<'PY2'
text=open("/tmp/dn-pt-metrics.txt").read()
assert "gateway_execute_path_total" in text, "missing gateway_execute_path_total"
assert 'execute_path="passthrough"' in text or "execute_path=\"passthrough\"" in text, text[:2000]
assert "gateway_passthrough_bytes_total" in text, "missing gateway_passthrough_bytes_total"
has_ext = (
    'type="QUERY_PARAMS"' in text
    or 'type="EXECUTE"' in text
    or "type=\"QUERY_PARAMS\"" in text
    or "type=\"EXECUTE\"" in text
)
assert has_ext, "expected QUERY_PARAMS or EXECUTE after extended traffic"
# A08: PG extended text-bind → backend re-encoded Parse/Bind/Execute TCP.
# Honesty label: execute_path=passthrough_extended (aliases passthrough_rewrite).
# MySQL COM_STMT remains streaming_demote. Still NOT original client frame relay.
pg_qp_ext = any(
    ('QUERY_PARAMS' in ln)
    and ('passthrough_extended' in ln or 'passthrough_rewrite' in ln)
    and ('gateway_execute_path_total' in ln)
    for ln in text.splitlines() if not ln.startswith('#')
)
assert pg_qp_ext, "expected QUERY_PARAMS execute_path=passthrough_extended after PG text-bind"
pg_qp_bytes = any(
    ('QUERY_PARAMS' in ln) and ('gateway_passthrough_bytes_total' in ln) and not ln.startswith('#')
    for ln in text.splitlines()
)
assert pg_qp_bytes, "expected passthrough_bytes for QUERY_PARAMS after PG text-bind"
print("A08 honesty: PG QUERY_PARAMS text-bind → passthrough_extended + wire bytes")
# MySQL COM_STMT should still demote (binary bind unsafe as text rewrite)
mysql_demote = any(
    ('EXECUTE' in ln) and ('streaming_demote' in ln or 'streaming' in ln) and ('mysql' in ln)
    for ln in text.splitlines() if 'gateway_execute_path_total' in ln and not ln.startswith('#')
)
assert mysql_demote, "expected MySQL EXECUTE streaming_demote under passthrough"
print("A08 honesty: MySQL COM_STMT remains streaming_demote (not text rewrite)")
print("A08 still NOT original client Parse/Bind/Execute frame relay")
print("A05 metrics ok")
for line in text.splitlines():
    if "gateway_execute_path_total" in line or "gateway_passthrough_bytes_total" in line:
        if line.startswith("#"):
            continue
        print(line)
PY2

echo "smoke-security-passthrough: OK"
