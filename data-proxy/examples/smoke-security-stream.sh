#!/usr/bin/env bash
# A06: streaming max_rows truncates on MySQL and PostgreSQL protocol paths.
# A10: prepared / QueryParams protocol paths also honor max_rows under Streaming.
# security.streaming.max_rows=1, window_rows=2 (config: security-stream-gateway-config.toml).
set -euo pipefail

export PATH="/Volumes/fushilu/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin:/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:${HOME}/.cargo/bin:/Volumes/fushilu/.rustup/toolchains/nightly-2025-01-07-aarch64-apple-darwin/bin:${PATH:-}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.94.1}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$ROOT/examples/docker-compose.dev.yml"
CONFIG_FILE="$ROOT/examples/security-stream-gateway-config.toml"
PROXY_LOG="${TMPDIR:-/tmp}/data-nexus-security-stream.log"
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

echo "==> seed multi-row MySQL table"
"${COMPOSE[@]}" exec -T mysql-primary mysql -uroot -proot -e "
CREATE DATABASE IF NOT EXISTS orders;
USE orders;
DROP TABLE IF EXISTS stream_smoke;
CREATE TABLE stream_smoke (id INT PRIMARY KEY, name VARCHAR(32));
INSERT INTO stream_smoke VALUES (1,'a'),(2,'b'),(3,'c');
"

echo "==> seed multi-row PostgreSQL table"
"${COMPOSE[@]}" exec -T postgres-primary \
  psql -U postgres -d analytics -v ON_ERROR_STOP=1 -c \
  "DROP TABLE IF EXISTS stream_smoke;
   CREATE TABLE stream_smoke (id INT PRIMARY KEY, name TEXT);
   INSERT INTO stream_smoke VALUES (1,'a'),(2,'b'),(3,'c');"

echo "==> start gateway (max_rows=1, window_rows=2, MySQL+PG)"
PROXY_BIN="${CARGO_TARGET_DIR}/debug/proxy"
(
  cd "$ROOT"
  if [[ ! -x "$PROXY_BIN" ]] \
    || [[ "$ROOT/runtime/gateway/src/backend/mysql.rs" -nt "$PROXY_BIN" ]] \
    || [[ "$ROOT/runtime/gateway/src/backend/postgresql.rs" -nt "$PROXY_BIN" ]] \
    || [[ "$ROOT/runtime/gateway/src/frontend/postgresql.rs" -nt "$PROXY_BIN" ]] \
    || [[ "$ROOT/runtime/gateway/src/frontend/mysql.rs" -nt "$PROXY_BIN" ]] \
    || [[ "$ROOT/gateway/core/src/model.rs" -nt "$PROXY_BIN" ]]; then
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
  # PG frontend currently accepts startup without password check; use postgres/postgres
  # like dual-listener smoke (backend endpoint credentials).
  docker run --rm --add-host=host.docker.internal:host-gateway postgres:16-alpine \
    env PGPASSWORD=postgres \
    psql -h host.docker.internal -p 9089 -U postgres -d analytics -tAc "$1"
}

echo "==> MySQL SELECT * should return only 1 row (max_rows=1)"
out="$(mysql_via_gateway 'SELECT id, name FROM stream_smoke ORDER BY id;')"
echo "$out"
lines="$(echo "$out" | sed '/^$/d' | wc -l | tr -d ' ')"
[[ "$lines" == "1" ]] || { echo "mysql: expected 1 row, got $lines: $out" >&2; exit 1; }
echo "$out" | grep -qE $'1[[:space:]]+a'

echo "==> PostgreSQL SELECT * should return only 1 row (max_rows=1, A06 path)"
out_pg="$(psql_via_gateway 'SELECT id, name FROM stream_smoke ORDER BY id;')"
echo "$out_pg"
lines_pg="$(echo "$out_pg" | sed '/^$/d' | wc -l | tr -d ' ')"
[[ "$lines_pg" == "1" ]] || { echo "pg: expected 1 row, got $lines_pg: $out_pg" >&2; exit 1; }
echo "$out_pg" | grep -qE '1.*a'

echo "==> MySQL in-transaction Streaming still applies max_rows (A06 txn lease)"
# Producer must return txn_lease after stream drain so COMMIT succeeds.
out_txn="$(mysql_via_gateway 'BEGIN; SELECT id, name FROM stream_smoke ORDER BY id; COMMIT;')"
echo "$out_txn"
# Expect a single data row (max_rows=1); COMMIT may print empty / status lines.
data_lines="$(echo "$out_txn" | sed '/^$/d' | grep -E $'^[0-9]+[[:space:]]' | wc -l | tr -d ' ')"
[[ "$data_lines" == "1" ]] || {
  echo "mysql txn: expected 1 data row under max_rows=1, got $data_lines: $out_txn" >&2
  exit 1
}
echo "$out_txn" | grep -qE $'1[[:space:]]+a'

echo "==> MySQL post-txn query still works (lease returned)"
out_after="$(mysql_via_gateway 'SELECT id FROM stream_smoke WHERE id=1;')"
echo "$out_after"
echo "$out_after" | grep -qE '^1$'

echo "==> PostgreSQL in-transaction Streaming still applies max_rows (A06 txn lease)"
# Use a multi-line script on one connection so BEGIN..SELECT..COMMIT share the session.
# -tAc on multi-statement only surfaces the last command (COMMIT); use unaligned text.
out_pg_txn="$(docker run --rm -i --add-host=host.docker.internal:host-gateway postgres:16-alpine \
  env PGPASSWORD=postgres \
  psql -h host.docker.internal -p 9089 -U postgres -d analytics -v ON_ERROR_STOP=1 -A -t <<'SQL'
BEGIN;
SELECT id || '|' || name FROM stream_smoke ORDER BY id;
COMMIT;
SQL
)"
echo "$out_pg_txn"
# Data rows look like "1|a"; BEGIN/COMMIT may print empty lines or "BEGIN"/"COMMIT" depending on -t.
pg_txn_data="$(echo "$out_pg_txn" | sed '/^$/d' | grep -E '^[0-9]+\|' || true)"
pg_txn_lines="$(echo "$pg_txn_data" | sed '/^$/d' | wc -l | tr -d ' ')"
[[ "$pg_txn_lines" == "1" ]] || {
  echo "pg txn: expected 1 data row under max_rows=1, got $pg_txn_lines: $out_pg_txn" >&2
  exit 1
}
echo "$pg_txn_data" | grep -qE '1\|a'

echo "==> A10 MySQL COM_STMT_PREPARE/EXECUTE max_rows=1 (binary prepared)"
# mysql-connector prepared=True uses COM_STMT_* (not text rewrite).
# Install drivers inside a throwaway Python image so host packages are not required.
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
        "SELECT id, name FROM stream_smoke WHERE id > %s ORDER BY id",
        (0,),
    )
    rows = cur.fetchall()
    print("mysql_prepared_rows", len(rows), rows)
    assert len(rows) == 1, rows
    assert int(rows[0][0]) == 1, rows
    cur.close()
finally:
    cnx.close()
print("mysql_prepared_ok")
PY
')"
echo "$mysql_prep_out"
echo "$mysql_prep_out" | grep -q 'mysql_prepared_ok'

echo "==> A10 PostgreSQL Bind/Execute (QueryParams) max_rows=1"
# Extended protocol with Describe: explicit SELECT list → RowDescription (not NoData).
# After Describe('P'), Execute must not re-send RowDescription.
pg_prep_out="$(docker run --rm -i --add-host=host.docker.internal:host-gateway python:3.12-slim-bookworm \
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
# startup
params = cstr("user") + cstr("postgres") + cstr("database") + cstr("analytics") + b"\x00"
startup = i32(8 + len(params)) + i32(196608) + params
sock.sendall(startup)
# read until ReadyForQuery
while True:
    tag, body = read_msg(sock)
    if tag == b"Z":
        break
    if tag == b"E":
        raise RuntimeError(body)

sql = "SELECT id, name FROM stream_smoke WHERE id > $1 ORDER BY id"
# Parse unnamed statement
sock.sendall(msg(b"P", cstr("") + cstr(sql) + i16(0)))
# Describe statement (expect ParameterDescription + RowDescription)
sock.sendall(msg(b"D", b"S" + cstr("")))
# Bind: portal "", stmt "", 0 param formats, 1 text param "0", 0 result formats
bind = cstr("") + cstr("") + i16(0) + i16(1) + i32(1) + b"0" + i16(0)
sock.sendall(msg(b"B", bind))
# Describe portal (expect RowDescription only)
sock.sendall(msg(b"D", b"P" + cstr("")))
# Execute portal "", max_rows=0 (all)
sock.sendall(msg(b"E", cstr("") + i32(0)))
# Sync
sock.sendall(msg(b"S", b""))

rows = 0
rowdesc_count = 0
paramdesc = 0
nodata = 0
while True:
    tag, body = read_msg(sock)
    if tag == b"1":  # ParseComplete
        continue
    if tag == b"2":  # BindComplete
        continue
    if tag == b"t":  # ParameterDescription
        paramdesc += 1
        continue
    if tag == b"n":  # NoData
        nodata += 1
        continue
    if tag == b"T":
        rowdesc_count += 1
        continue
    if tag == b"D":
        rows += 1
        continue
    if tag == b"C":  # CommandComplete
        continue
    if tag == b"Z":
        break
    if tag == b"E":
        raise RuntimeError(body.decode("utf-8", "replace"))

print(
    "pg_prepared_rows", rows,
    "rowdesc", rowdesc_count,
    "paramdesc", paramdesc,
    "nodata", nodata,
)
assert paramdesc >= 1, "expected ParameterDescription from Describe(S)"
assert nodata == 0, "explicit SELECT list must not return NoData"
# Describe(S) + Describe(P) each send RowDescription; Execute suppresses third T.
assert rowdesc_count == 2, f"expected 2 RowDescription (S+P), got {rowdesc_count}"
assert rows == 1, f"expected max_rows=1, got {rows}"
print("pg_prepared_ok")
sock.close()
PY
)"
echo "$pg_prep_out"
echo "$pg_prep_out" | grep -q 'pg_prepared_ok'

echo "==> A10 PostgreSQL Describe SELECT * uses catalog RowDescription"
# Wildcard cannot be inferred from SQL text; backend prepare must supply columns.
pg_star_out="$(docker run --rm -i --add-host=host.docker.internal:host-gateway python:3.12-slim-bookworm \
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

sql = "SELECT * FROM stream_smoke ORDER BY id"
sock.sendall(msg(b"P", cstr("sstar") + cstr(sql) + i16(0)))
sock.sendall(msg(b"D", b"S" + cstr("sstar")))
sock.sendall(msg(b"S", b""))

paramdesc = 0
rowdesc = 0
nodata = 0
ncols = None
while True:
    tag, body = read_msg(sock)
    if tag == b"1":
        continue
    if tag == b"t":
        paramdesc += 1
        continue
    if tag == b"n":
        nodata += 1
        continue
    if tag == b"T":
        rowdesc += 1
        ncols = struct.unpack("!h", body[0:2])[0]
        continue
    if tag == b"E":
        raise RuntimeError(body.decode("utf-8", "replace"))
    if tag == b"Z":
        break

print("pg_star_describe", "paramdesc", paramdesc, "rowdesc", rowdesc, "nodata", nodata, "ncols", ncols)
assert paramdesc >= 1, "expected ParameterDescription"
assert nodata == 0, "SELECT * must not return NoData when catalog prepare works"
assert rowdesc == 1, rowdesc
assert ncols == 2, f"stream_smoke has 2 columns, got {ncols}"
print("pg_star_describe_ok")
sock.close()
PY
)"
echo "$pg_star_out"
echo "$pg_star_out" | grep -q 'pg_star_describe_ok'

echo "==> A10 PostgreSQL psycopg3 prepared max_rows=1 (Describe + RowDescription)"
# Full client path: requires Describe → RowDescription (not NoData).
# Integer binds may arrive as binary INT2 even under text format codes.
# Same-connection re-execute (psycopg prepare reuse) must work after Sync.
pg_psycopg_out="$(docker run --rm --add-host=host.docker.internal:host-gateway python:3.12-slim-bookworm \
  bash -lc 'pip install -q --disable-pip-version-check "psycopg[binary]>=3.1" >/tmp/pip.log 2>&1 || { cat /tmp/pip.log; exit 1; }
python - <<"PY"
import psycopg
with psycopg.connect(
    "host=host.docker.internal port=9089 user=postgres password=postgres dbname=analytics",
    autocommit=True,
) as conn:
    with conn.cursor() as cur:
        # int param (may be binary INT2 on the wire)
        cur.execute(
            "SELECT id, name FROM stream_smoke WHERE id > %s ORDER BY id",
            (0,),
        )
        rows = cur.fetchall()
        print("psycopg_rows", len(rows), rows)
        assert len(rows) == 1, rows
        assert int(rows[0][0]) == 1, rows
        # same connection, same prepared SQL — second Bind/Execute after Sync
        cur.execute(
            "SELECT id, name FROM stream_smoke WHERE id > %s ORDER BY id",
            (0,),
        )
        rows_re = cur.fetchall()
        print("psycopg_rebind_rows", len(rows_re), rows_re)
        assert len(rows_re) == 1, rows_re
        assert int(rows_re[0][0]) == 1, rows_re
# separate connection for text param
with psycopg.connect(
    "host=host.docker.internal port=9089 user=postgres password=postgres dbname=analytics",
    autocommit=True,
) as conn:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, name FROM stream_smoke WHERE id > %s ORDER BY id",
            ("0",),
        )
        rows2 = cur.fetchall()
        assert len(rows2) == 1, rows2
# SELECT * catalog describe + execute (max_rows=1 → 1 row)
with psycopg.connect(
    "host=host.docker.internal port=9089 user=postgres password=postgres dbname=analytics",
    autocommit=True,
) as conn:
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM stream_smoke ORDER BY id")
        star = cur.fetchall()
        print("psycopg_star_rows", len(star), star)
        assert len(star) == 1, star
print("psycopg_prepared_ok")
PY
')"
echo "$pg_psycopg_out"
echo "$pg_psycopg_out" | grep -q 'psycopg_prepared_ok'
echo "$pg_psycopg_out" | grep -q 'psycopg_rebind_rows'

echo "==> metrics execute_path present after traffic"
metrics="$(curl -fsS http://127.0.0.1:8082/metrics || true)"
if echo "$metrics" | grep -q 'gateway_execute_path_total'; then
  echo "$metrics" | grep 'gateway_execute_path_total' | head -8 || true
  # max_rows obligation forces Streaming (not wire passthrough), including A10 prepared.
  # A06: multi-row SELECT with max_rows must observe execute_path=streaming.
  if echo "$metrics" | grep -q 'execute_path="streaming"'; then
    echo "streaming path counter observed"
  else
    echo "FAIL: expected execute_path=streaming after max_rows Streaming traffic" >&2
    echo "$metrics" | grep 'gateway_execute_path_total' || true
    exit 1
  fi
else
  echo "note: gateway_execute_path_total metric missing; continuing"
fi

echo "smoke-security-stream: OK"
