#!/usr/bin/env bash
# A09: portal multi-row export over reverse cross-protocol
# (PostgreSQL SQL surface → MySQL backend) must stream backend_window.
set -euo pipefail

export PATH="/Volumes/fushilu/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin:/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:${HOME}/.cargo/bin:${PATH:-}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.94.1}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$ROOT/examples/docker-compose.dev.yml"
CONFIG_FILE="$ROOT/examples/security-portal-xproto-pg-mysql-gateway-config.toml"
PROXY_LOG="${TMPDIR:-/tmp}/data-nexus-portal-xproto-pg-mysql-smoke.log"
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
for port in 8085 9092; do
  if command -v lsof >/dev/null 2>&1; then
    pids="$(lsof -tiTCP:$port -sTCP:LISTEN 2>/dev/null || true)"
    if [[ -n "$pids" ]]; then
      # shellcheck disable=SC2086
      kill $pids 2>/dev/null || true
    fi
  fi
done
sleep 1

echo "==> backends"
"${COMPOSE[@]}" up -d
for _ in $(seq 1 90); do
  "${COMPOSE[@]}" exec -T mysql-primary mysqladmin ping -h 127.0.0.1 -uroot -proot --silent 2>/dev/null && break
  sleep 2
done

echo "==> seed multi-row MySQL table for portal xproto reverse"
"${COMPOSE[@]}" exec -T mysql-primary mysql -uroot -proot -e "
CREATE DATABASE IF NOT EXISTS orders;
USE orders;
DROP TABLE IF EXISTS portal_xproto_rev;
CREATE TABLE portal_xproto_rev (id INT PRIMARY KEY, name VARCHAR(32));
INSERT INTO portal_xproto_rev VALUES (1,'a'),(2,'b'),(3,'c');
"

echo "==> gateway (portal xproto reverse PG→MySQL, window_rows=2)"
PROXY_BIN="${CARGO_TARGET_DIR}/debug/proxy"
(
  cd "$ROOT"
  if [[ ! -x "$PROXY_BIN" ]] \
    || [[ "$ROOT/http/src/http/mod.rs" -nt "$PROXY_BIN" ]] \
    || [[ "$ROOT/gateway/core/src/translation.rs" -nt "$PROXY_BIN" ]] \
    || [[ "$ROOT/runtime/gateway/src/backend/mysql.rs" -nt "$PROXY_BIN" ]]; then
    cargo build -p data-proxy --bin proxy
  fi
  "$PROXY_BIN" daemon -c "$CONFIG_FILE"
) >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!

for _ in $(seq 1 120); do
  curl -fsS "http://127.0.0.1:8085/healthz" >/dev/null 2>&1 && break
  kill -0 "$PROXY_PID" 2>/dev/null || { cat "$PROXY_LOG"; exit 1; }
  sleep 1
done
curl -fsS "http://127.0.0.1:8085/healthz" >/dev/null

echo "==> portal reverse xproto NDJSON multi-row backend_window"
curl -fsS -D /tmp/dn-portal-xproto-rev-ndjson.hdr -o /tmp/dn-portal-xproto-rev.ndjson \
  -X POST "http://127.0.0.1:8085/admin/portal/query" \
  -H 'content-type: application/json' \
  -d "$(python3 - <<'PY'
import json
print(json.dumps({
  "service": "orders-via-pg",
  "sql": 'SELECT id, name FROM portal_xproto_rev ORDER BY id',
  "subject_id": "portal-xproto-rev",
  "format": "ndjson",
  "max_rows": 10,
}))
PY
)"
python3 - <<'PY'
import json
hdr=open("/tmp/dn-portal-xproto-rev-ndjson.hdr").read().lower()
assert "x-data-nexus-stream: backend_window" in hdr, hdr
lines=[ln for ln in open("/tmp/dn-portal-xproto-rev.ndjson") if ln.strip()]
assert len(lines) >= 2, lines
meta=json.loads(lines[0])
assert meta.get("_meta") is True
assert meta.get("stream") == "backend_window", meta
assert meta.get("service") == "orders-via-pg", meta
assert int(meta.get("window_rows") or 0) >= 1, meta
rows=[]
for ln in lines[1:]:
    obj=json.loads(ln)
    if obj.get("_meta"):
        continue
    rows.append(obj)
assert len(rows) >= 2, rows
ids=sorted(int(r["id"]) for r in rows if "id" in r)
assert ids[:3] == [1, 2, 3] or ids[:2] == [1, 2], ids
print("portal reverse xproto ndjson backend_window ok", "rows", len(rows), "window", meta.get("window_rows"))
PY

echo "==> portal reverse xproto JSON multi-row backend_window"
curl -fsS -D /tmp/dn-portal-xproto-rev-json.hdr -o /tmp/dn-portal-xproto-rev.json \
  -X POST "http://127.0.0.1:8085/admin/portal/query" \
  -H 'content-type: application/json' \
  -d "$(python3 - <<'PY'
import json
print(json.dumps({
  "service": "orders-via-pg",
  "sql": 'SELECT id, name FROM portal_xproto_rev ORDER BY id',
  "subject_id": "portal-xproto-rev",
  "format": "json",
  "max_rows": 10,
}))
PY
)"
python3 - <<'PY'
import json
hdr=open("/tmp/dn-portal-xproto-rev-json.hdr").read().lower()
assert "x-data-nexus-stream: backend_window" in hdr, hdr
body=json.load(open("/tmp/dn-portal-xproto-rev.json"))
assert body.get("decision")=="allow", body
assert body.get("stream")=="backend_window", body
assert body.get("row_count", 0) >= 2, body
assert isinstance(body.get("rows"), list) and len(body["rows"]) >= 2, body
print("portal reverse xproto json backend_window ok", "rows", body.get("row_count"), "window", body.get("window_rows"))
PY

echo "==> portal reverse xproto CSV multi-row backend_window"
curl -fsS -D /tmp/dn-portal-xproto-rev-csv.hdr -o /tmp/dn-portal-xproto-rev.csv \
  -X POST "http://127.0.0.1:8085/admin/portal/query" \
  -H 'content-type: application/json' \
  -d "$(python3 - <<'PY'
import json
print(json.dumps({
  "service": "orders-via-pg",
  "sql": 'SELECT id, name FROM portal_xproto_rev ORDER BY id',
  "subject_id": "portal-xproto-rev",
  "format": "csv",
  "max_rows": 10,
  "download": True,
}))
PY
)"
python3 - <<'PY'
hdr=open("/tmp/dn-portal-xproto-rev-csv.hdr").read().lower()
body=open("/tmp/dn-portal-xproto-rev.csv").read()
assert "text/csv" in hdr, hdr
assert "x-data-nexus-stream: backend_window" in hdr, hdr
lines=[ln for ln in body.splitlines() if ln.strip() and not ln.startswith("#")]
assert len(lines) >= 3, lines
print("portal reverse xproto csv backend_window ok", "lines", len(lines))
PY

echo "==> portal reverse xproto PG dialect rewrite (COALESCE) still streams"
curl -fsS -D /tmp/dn-portal-xproto-rev-coalesce.hdr -o /tmp/dn-portal-xproto-rev-coalesce.ndjson \
  -X POST "http://127.0.0.1:8085/admin/portal/query" \
  -H 'content-type: application/json' \
  -d "$(python3 - <<'PY'
import json
print(json.dumps({
  "service": "orders-via-pg",
  "sql": "SELECT id, COALESCE(name, '') AS name FROM portal_xproto_rev WHERE id=1",
  "subject_id": "portal-xproto-rev",
  "format": "ndjson",
  "max_rows": 5,
}))
PY
)"
python3 - <<'PY'
import json
hdr=open("/tmp/dn-portal-xproto-rev-coalesce.hdr").read().lower()
assert (
    "x-data-nexus-stream: backend_window" in hdr
    or "x-data-nexus-stream: chunked" in hdr
), hdr
lines=[ln for ln in open("/tmp/dn-portal-xproto-rev-coalesce.ndjson") if ln.strip()]
assert len(lines) >= 2, lines
row=json.loads(lines[1])
assert str(row.get("id")) in ("1",) or row.get("id") == 1, row
assert str(row.get("name")) == "a", row
print("portal reverse xproto coalesce rewrite ok", row)
PY

echo "==> portal reverse xproto DDL rejected by translation"
set +e
curl -sS -o /tmp/dn-portal-xproto-rev-ddl.json -w "%{http_code}" \
  -X POST "http://127.0.0.1:8085/admin/portal/query" \
  -H 'content-type: application/json' \
  -d "$(python3 - <<'PY'
import json
print(json.dumps({
  "service": "orders-via-pg",
  "sql": "DROP TABLE portal_xproto_rev",
  "subject_id": "portal-xproto-rev",
}))
PY
)" >/tmp/dn-portal-xproto-rev-ddl.code
set -e
python3 - <<'PY'
code=open("/tmp/dn-portal-xproto-rev-ddl.code").read().strip()
body=open("/tmp/dn-portal-xproto-rev-ddl.json").read().lower()
assert code.startswith("4") or "error" in body or "denied" in body or "not supported" in body or "translation" in body or "ddl" in body, (code, body)
print("portal reverse xproto ddl rejected", code)
PY

echo "smoke-security-portal-xproto-pg-mysql: OK"
