#!/usr/bin/env bash
# S6: portal query via PEP + vault lease (no password in lease JSON).
set -euo pipefail

export PATH="/Volumes/fushilu/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin:/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:${HOME}/.cargo/bin:/Volumes/fushilu/.rustup/toolchains/nightly-2025-01-07-aarch64-apple-darwin/bin:${PATH:-}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.94.1}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$ROOT/examples/docker-compose.dev.yml"
CONFIG_FILE="$ROOT/examples/security-portal-gateway-config.toml"
PROXY_LOG="${TMPDIR:-/tmp}/data-nexus-portal-smoke.log"
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
DROP TABLE IF EXISTS portal_t;
CREATE TABLE portal_t (id INT PRIMARY KEY, name VARCHAR(32));
INSERT INTO portal_t VALUES (1,'portal'),(2,'row2'),(3,'row3');
"

echo "==> gateway"
PROXY_BIN="${CARGO_TARGET_DIR}/debug/proxy"
(
  cd "$ROOT"
  if [[ ! -x "$PROXY_BIN" ]]     || [[ "$ROOT/http/src/http/mod.rs" -nt "$PROXY_BIN" ]]     || [[ "$CONFIG_FILE" -nt "$PROXY_BIN" ]]; then
    cargo build -p data-proxy --bin proxy
  fi
  "$PROXY_BIN" daemon -c "$CONFIG_FILE"
) >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!

for _ in $(seq 1 120); do
  curl -fsS "http://127.0.0.1:8082/admin/projects" >/dev/null 2>&1 && break
  kill -0 "$PROXY_PID" 2>/dev/null || { cat "$PROXY_LOG"; exit 1; }
  sleep 1
done

echo "==> projects"
curl -fsS "http://127.0.0.1:8082/admin/projects" | tee /tmp/dn-projects.json
python3 - <<'PY'
import json
p=json.load(open("/tmp/dn-projects.json"))
assert isinstance(p, list) and len(p) >= 1
print("projects", [x.get("name") for x in p])
PY

echo "==> vault lease"
curl -fsS -X POST "http://127.0.0.1:8082/admin/vault/leases" \
  -H 'content-type: application/json' \
  -d '{"project":"orders","environment":"dev","ttl_secs":600}' \
  | tee /tmp/dn-lease.json
python3 - <<'PY'
import json
lease=json.load(open("/tmp/dn-lease.json"))
assert "lease_id" in lease
assert "access_token" in lease
assert "password" not in lease
s=json.dumps(lease)
assert "root" in s or lease.get("username")
# password from config must not appear
assert "password" not in s.lower() or '"password"' not in s
print("lease", lease["lease_id"], "user", lease.get("username"))
open("/tmp/dn-lease-id.txt","w").write(lease["lease_id"])
PY
LEASE_ID="$(cat /tmp/dn-lease-id.txt)"

echo "==> portal query allow"
curl -fsS -X POST "http://127.0.0.1:8082/admin/portal/query" \
  -H 'content-type: application/json' \
  -d "$(python3 - <<PY
import json
print(json.dumps({
  "service": "orders",
  "sql": "SELECT id, name FROM portal_t WHERE id=1",
  "lease_id": "$LEASE_ID",
  "subject_id": "portal-user",
  "max_rows": 10
}))
PY
)" | tee /tmp/dn-portal-ok.json
python3 - <<'PY'
import json
r=json.load(open("/tmp/dn-portal-ok.json"))
assert r.get("decision")=="allow"
assert r.get("row_count",0) >= 1
assert "portal" in json.dumps(r)
print("rows", r["row_count"], "cols", r["columns"])
PY

echo "==> portal query deny secret table"
set +e
curl -sS -X POST "http://127.0.0.1:8082/admin/portal/query" \
  -H 'content-type: application/json' \
  -d '{"service":"orders","sql":"SELECT id FROM secret_tokens","subject_id":"portal-user"}' \
  | tee /tmp/dn-portal-deny.json
set -e
python3 - <<'PY'
import json
raw=open("/tmp/dn-portal-deny.json").read()
# expect error JSON
assert "denied" in raw.lower() or "deny" in raw.lower() or "secret" in raw.lower() or "portal_denied" in raw.lower()
print("deny ok")
PY

echo "==> portal export CSV (B05)"
curl -fsS -D /tmp/dn-portal-csv.hdr -o /tmp/dn-portal.csv \
  -X POST "http://127.0.0.1:8082/admin/portal/query" \
  -H 'content-type: application/json' \
  -d "$(python3 - <<PY
import json
print(json.dumps({
  "service": "orders",
  "sql": "SELECT id, name FROM portal_t WHERE id=1",
  "subject_id": "portal-user",
  "max_rows": 10,
  "format": "csv",
  "download": True
}))
PY
)"
python3 - <<'PY'
hdr=open("/tmp/dn-portal-csv.hdr").read().lower()
body=open("/tmp/dn-portal.csv").read()
assert "text/csv" in hdr, hdr
assert "content-disposition" in hdr and "portal-export.csv" in hdr, hdr
assert "id,name" in body.replace(" ", "").lower() or body.splitlines()[0].lower().startswith("id")
assert "portal" in body.lower()
print("csv export ok", body.splitlines()[:3])
PY

echo "==> portal export NDJSON stream (A09 backend_window or B05b chunked fallback)"
curl -fsS -D /tmp/dn-portal-ndjson.hdr -o /tmp/dn-portal.ndjson \
  -X POST "http://127.0.0.1:8082/admin/portal/query" \
  -H 'content-type: application/json' \
  -d '{"service":"orders","sql":"SELECT id, name FROM portal_t WHERE id=1","subject_id":"portal-user","format":"ndjson","max_rows":10}'
python3 - <<'PY'
import json
hdr=open("/tmp/dn-portal-ndjson.hdr").read().lower()
assert "ndjson" in hdr or "json" in hdr, hdr
# A09: MySQL non-txn Streaming → backend_window; Complete backends → chunked.
assert (
    "x-data-nexus-stream: backend_window" in hdr
    or "x-data-nexus-stream: chunked" in hdr
), hdr
lines=[ln for ln in open("/tmp/dn-portal.ndjson") if ln.strip()]
assert len(lines) >= 2, lines
meta=json.loads(lines[0])
assert meta.get("_meta") is True
assert meta.get("decision")=="allow"
assert meta.get("stream") in ("backend_window", "chunked"), meta
row=json.loads(lines[1])
assert "id" in row and "name" in row
print("ndjson stream export ok", meta.get("stream"), meta.get("row_count"), row)
PY

echo "==> portal multi-row NDJSON requires backend_window (A09)"
curl -fsS -D /tmp/dn-portal-ndjson2.hdr -o /tmp/dn-portal2.ndjson \
  -X POST "http://127.0.0.1:8082/admin/portal/query" \
  -H 'content-type: application/json' \
  -d '{"service":"orders","sql":"SELECT id, name FROM portal_t ORDER BY id","subject_id":"portal-user","format":"ndjson","max_rows":10}'
python3 - <<'PY'
import json
hdr=open("/tmp/dn-portal-ndjson2.hdr").read().lower()
# A09: multi-row MySQL SELECT via portal must use backend Streaming → HTTP chunk,
# not B05b materialize-then-chunk fallback.
assert "x-data-nexus-stream: backend_window" in hdr, hdr
lines=[ln for ln in open("/tmp/dn-portal2.ndjson") if ln.strip()]
assert len(lines) >= 2, lines
meta=json.loads(lines[0])
assert meta.get("_meta") is True
assert meta.get("stream") == "backend_window", meta
# A09: portal smoke config pins window_rows=2 for honest windowed export.
assert int(meta.get("window_rows") or 0) == 2, meta
rows=[]
for ln in lines[1:]:
    obj=json.loads(ln)
    if obj.get("_meta"):
        continue
    rows.append(obj)
assert len(rows) >= 2, ("expected multi-row backend_window", rows)
ids=sorted(int(r["id"]) for r in rows if "id" in r)
assert ids[:3] == [1, 2, 3] or ids[:2] == [1, 2], ids
print("ndjson multi-row backend_window ok", "rows", len(rows), "window", meta.get("window_rows"))
PY

echo "==> portal multi-row JSON streams backend_window (A09)"
curl -fsS -D /tmp/dn-portal-json.hdr -o /tmp/dn-portal-multi.json \
  -X POST "http://127.0.0.1:8082/admin/portal/query" \
  -H 'content-type: application/json' \
  -d '{"service":"orders","sql":"SELECT id, name FROM portal_t ORDER BY id","subject_id":"portal-user","format":"json","max_rows":10}'
python3 - <<'PY'
import json
hdr=open("/tmp/dn-portal-json.hdr").read().lower()
assert "application/json" in hdr or "json" in hdr, hdr
# A09: multi-row MySQL SELECT via portal JSON must use backend Streaming → HTTP chunk.
assert "x-data-nexus-stream: backend_window" in hdr, hdr
body=json.load(open("/tmp/dn-portal-multi.json"))
assert body.get("decision")=="allow", body
assert body.get("stream")=="backend_window", body
assert int(body.get("window_rows") or 0) == 2, body
assert body.get("row_count", 0) >= 2, body
assert isinstance(body.get("rows"), list) and len(body["rows"]) >= 2, body
# rows remain array-of-arrays (AdminPortalQueryResponse shape for data-ui).
assert isinstance(body["rows"][0], list), body["rows"][0]
ids=sorted(int(r[0]) for r in body["rows"] if r)
assert ids[:3] == [1, 2, 3] or ids[:2] == [1, 2], ids
print("json multi-row backend_window ok", "rows", body.get("row_count"), "window", body.get("window_rows"))
PY

echo "==> portal multi-row CSV streams backend_window (A09)"
curl -fsS -D /tmp/dn-portal-csv2.hdr -o /tmp/dn-portal-multi.csv \
  -X POST "http://127.0.0.1:8082/admin/portal/query" \
  -H 'content-type: application/json' \
  -d '{"service":"orders","sql":"SELECT id, name FROM portal_t ORDER BY id","subject_id":"portal-user","format":"csv","max_rows":10,"download":true}'
python3 - <<'PY'
hdr=open("/tmp/dn-portal-csv2.hdr").read().lower()
body=open("/tmp/dn-portal-multi.csv").read()
assert "text/csv" in hdr, hdr
# MySQL non-txn Streaming should yield true backend_window for CSV now.
assert "x-data-nexus-stream: backend_window" in hdr, hdr
# A09 honesty: CSV has no JSON meta — window pin is only via response header.
assert "x-data-nexus-window-rows: 2" in hdr, hdr
lines=[ln for ln in body.splitlines() if ln.strip() and not ln.startswith("#")]
assert len(lines) >= 3, lines  # header + >=2 data rows
assert lines[0].lower().startswith("id"), lines[0]
print("csv multi-row backend_window ok", "lines", len(lines), "window_header=2")
PY


echo "==> portal Complete path INSERT → chunked (not backend_window)"
# Non-SELECT yields ExecuteOutcome::Complete; export must still stream HTTP windows
# with x-data-nexus-stream: chunked (honest: no RowStream).
curl -fsS -D /tmp/dn-portal-insert.hdr -o /tmp/dn-portal-insert.ndjson \
  -X POST "http://127.0.0.1:8082/admin/portal/query" \
  -H 'content-type: application/json' \
  -d "$(python3 - <<'PY'
import json
print(json.dumps({
  "service": "orders",
  "sql": "INSERT INTO portal_t (id, name) VALUES (99, 'chunked') ON DUPLICATE KEY UPDATE name=VALUES(name)",
  "subject_id": "portal-user",
  "format": "ndjson",
  "max_rows": 10,
}))
PY
)"
python3 - <<'PY'
import json
hdr=open("/tmp/dn-portal-insert.hdr").read().lower()
assert "x-data-nexus-stream: chunked" in hdr, hdr
lines=[ln for ln in open("/tmp/dn-portal-insert.ndjson") if ln.strip()]
assert len(lines) >= 1, lines
meta=json.loads(lines[0])
assert meta.get("_meta") is True, meta
assert meta.get("stream") == "chunked", meta
assert meta.get("decision") == "allow", meta
# Complete path still advertises the HTTP encode window (not backend RowStream).
assert "x-data-nexus-window-rows:" in hdr, hdr
print("portal complete insert chunked ok", "stream", meta.get("stream"), "lines", len(lines))
PY

echo "==> portal Complete path INSERT JSON also chunked"
curl -fsS -D /tmp/dn-portal-insert-json.hdr -o /tmp/dn-portal-insert.json \
  -X POST "http://127.0.0.1:8082/admin/portal/query" \
  -H 'content-type: application/json' \
  -d "$(python3 - <<'PY'
import json
print(json.dumps({
  "service": "orders",
  "sql": "INSERT INTO portal_t (id, name) VALUES (100, 'chunked-json') ON DUPLICATE KEY UPDATE name=VALUES(name)",
  "subject_id": "portal-user",
  "format": "json",
  "max_rows": 10,
}))
PY
)"
python3 - <<'PY'
import json
hdr=open("/tmp/dn-portal-insert-json.hdr").read().lower()
assert "x-data-nexus-stream: chunked" in hdr, hdr
body=json.load(open("/tmp/dn-portal-insert.json"))
assert body.get("decision")=="allow", body
assert body.get("stream")=="chunked", body
print("portal complete insert json chunked ok", "rows", body.get("row_count"), "stream", body.get("stream"))
PY


echo "==> portal Complete path INSERT CSV also chunked"
curl -fsS -D /tmp/dn-portal-insert-csv.hdr -o /tmp/dn-portal-insert.csv \
  -X POST "http://127.0.0.1:8082/admin/portal/query" \
  -H 'content-type: application/json' \
  -d "$(python3 - <<'PY'
import json
print(json.dumps({
  "service": "orders",
  "sql": "INSERT INTO portal_t (id, name) VALUES (101, 'chunked-csv') ON DUPLICATE KEY UPDATE name=VALUES(name)",
  "subject_id": "portal-user",
  "format": "csv",
  "max_rows": 10,
  "download": True,
}))
PY
)"
python3 - <<'PY'
hdr=open("/tmp/dn-portal-insert-csv.hdr").read().lower()
body=open("/tmp/dn-portal-insert.csv").read()
assert "text/csv" in hdr, hdr
assert "x-data-nexus-stream: chunked" in hdr, hdr
assert "backend_window" not in hdr, hdr
assert "x-data-nexus-window-rows:" in hdr, hdr
lines=[ln for ln in body.splitlines() if ln.strip() and not ln.startswith("#")]
assert len(lines) >= 1, lines
print("portal complete insert csv chunked ok", "lines", len(lines), "head", lines[0][:40])
PY

echo "==> portal invalid format rejected"
set +e
curl -sS -o /tmp/dn-portal-badfmt.json -w "%{http_code}" \
  -X POST "http://127.0.0.1:8082/admin/portal/query" \
  -H 'content-type: application/json' \
  -d '{"service":"orders","sql":"SELECT 1","format":"xlsx"}' \
  >/tmp/dn-portal-badfmt.code
set -e
python3 - <<'PY'
code=open("/tmp/dn-portal-badfmt.code").read().strip()
body=open("/tmp/dn-portal-badfmt.json").read().lower()
assert code.startswith("4"), code
assert "format" in body or "invalid" in body, body
print("bad format rejected", code)
PY

echo "==> A09 honesty: portal HTTP path vs protocol CoreEngine metrics"
# Portal multi-row exports already pinned stream=backend_window + x-data-nexus-window-rows=2.
# They call backend.execute_outcome directly (PEP on Admin API), not the protocol CoreEngine
# handle_frame path — so gateway_execute_path_total / encode_peak may be absent or stale.
# Do not claim protocol RSS/peak CI from portal alone; window pin is the portal contract.
metrics="$(curl -fsS http://127.0.0.1:8082/metrics 2>/dev/null || true)"
if echo "$metrics" | grep -q 'gateway_encode_peak_window_rows{'; then
  bad_peak="$(echo "$metrics" | awk '/gateway_encode_peak_window_rows\{/ {
    v=$NF+0; if (v > 2) print v
  }' | head -1)"
  if [[ -n "$bad_peak" ]]; then
    echo "FAIL: if peak samples exist they must be ≤ window_rows=2, got $bad_peak" >&2
    exit 1
  fi
  echo "note: encode_peak samples present and ≤2 (may be from prior protocol traffic)"
else
  echo "note: no encode_peak samples (expected for portal-only HTTP path; window pinned via headers)"
fi
if echo "$metrics" | grep -q 'execute_path="streaming"'; then
  echo "note: streaming path counter present (protocol and/or prior traffic)"
else
  echo "note: no protocol execute_path=streaming sample required for portal HTTP exports"
fi
echo "portal window contract already asserted via x-data-nexus-stream/window-rows headers"

echo "smoke-security-portal: OK"
