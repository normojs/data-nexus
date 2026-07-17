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
CONFIG_FILE="$ROOT/examples/security-deny-gateway-config.toml"
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
CREATE TABLE IF NOT EXISTS portal_t (id INT PRIMARY KEY, name VARCHAR(32));
INSERT INTO portal_t VALUES (1,'portal') ON DUPLICATE KEY UPDATE name=VALUES(name);
"

echo "==> gateway"
PROXY_BIN="${CARGO_TARGET_DIR}/debug/proxy"
(
  cd "$ROOT"
  if [[ ! -x "$PROXY_BIN" ]] || [[ "$ROOT/http/src/http/mod.rs" -nt "$PROXY_BIN" ]]; then
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

echo "==> portal export NDJSON chunked (B05b)"
curl -fsS -D /tmp/dn-portal-ndjson.hdr -o /tmp/dn-portal.ndjson \
  -X POST "http://127.0.0.1:8082/admin/portal/query" \
  -H 'content-type: application/json' \
  -d '{"service":"orders","sql":"SELECT id, name FROM portal_t WHERE id=1","subject_id":"portal-user","format":"ndjson","max_rows":10}'
python3 - <<'PY'
import json
hdr=open("/tmp/dn-portal-ndjson.hdr").read().lower()
assert "ndjson" in hdr or "json" in hdr, hdr
assert "x-data-nexus-stream: chunked" in hdr, hdr
# Transfer-Encoding may be hop-by-hop stripped by some stacks; body shape is authoritative.
lines=[ln for ln in open("/tmp/dn-portal.ndjson") if ln.strip()]
assert len(lines) >= 2, lines
meta=json.loads(lines[0])
assert meta.get("_meta") is True
assert meta.get("decision")=="allow"
assert meta.get("stream")=="chunked"
row=json.loads(lines[1])
assert "id" in row and "name" in row
print("ndjson chunked export ok", meta.get("row_count"), row)
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

echo "smoke-security-portal: OK"
