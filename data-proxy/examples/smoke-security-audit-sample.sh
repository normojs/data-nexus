#!/usr/bin/env bash
# B08: L2 audit samples attach sample_body (bounded, post-mask path).
# Not full-result L3. Requires sample_enabled + default_audit_level=L2.
set -euo pipefail

export PATH="/Volumes/fushilu/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin:/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:${HOME}/.cargo/bin:${PATH:-}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.94.1}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$ROOT/examples/docker-compose.dev.yml"
CONFIG_FILE="$ROOT/examples/security-audit-sample-gateway-config.toml"
PROXY_LOG="${TMPDIR:-/tmp}/data-nexus-security-audit-sample.log"
AUDIT_FILE="/tmp/data-nexus-audit-sample-events.jsonl"
AUDIT_INDEX="/tmp/data-nexus-audit-sample-index.sqlite"
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
rm -f "$AUDIT_FILE" "$AUDIT_INDEX" "${AUDIT_INDEX}-wal" "${AUDIT_INDEX}-shm"

echo "==> start backends"
"${COMPOSE[@]}" up -d
for _ in $(seq 1 90); do
  "${COMPOSE[@]}" exec -T mysql-primary mysqladmin ping -h 127.0.0.1 -uroot -proot --silent 2>/dev/null && break
  sleep 2
done

echo "==> seed multi-row table for samples"
"${COMPOSE[@]}" exec -T mysql-primary mysql -uroot -proot -e "
CREATE DATABASE IF NOT EXISTS orders;
USE orders;
DROP TABLE IF EXISTS audit_sample_t;
CREATE TABLE audit_sample_t (id INT PRIMARY KEY, name VARCHAR(32));
INSERT INTO audit_sample_t VALUES (1,'a'),(2,'b'),(3,'c');
"

echo "==> start gateway (L2 + sample_enabled, max_rows=2)"
PROXY_BIN="${CARGO_TARGET_DIR}/debug/proxy"
(
  cd "$ROOT"
  if [[ ! -x "$PROXY_BIN" ]] \
    || [[ "$ROOT/gateway/core/src/security.rs" -nt "$PROXY_BIN" ]] \
    || [[ "$ROOT/gateway/core/src/audit.rs" -nt "$PROXY_BIN" ]] \
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

echo "==> generate multi-row SELECT traffic"
mysql_via_gateway 'SELECT id, name FROM audit_sample_t ORDER BY id;'

echo "==> wait for audit sample events"
for _ in $(seq 1 80); do
  if curl -fsS "http://127.0.0.1:8082/admin/audit/events?limit=50" 2>/dev/null \
    | python3 -c 'import sys,json; d=json.load(sys.stdin); ev=d.get("events") or []; raise SystemExit(0 if any(e.get("sample_body") or e.get("sample_row_count") for e in ev) else 1)'; then
    break
  fi
  sleep 0.15
done

echo "==> assert sample_body present and bounded"
curl -fsS "http://127.0.0.1:8082/admin/audit/events?limit=50" | tee /tmp/dn-audit-sample-events.json >/dev/null
python3 - <<'PY'
import json
data=json.load(open("/tmp/dn-audit-sample-events.json"))
ev=data.get("events") or []
samples=[e for e in ev if e.get("sample_body") or e.get("sample_row_count") is not None]
assert samples, f"expected at least one event with sample fields, got {len(ev)} events"
# Prefer an event with sample_body (inline=true)
body_ev=None
for e in samples:
    if e.get("sample_body"):
        body_ev=e
        break
assert body_ev is not None, samples[0]
body=body_ev["sample_body"]
# sample_body may be a JSON string
payload=json.loads(body) if isinstance(body, str) else body
assert "columns" in payload and "rows" in payload, payload
rows=payload["rows"]
# sample_max_rows=2 in config — must not dump all 3 as "full result"
assert len(rows) <= 2, f"sample must be bounded to max_rows=2, got {len(rows)}"
assert body_ev.get("sample_row_count") in (None, len(rows), 1, 2) or int(body_ev.get("sample_row_count") or 0) <= 2
# Must not look like full-table dump of 3 rows without truncated flag when more existed
if len(rows) < 3:
    # truncated may be true when more backend rows existed
    pass
print(
    "b08 sample ok",
    "rows", len(rows),
    "sample_row_count", body_ev.get("sample_row_count"),
    "truncated", payload.get("truncated"),
    "sample_truncated", body_ev.get("sample_truncated"),
)
# Sanity: no multi-MB body
assert len(json.dumps(body_ev)) < 100_000
PY

echo "smoke-security-audit-sample: OK"
