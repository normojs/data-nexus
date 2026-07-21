#!/usr/bin/env bash
# S4: audit pipeline + GET /admin/audit/events smoke.
set -euo pipefail

export PATH="/Volumes/fushilu/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin:/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:${HOME}/.cargo/bin:/Volumes/fushilu/.rustup/toolchains/nightly-2025-01-07-aarch64-apple-darwin/bin:${PATH:-}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.94.1}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$ROOT/examples/docker-compose.dev.yml"
CONFIG_FILE="$ROOT/examples/security-deny-gateway-config.toml"
PROXY_LOG="${TMPDIR:-/tmp}/data-nexus-security-audit.log"
AUDIT_FILE="/tmp/data-nexus-audit-events.jsonl"
AUDIT_INDEX="/tmp/data-nexus-audit-index.sqlite"
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

echo "==> start gateway"
PROXY_BIN="${CARGO_TARGET_DIR}/debug/proxy"
(
  cd "$ROOT"
  if [[ ! -x "$PROXY_BIN" ]] \
    || [[ "$ROOT/gateway/core/src/audit_pipeline.rs" -nt "$PROXY_BIN" ]] \
    || [[ "$ROOT/gateway/core/src/audit_index.rs" -nt "$PROXY_BIN" ]] \
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
  docker run --rm --add-host=host.docker.internal:host-gateway mysql:8.0 \
    mysql --ssl-mode=DISABLED -h host.docker.internal -P 9088 -uroot -proot -N -e "$1" || true
}

echo "==> generate allow + deny traffic"
mysql_via_gateway 'SELECT 1;'
mysql_via_gateway 'SELECT id FROM secret_tokens;'

echo "==> wait for audit worker + index"
for _ in $(seq 1 50); do
  if curl -fsS "http://127.0.0.1:8082/admin/audit/stats" 2>/dev/null \
    | python3 -c 'import sys,json; s=json.load(sys.stdin); raise SystemExit(0 if s.get("index_inserted",0)>=1 and s.get("accepted",0)>=1 else 1)'; then
    break
  fi
  sleep 0.1
done

echo "==> security-policies exposes B07 audit_queue + UI18 pdp"
curl -fsS "http://127.0.0.1:8082/admin/security-policies" | tee /tmp/dn-audit-policies.json >/dev/null
python3 - <<'PY'
import json
data=json.load(open("/tmp/dn-audit-policies.json"))
q=data.get("audit_queue") or {}
assert int(q.get("queue_capacity") or 0) >= 1, q
assert int(q.get("priority_queue_capacity") or 0) >= 1, q
assert q.get("overflow"), q
assert isinstance(q.get("sinks"), list) and q["sinks"], q
pdp=data.get("pdp") or {}
assert pdp.get("backend") in ("local","cedar","remote"), pdp
assert "remote_configured" in pdp and "remote_fail_closed" in pdp, pdp
assert "remote_url" not in pdp and "remote_token" not in pdp, pdp
print("policies audit_queue", q, "pdp", pdp)
PY

echo "==> GET /admin/audit/stats"
curl -fsS "http://127.0.0.1:8082/admin/audit/stats" | tee /tmp/dn-audit-stats.json
python3 - <<'PY'
import json
s=json.load(open("/tmp/dn-audit-stats.json"))
assert s.get("accepted",0) >= 1, s
# B04 fields present (defaults 0 when no rotate yet)
assert "rotated" in s, s
assert "pruned" in s, s
# B06 index stats
assert s.get("index_enabled") is True, s
assert s.get("index_inserted", 0) >= 1, s
assert "index_rows" in s and "index_errors" in s, s
# B07: deny traffic must hit priority queue (priority_queue_capacity>0 in deny config)
assert int(s.get("priority_queue_capacity") or 0) > 0, s
assert int(s.get("priority_accepted") or 0) >= 1, (
    f"B07 expected priority_accepted>=1 after deny, got {s.get('priority_accepted')}"
)
print("stats ok", s)
print("B07 priority_accepted", s.get("priority_accepted"), "cap", s.get("priority_queue_capacity"))
PY

echo "==> GET /admin/audit/events?decision=deny"
curl -fsS "http://127.0.0.1:8082/admin/audit/events?decision=deny&limit=20" | tee /tmp/dn-audit-events.json
python3 - <<'PY'
import json
data=json.load(open("/tmp/dn-audit-events.json"))
ev=data.get("events") or []
assert any((e.get("decision")=="deny") for e in ev), data
assert any((e.get("outcome")=="security_deny" or e.get("code")=="security_deny") for e in ev), data
assert data.get("source") == "index", data
print("deny events:", len(ev), "source=", data.get("source"))
# F32: L0 must not keep sql_text on events (deny config default_audit_level=L0).
for e in ev:
    assert not e.get("sql_text"), f"L0 must strip sql_text, got {e.get('sql_text')!r} on {e.get('event_id')}"
print("F32 L0 strips sql_text ok")
# B06 event_id round-trip via index
eid = next(e.get("event_id") for e in ev if e.get("decision")=="deny" and e.get("event_id"))
open("/tmp/dn-audit-deny-eid.txt","w").write(eid)
print("deny event_id", eid)
PY

DENY_EID=$(cat /tmp/dn-audit-deny-eid.txt)
echo "==> GET /admin/audit/events?event_id=$DENY_EID"
curl -fsS "http://127.0.0.1:8082/admin/audit/events?event_id=${DENY_EID}&limit=5" | tee /tmp/dn-audit-by-id.json
python3 - <<PY
import json
data=json.load(open("/tmp/dn-audit-by-id.json"))
ev=data.get("events") or []
assert len(ev) == 1, data
assert ev[0].get("event_id") == "$DENY_EID", data
assert data.get("source") == "index", data
print("event_id lookup ok")
PY

echo "==> JSONL file sink"
if [[ -f "$AUDIT_FILE" ]]; then
  lines=$(wc -l < "$AUDIT_FILE" | tr -d ' ')
  echo "jsonl lines=$lines"
  [[ "$lines" -ge 1 ]]
else
  echo "error: expected JSONL file sink at $AUDIT_FILE after deny traffic" >&2
  exit 1
fi

if [[ -f "$AUDIT_INDEX" ]]; then
  echo "sqlite index present: $AUDIT_INDEX"
else
  echo "error: expected SQLite index at $AUDIT_INDEX" >&2
  exit 1
fi

echo "==> GET /admin/audit/events?audit_level=L0"
curl -fsS "http://127.0.0.1:8082/admin/audit/events?audit_level=L0&limit=20" | tee /tmp/dn-audit-l0.json >/dev/null
python3 - <<'PY'
import json
data=json.load(open("/tmp/dn-audit-l0.json"))
ev=data.get("events") or []
assert ev, data
for e in ev:
    lvl=(e.get("audit_level") or "").upper()
    assert lvl=="L0", e
print("audit_level=L0 filter ok", "events", len(ev))
PY

echo "==> GET /admin/audit/events?outcome=security_deny"
curl -fsS "http://127.0.0.1:8082/admin/audit/events?outcome=security_deny&limit=20" | tee /tmp/dn-audit-outcome.json >/dev/null
python3 - <<'PY'
import json
data=json.load(open("/tmp/dn-audit-outcome.json"))
ev=data.get("events") or []
assert ev, data
for e in ev:
    assert e.get("outcome") == "security_deny", e
assert data.get("source") == "index", data
print("outcome=security_deny filter ok", "events", len(ev))
# pick a listener for UI19 filter
lsn = next((e.get("listener") for e in ev if e.get("listener")), None)
assert lsn, f"expected deny event with listener, got {ev[0] if ev else None}"
open("/tmp/dn-audit-deny-listener.txt","w").write(lsn)
print("deny listener", lsn)
PY

DENY_LSN=$(cat /tmp/dn-audit-deny-listener.txt)
echo "==> GET /admin/audit/events?listener=$DENY_LSN"
curl -fsS "http://127.0.0.1:8082/admin/audit/events?listener=${DENY_LSN}&limit=20" | tee /tmp/dn-audit-listener.json >/dev/null
python3 - <<PY
import json
data=json.load(open("/tmp/dn-audit-listener.json"))
ev=data.get("events") or []
assert ev, data
for e in ev:
    assert e.get("listener") == "$DENY_LSN", e
assert data.get("source") == "index", data
print("listener filter ok", "listener=$DENY_LSN", "events", len(ev))
# pick a rule for UI20 filter
rule = next((e.get("rule") for e in data.get("events") or [] if e.get("rule")), None)
# Prefer deny rule from outcome events
import json as _json
out=json.load(open("/tmp/dn-audit-outcome.json"))
rule = next((e.get("rule") for e in (out.get("events") or []) if e.get("rule")), rule)
assert rule, "expected deny event with rule"
open("/tmp/dn-audit-deny-rule.txt","w").write(rule)
print("deny rule", rule)
PY

DENY_RULE=$(cat /tmp/dn-audit-deny-rule.txt)
echo "==> GET /admin/audit/events?rule=$DENY_RULE"
curl -fsS "http://127.0.0.1:8082/admin/audit/events?rule=${DENY_RULE}&limit=20" | tee /tmp/dn-audit-rule.json >/dev/null
python3 - <<PY
import json
from urllib.parse import quote
data=json.load(open("/tmp/dn-audit-rule.json"))
ev=data.get("events") or []
assert ev, data
for e in ev:
    assert e.get("rule") == "$DENY_RULE", e
assert data.get("source") == "index", data
print("rule filter ok", "rule=$DENY_RULE", "events", len(ev))
PY

echo "smoke-security-audit: OK"
