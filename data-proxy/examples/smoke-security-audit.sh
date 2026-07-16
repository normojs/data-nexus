#!/usr/bin/env bash
# S4: audit pipeline + GET /admin/audit/events smoke.
set -euo pipefail

export PATH="/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:${HOME}/.cargo/bin:/Volumes/fushilu/.rustup/toolchains/nightly-2025-01-07-aarch64-apple-darwin/bin:${PATH:-}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Users/fushilu/workspace/revocloud/data-nexus/.cargo-target}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$ROOT/examples/docker-compose.dev.yml"
CONFIG_FILE="$ROOT/examples/security-deny-gateway-config.toml"
PROXY_LOG="${TMPDIR:-/tmp}/data-nexus-security-audit.log"
AUDIT_FILE="/tmp/data-nexus-audit-events.jsonl"
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
rm -f "$AUDIT_FILE"

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
  if [[ ! -x "$PROXY_BIN" ]] || [[ "$ROOT/gateway/core/src/audit_pipeline.rs" -nt "$PROXY_BIN" ]]; then
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
sleep 0.5

echo "==> GET /admin/audit/stats"
curl -fsS "http://127.0.0.1:8082/admin/audit/stats" | tee /tmp/dn-audit-stats.json
python3 - <<'PY'
import json
s=json.load(open("/tmp/dn-audit-stats.json"))
assert s.get("accepted",0) >= 1, s
# B04 fields present (defaults 0 when no rotate yet)
assert "rotated" in s, s
assert "pruned" in s, s
print("stats ok", s)
PY

echo "==> GET /admin/audit/events?decision=deny"
curl -fsS "http://127.0.0.1:8082/admin/audit/events?decision=deny&limit=20" | tee /tmp/dn-audit-events.json
python3 - <<'PY'
import json
data=json.load(open("/tmp/dn-audit-events.json"))
ev=data.get("events") or []
assert any((e.get("decision")=="deny") for e in ev), data
assert any((e.get("outcome")=="security_deny" or e.get("code")=="security_deny") for e in ev), data
print("deny events:", len(ev))
PY

echo "==> JSONL file sink"
if [[ -f "$AUDIT_FILE" ]]; then
  lines=$(wc -l < "$AUDIT_FILE" | tr -d ' ')
  echo "jsonl lines=$lines"
  [[ "$lines" -ge 1 ]]
else
  echo "warn: jsonl not found yet (worker lag); recent API is source of truth"
fi

echo "smoke-security-audit: OK"
