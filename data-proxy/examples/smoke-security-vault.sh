#!/usr/bin/env bash
# H03: vault lease revoke / renew / prune (no password in JSON).
set -euo pipefail

export PATH="/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:${HOME}/.cargo/bin:/Volumes/fushilu/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin:${PATH:-}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG_FILE="$ROOT/examples/security-deny-gateway-config.toml"
PROXY_LOG="${TMPDIR:-/tmp}/data-nexus-vault-smoke.log"
PROXY_BIN="${CARGO_TARGET_DIR}/debug/proxy"

cleanup() {
  if [[ -n "${PROXY_PID:-}" ]] && kill -0 "$PROXY_PID" 2>/dev/null; then
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing $1" >&2; exit 1; }; }
need curl; need cargo; need python3

pkill -f '/debug/proxy' 2>/dev/null || true
sleep 1

echo "==> build/start gateway"
(
  cd "$ROOT"
  if [[ ! -x "$PROXY_BIN" ]] || [[ "$ROOT/gateway/core/src/vault.rs" -nt "$PROXY_BIN" ]] \
    || [[ "$ROOT/http/src/http/mod.rs" -nt "$PROXY_BIN" ]]; then
    cargo build -p data-proxy --bin proxy
  fi
  exec "$PROXY_BIN" daemon -c "$CONFIG_FILE"
) >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!

for _ in $(seq 1 120); do
  curl -fsS "http://127.0.0.1:8082/admin/projects" >/dev/null 2>&1 && break
  kill -0 "$PROXY_PID" 2>/dev/null || { cat "$PROXY_LOG"; exit 1; }
  sleep 1
done

echo "==> issue lease"
curl -fsS -X POST "http://127.0.0.1:8082/admin/vault/leases" \
  -H 'content-type: application/json' \
  -d '{"project":"orders","environment":"dev","ttl_secs":600}' \
  | tee /tmp/dn-vault-lease.json
python3 - <<'PY'
import json
lease=json.load(open("/tmp/dn-vault-lease.json"))
assert "lease_id" in lease and "access_token" in lease
assert "password" not in json.dumps(lease).lower() or '"password"' not in json.dumps(lease)
assert lease.get("revoked") in (False, None, 0)
open("/tmp/dn-vault-id.txt","w").write(lease["lease_id"])
open("/tmp/dn-vault-token.txt","w").write(lease["access_token"])
print("issued", lease["lease_id"])
PY
LEASE_ID="$(cat /tmp/dn-vault-id.txt)"

echo "==> renew rotates token"
curl -fsS -X POST "http://127.0.0.1:8082/admin/vault/leases/${LEASE_ID}/renew" \
  -H 'content-type: application/json' \
  -d '{"ttl_secs":900}' | tee /tmp/dn-vault-renew.json
python3 - <<'PY'
import json
old=open("/tmp/dn-vault-token.txt").read()
r=json.load(open("/tmp/dn-vault-renew.json"))
assert r["lease_id"]==open("/tmp/dn-vault-id.txt").read()
assert r["access_token"] != old
assert "password" not in json.dumps(r)
print("renewed token rotated")
PY

echo "==> revoke"
curl -fsS -X POST "http://127.0.0.1:8082/admin/vault/leases/${LEASE_ID}/revoke" \
  -H 'content-type: application/json' \
  -d '{"revoked_by":"smoke"}' | tee /tmp/dn-vault-rev.json
python3 - <<'PY'
import json
r=json.load(open("/tmp/dn-vault-rev.json"))
assert r.get("revoked") is True
print("revoked")
PY

echo "==> renew after revoke fails"
set +e
curl -sS -o /tmp/dn-vault-renew2.json -w "%{http_code}" \
  -X POST "http://127.0.0.1:8082/admin/vault/leases/${LEASE_ID}/renew" \
  -H 'content-type: application/json' -d '{}' >/tmp/dn-vault-renew2.code
set -e
python3 - <<'PY'
code=open("/tmp/dn-vault-renew2.code").read().strip()
assert code.startswith("4"), code
body=open("/tmp/dn-vault-renew2.json").read().lower()
assert "revok" in body or "failed" in body, body
print("renew-after-revoke blocked", code)
PY

echo "==> prune"
curl -fsS -X POST "http://127.0.0.1:8082/admin/vault/leases/prune" | tee /tmp/dn-vault-prune.json
python3 - <<'PY'
import json
r=json.load(open("/tmp/dn-vault-prune.json"))
assert "removed" in r
print("pruned", r["removed"])
PY

echo "smoke-security-vault: OK"
