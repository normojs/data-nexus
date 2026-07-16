#!/usr/bin/env bash
# Admin API auth smoke: no token → 401; break-glass login → me → reload 200.
# Requires: cargo (or prebuilt proxy), curl, python3
# Does NOT require Docker/MySQL (Admin path only).
set -euo pipefail

export PATH="/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:${HOME}/.cargo/bin:/Volumes/fushilu/.rustup/toolchains/nightly-2025-01-07-aarch64-apple-darwin/bin:${PATH:-}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Users/fushilu/workspace/revocloud/data-nexus/.cargo-target}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG_FILE="$ROOT/examples/admin-auth-gateway-config.toml"
PROXY_LOG="${TMPDIR:-/tmp}/data-nexus-admin-auth-smoke.log"
ADMIN="http://127.0.0.1:8082"
PASS="smoke-break-glass"

cleanup() {
  if [[ -n "${PROXY_PID:-}" ]] && kill -0 "$PROXY_PID" 2>/dev/null; then
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

need curl
need python3
need cargo

# Free :8082 from a previous smoke before starting JWT-enabled admin.
pkill -f '/debug/proxy' 2>/dev/null || true
sleep 1

echo "==> building and starting gateway (admin auth enabled; data-plane security off)"
: >"$PROXY_LOG"
PROXY_BIN=""
for candidate in \
  "${CARGO_TARGET_DIR}/debug/proxy" \
  /Users/fushilu/workspace/revocloud/data-nexus/.cargo-target/debug/proxy \
  /Volumes/fushilu/.caches/data-nexus-target/debug/proxy \
  "$ROOT/target/debug/proxy"
do
  if [[ -n "$candidate" && -x "$candidate" ]]; then
    PROXY_BIN="$candidate"
    break
  fi
done
(
  cd "$ROOT"
  if [[ -z "$PROXY_BIN" ]]; then
    cargo build -p data-proxy --bin proxy
    PROXY_BIN="${CARGO_TARGET_DIR}/debug/proxy"
  fi
  echo "using binary: $PROXY_BIN" >>"$PROXY_LOG"
  "$PROXY_BIN" daemon -c "$CONFIG_FILE"
) >>"$PROXY_LOG" 2>&1 &
PROXY_PID=$!

echo "==> waiting for admin healthz (8082)"
for _ in $(seq 1 120); do
  if curl -fsS "$ADMIN/healthz" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "gateway exited early; log:"
    cat "$PROXY_LOG"
    exit 1
  fi
  sleep 1
done
curl -fsS "$ADMIN/healthz" >/dev/null

echo "==> GET /admin/auth/config (public)"
curl -fsS "$ADMIN/admin/auth/config" >/tmp/data-nexus-auth-config.json
python3 - <<'PY'
import json
cfg = json.load(open("/tmp/data-nexus-auth-config.json"))
assert cfg.get("enabled") is True, cfg
assert cfg.get("mode") == "jwt_hmac", cfg
assert cfg.get("break_glass_login") is True, cfg
print("auth config:", cfg)
PY

echo "==> POST /admin/reload without token → 401"
code="$(curl -s -o /tmp/data-nexus-reload-401.json -w "%{http_code}" -X POST "$ADMIN/admin/reload")"
[[ "$code" == "401" ]] || {
  echo "expected 401, got $code body=$(cat /tmp/data-nexus-reload-401.json)"
  exit 1
}
echo "reload without token: $code"

echo "==> GET /admin/listeners without token → 401"
code="$(curl -s -o /tmp/data-nexus-listeners-401.json -w "%{http_code}" "$ADMIN/admin/listeners")"
[[ "$code" == "401" ]] || {
  echo "expected 401, got $code"
  exit 1
}
echo "listeners without token: $code"

echo "==> POST /admin/auth/login (break-glass)"
curl -fsS -X POST "$ADMIN/admin/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"password\":\"$PASS\"}" >/tmp/data-nexus-login.json
TOKEN="$(python3 - <<'PY'
import json
data = json.load(open("/tmp/data-nexus-login.json"))
assert data.get("token_type") == "Bearer", data
assert data.get("access_token"), data
assert "admin" in data.get("roles", []), data
print(data["access_token"])
PY
)"
echo "login ok, token length=${#TOKEN}"

echo "==> GET /admin/me with token"
curl -fsS "$ADMIN/admin/me" \
  -H "Authorization: Bearer $TOKEN" >/tmp/data-nexus-me.json
python3 - <<'PY'
import json
me = json.load(open("/tmp/data-nexus-me.json"))
assert me.get("auth_enabled") is True, me
assert me.get("subject") == "break-glass", me
assert "admin" in me.get("roles", []), me
perms = me.get("permissions", [])
assert "config:reload" in perms, perms
print("me:", {k: me[k] for k in ("subject", "roles", "auth_method", "auth_enabled")})
PY

echo "==> POST /admin/reload with admin token → 200"
code="$(curl -s -o /tmp/data-nexus-reload-200.json -w "%{http_code}" \
  -X POST "$ADMIN/admin/reload" \
  -H "Authorization: Bearer $TOKEN")"
[[ "$code" == "200" ]] || {
  echo "expected 200, got $code body=$(cat /tmp/data-nexus-reload-200.json)"
  cat "$PROXY_LOG" | tail -40
  exit 1
}
python3 - <<'PY'
import json
body = json.load(open("/tmp/data-nexus-reload-200.json"))
assert "status" in body, body
print("reload:", body.get("status"), "changed=", body.get("changed"))
PY

echo "==> GET /metrics still public (public_metrics=true)"
code="$(curl -s -o /tmp/data-nexus-metrics.txt -w "%{http_code}" "$ADMIN/metrics")"
[[ "$code" == "200" ]] || {
  echo "expected metrics 200, got $code"
  exit 1
}
echo "metrics: $code"

echo "==> wrong password login → 401"
code="$(curl -s -o /tmp/data-nexus-login-bad.json -w "%{http_code}" \
  -X POST "$ADMIN/admin/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"password":"wrong-password"}')"
[[ "$code" == "401" ]] || {
  echo "expected 401 for bad password, got $code"
  exit 1
}
echo "bad password: $code"

kill -0 "$PROXY_PID"
echo "smoke admin-auth: OK"
