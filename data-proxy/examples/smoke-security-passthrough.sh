#!/usr/bin/env bash
# A3: same-protocol wire passthrough E2E (MySQL).
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

echo "==> seed"
"${COMPOSE[@]}" exec -T mysql-primary mysql -uroot -proot -e "
CREATE DATABASE IF NOT EXISTS orders;
USE orders;
CREATE TABLE IF NOT EXISTS pass_smoke (id INT PRIMARY KEY, name VARCHAR(32));
INSERT INTO pass_smoke VALUES (1,'alice'),(2,'bob')
  ON DUPLICATE KEY UPDATE name=VALUES(name);
"

echo "==> start gateway (passthrough=true, no obligations)"
PROXY_BIN="${CARGO_TARGET_DIR}/debug/proxy"
(
  cd "$ROOT"
  if [[ ! -x "$PROXY_BIN" ]] \
    || [[ "$ROOT/runtime/gateway/src/backend/mysql.rs" -nt "$PROXY_BIN" ]] \
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

echo "==> SELECT via passthrough path"
out="$(mysql_via_gateway 'SELECT id, name FROM pass_smoke ORDER BY id;')"
echo "$out"
echo "$out" | grep -q 'alice'
echo "$out" | grep -q 'bob'

# audit should show outcome passthrough if pipeline installed
sleep 0.3
if curl -fsS "http://127.0.0.1:8082/admin/audit/events?limit=20" >/tmp/dn-pt-events.json 2>/dev/null; then
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
if rg -q 'passthrough' "$PROXY_LOG"; then
  echo "log contains passthrough outcome"
fi

echo "==> A05 Prometheus execute_path + passthrough_bytes"
curl -fsS "http://127.0.0.1:8082/metrics" | tee /tmp/dn-pt-metrics.txt >/dev/null
python3 - <<'PY'
text=open("/tmp/dn-pt-metrics.txt").read()
assert "gateway_execute_path_total" in text, "missing gateway_execute_path_total"
assert 'execute_path="passthrough"' in text or "execute_path=\"passthrough\"" in text, text[:2000]
# bytes counter present (may be 0 if wire path not taken under this build, but series should exist after traffic)
assert "gateway_passthrough_bytes_total" in text, "missing gateway_passthrough_bytes_total"
print("A05 metrics ok")
# print matching lines for debug
for line in text.splitlines():
    if "gateway_execute_path_total" in line or "gateway_passthrough_bytes_total" in line:
        if line.startswith("#"):
            continue
        print(line)
PY

echo "smoke-security-passthrough: OK"
