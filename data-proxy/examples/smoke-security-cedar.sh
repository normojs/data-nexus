#!/usr/bin/env bash
# F26: Cedar PDP — SELECT ok, secret table denied via Cedar forbid.
# Requires rustc ≥1.88 (uses 1.94.1 when available) and --features security-cedar.
set -euo pipefail

export RUSTUP_HOME="${RUSTUP_HOME:-/Volumes/fushilu/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
# Prefer a toolchain that can build cedar-policy 4.x transitive deps.
if [[ -x /Volumes/fushilu/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/cargo ]]; then
  export PATH="/Volumes/fushilu/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin:${HOME}/.cargo/bin:/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:${PATH:-}"
elif [[ -x "$HOME/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/cargo" ]]; then
  export PATH="$HOME/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin:${HOME}/.cargo/bin:/usr/local/bin:${PATH:-}"
else
  export PATH="/usr/local/bin:/opt/homebrew/bin:${HOME}/.cargo/bin:/Volumes/fushilu/.rustup/toolchains/nightly-2025-01-07-aarch64-apple-darwin/bin:${PATH:-}"
fi
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Users/fushilu/workspace/revocloud/data-nexus/.cargo-target-cedar}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$ROOT/examples/docker-compose.dev.yml"
CONFIG_FILE="$ROOT/examples/security-cedar-gateway-config.toml"
PROXY_LOG="${TMPDIR:-/tmp}/data-nexus-security-cedar.log"
COMPOSE=(docker compose -f "$COMPOSE_FILE")

cleanup() {
  if [[ -n "${PROXY_PID:-}" ]] && kill -0 "$PROXY_PID" 2>/dev/null; then
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing $1" >&2; exit 1; }; }
need docker; need cargo; need curl; need python3

echo "==> rustc $(rustc --version)"
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
CREATE TABLE IF NOT EXISTS secret_tokens (id INT PRIMARY KEY, token VARCHAR(64));
INSERT INTO secret_tokens VALUES (1,'x') ON DUPLICATE KEY UPDATE token=VALUES(token);
"

echo "==> build gateway with security-cedar (foreground)"
PROXY_BIN="${CARGO_TARGET_DIR}/debug/proxy"
(
  cd "$ROOT"
  cargo build -p data-proxy --bin proxy --features security-cedar
)
# policy_dir is relative to process cwd (= ROOT)
: >"$PROXY_LOG"
(
  cd "$ROOT"
  exec "$PROXY_BIN" daemon -c "$CONFIG_FILE"
) >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!

for _ in $(seq 1 120); do
  if curl -fsS "http://127.0.0.1:8082/admin/security-policies" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "gateway exited early; log:"
    cat "$PROXY_LOG"
    exit 1
  fi
  sleep 1
done
curl -fsS "http://127.0.0.1:8082/admin/security-policies" | head -c 200 || {
  echo "admin not ready"; cat "$PROXY_LOG"; exit 1
}
echo

mysql_via_gateway() {
  local sql="$1"
  docker run --rm --add-host=host.docker.internal:host-gateway mysql:8.0 \
    mysql --ssl-mode=DISABLED -h host.docker.internal -P 9088 -uroot -proot -N -e "$sql"
}

echo "==> SELECT 1 allowed (Cedar __none__)"
out="$(mysql_via_gateway 'SELECT 1;')"
echo "$out" | tr -d '[:space:]' | grep -qx '1'

echo "==> SELECT portal_t allowed"
out="$(mysql_via_gateway 'SELECT id, name FROM portal_t WHERE id=1;')"
echo "$out" | tr '\t' ' ' | grep -q 'portal'

echo "==> SELECT secret_tokens denied by Cedar"
set +e
mysql_via_gateway 'SELECT id FROM secret_tokens;' >/tmp/dn-cedar-deny.txt 2>&1
rc=$?
set -e
[[ $rc -ne 0 ]]
grep -qiE 'cedar|deny|secret|security|ERROR' /tmp/dn-cedar-deny.txt
cat /tmp/dn-cedar-deny.txt || true

echo "==> INSERT into non-portal table denied"
set +e
mysql_via_gateway 'INSERT INTO secret_tokens VALUES (2,"y");' >/tmp/dn-cedar-ins.txt 2>&1
rc2=$?
set -e
[[ $rc2 -ne 0 ]]

echo "smoke-security-cedar: OK"
