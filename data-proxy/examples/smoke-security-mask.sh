#!/usr/bin/env bash
# S3: dynamic mask + row_filter smoke.
# Requires: docker, cargo
set -euo pipefail

export PATH="/Volumes/fushilu/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin:/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:${HOME}/.cargo/bin:/Volumes/fushilu/.rustup/toolchains/nightly-2025-01-07-aarch64-apple-darwin/bin:${PATH:-}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.94.1}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$ROOT/examples/docker-compose.dev.yml"
CONFIG_FILE="$ROOT/examples/security-mask-gateway-config.toml"
PROXY_LOG="${TMPDIR:-/tmp}/data-nexus-security-mask.log"
COMPOSE=(docker compose -f "$COMPOSE_FILE")

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

need docker
need cargo
need curl

echo "==> free ports if stale proxy left over"
pkill -f '/debug/proxy' 2>/dev/null || true
sleep 1

echo "==> starting backend containers"
"${COMPOSE[@]}" up -d

echo "==> waiting for MySQL"
for _ in $(seq 1 90); do
  if "${COMPOSE[@]}" exec -T mysql-primary \
    mysqladmin ping -h 127.0.0.1 -uroot -proot --silent 2>/dev/null; then
    break
  fi
  sleep 2
done
"${COMPOSE[@]}" exec -T mysql-primary mysqladmin ping -h 127.0.0.1 -uroot -proot --silent

echo "==> seed employees with tenant + phone/salary"
"${COMPOSE[@]}" exec -T mysql-primary mysql -uroot -proot -e "
CREATE DATABASE IF NOT EXISTS orders;
USE orders;
DROP TABLE IF EXISTS employees;
CREATE TABLE employees (
  id INT PRIMARY KEY,
  name VARCHAR(64) NOT NULL,
  phone VARCHAR(32) NOT NULL,
  salary INT NOT NULL,
  tenant_id INT NOT NULL
);
INSERT INTO employees (id, name, phone, salary, tenant_id) VALUES
  (1, 'alice', '13812345678', 90000, 1),
  (2, 'bob', '13987654321', 80000, 2);
"

echo "==> building and starting gateway (security mask/row)"
PROXY_BIN=""
for candidate in \
  "${CARGO_TARGET_DIR}/debug/proxy" \
  /Volumes/fushilu/.caches/data-nexus/cargo-target/debug/proxy \
  "$ROOT/target/debug/proxy"
do
  if [[ -n "$candidate" && -x "$candidate" ]]; then
    PROXY_BIN="$candidate"
    break
  fi
done
(
  cd "$ROOT"
  NEED_BUILD=1
  if [[ -n "$PROXY_BIN" ]]; then
    if [[ ! "$ROOT/gateway/core/src/pdp.rs" -nt "$PROXY_BIN" ]] \
      && [[ ! "$ROOT/gateway/core/src/obligations.rs" -nt "$PROXY_BIN" ]] \
      && [[ ! "$ROOT/runtime/gateway/src/core_engine.rs" -nt "$PROXY_BIN" ]]; then
      NEED_BUILD=0
    fi
  fi
  if [[ "$NEED_BUILD" -eq 1 ]]; then
    cargo build -p data-proxy --bin proxy
    PROXY_BIN="${CARGO_TARGET_DIR}/debug/proxy"
  fi
  echo "using binary: $PROXY_BIN" >>"$PROXY_LOG"
  "$PROXY_BIN" daemon -c "$CONFIG_FILE"
) >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!

echo "==> waiting for admin (8082)"
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

echo "==> UI04 GET /admin/security-policies includes mask_rules + column_tags"
curl -fsS "http://127.0.0.1:8082/admin/security-policies" >/tmp/data-nexus-security-policies-mask.json
python3 - <<'PY'
import json
data=json.load(open("/tmp/data-nexus-security-policies-mask.json"))
assert data["enabled"] is True, data
assert "mask_rules" in data and "column_tags" in data, sorted(data.keys())
mask_names=sorted(r["name"] for r in data["mask_rules"])
assert len(mask_names) >= 1, mask_names
assert all("algorithm" in r for r in data["mask_rules"]), data["mask_rules"]
assert all("mask_rule" in t and "column" in t for t in data["column_tags"]), data["column_tags"]
# static watermark token value must not leak if present
wm=data.get("watermark") or {}
assert "token" not in wm, wm
print("ui04 mask policies:", mask_names, "tags", len(data["column_tags"]))
PY

mysql_via_gateway() {
  local sql="$1"
  docker run --rm --add-host=host.docker.internal:host-gateway mysql:8.0 \
    mysql --ssl-mode=DISABLED -h host.docker.internal -P 9088 -uroot -proot -N -e "$sql"
}

echo "==> allow: SELECT 1"
out="$(mysql_via_gateway 'SELECT 1 AS ok;')"
echo "$out" | tr -d '[:space:]' | grep -qx '1'

echo "==> row filter: only tenant_id=1 rows"
out="$(mysql_via_gateway 'SELECT id, name FROM employees ORDER BY id;')"
echo "$out"
echo "$out" | tr '\t' ' ' | grep -qi 'alice'
if echo "$out" | grep -qi 'bob'; then
  echo "row filter failed: bob (tenant 2) leaked" >&2
  exit 1
fi

echo "==> mask: phone partial + salary null"
# Use -e with column names via default mysql tabular is harder with -N;
# check that raw salary 90000 and full phone do not appear.
out="$(mysql_via_gateway 'SELECT id, phone, salary FROM employees WHERE id=1;')"
echo "$out"
if echo "$out" | grep -q '90000'; then
  echo "salary not nullified" >&2
  exit 1
fi
if echo "$out" | grep -q '13812345678'; then
  echo "phone not masked" >&2
  exit 1
fi
# partial keeps prefix 138 and suffix 78
if ! echo "$out" | grep -q '138'; then
  echo "phone partial prefix missing" >&2
  exit 1
fi

echo "==> O01 metrics: mask/encode counters present after Secure path"
metrics="$(curl -fsS http://127.0.0.1:8082/metrics || true)"
if echo "$metrics" | grep -q 'gateway_mask_rows_total'; then
  echo "$metrics" | grep 'gateway_mask_rows_total' | head -3 || true
  # O01: after mask traffic, at least one series must be > 0 (hard fail).
  if ! echo "$metrics" | grep -E 'gateway_mask_rows_total\{' | grep -q '[1-9]'; then
    echo "FAIL: gateway_mask_rows_total present but all zero after mask traffic" >&2
    echo "$metrics" | grep 'gateway_mask_rows_total' || true
    exit 1
  fi
  echo "mask_rows counter > 0"
else
  echo "missing gateway_mask_rows_total in /metrics" >&2
  echo "$metrics" | head -20 >&2
  exit 1
fi
if echo "$metrics" | grep -q 'gateway_encode_windows_total'; then
  echo "$metrics" | grep 'gateway_encode_windows_total' | head -3 || true
  if ! echo "$metrics" | grep -E 'gateway_encode_windows_total\{' | grep -q '[1-9]'; then
    echo "FAIL: gateway_encode_windows_total all zero after mask traffic" >&2
    exit 1
  fi
  echo "encode_windows counter > 0"
else
  echo "FAIL: missing gateway_encode_windows_total after Secure encode" >&2
  exit 1
fi
if echo "$metrics" | grep -q 'gateway_audit_queue_len'; then
  echo "$metrics" | grep 'gateway_audit_queue_len' | head -5 || true
fi

echo "==> A08 honesty: mask/row obligations force Streaming even when passthrough=true"
# Config has passthrough=true but result obligations must never WireRelay/passthrough.
# Expect execute_path=streaming (not only passthrough*) after mask traffic.
curl -fsS http://127.0.0.1:8082/metrics | tee /tmp/dn-mask-metrics.txt >/dev/null
python3 - <<'PY'
import re
text = open("/tmp/dn-mask-metrics.txt").read()
paths = set()
for ln in text.splitlines():
    if "gateway_execute_path_total" not in ln or ln.startswith("#"):
        continue
    if "QUERY" not in ln:
        continue
    mp = re.search(r'execute_path="([^"]+)"', ln)
    if mp:
        paths.add(mp.group(1))
print("execute_path labels (QUERY-ish):", sorted(paths))
assert "streaming" in paths, f"expected streaming under mask+passthrough config, got {paths}"
if paths and paths.issubset({"passthrough", "passthrough_client", "passthrough_extended", "n/a"}):
    raise SystemExit(f"FAIL: mask traffic produced only passthrough-ish paths: {paths}")
print("A08 honesty: result obligations demote off wire passthrough (streaming under passthrough=true config)")
for ln in text.splitlines():
    if "gateway_encode_peak_window_rows{" in ln and not ln.startswith("#"):
        v = float(ln.split()[-1])
        assert v <= 2.0 + 1e-9, f"peak_window_rows={v} exceeds window_rows=2 under mask: {ln}"
print("A06: peak_window_rows ≤ window_rows=2 under mask path")
for ln in text.splitlines():
    if "gateway_execute_path_total" in ln and not ln.startswith("#") and "QUERY" in ln:
        print(ln)
PY

echo "smoke-security-mask: OK"
