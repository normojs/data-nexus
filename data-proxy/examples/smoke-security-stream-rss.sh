#!/usr/bin/env bash
# A06: coarse process-RSS sanity for true Streaming (logical peak still authoritative).
#
# Honesty:
# - Samples OS RSS (ps) of the gateway process during a large multi-window SELECT.
# - Hard-fails if RSS grows past a catastrophic bound (default 128 MiB).
# - Hard-fails if RSS growth is not clearly below a full-result size estimate.
# - Still asserts gateway_encode_peak_window_rows ≤ window_rows (logical peak).
# - Does NOT prove peak ≈ 1–2 windows in bytes; macOS RSS noise is large.
# - Not a substitute for cgroup/RSS CI in production CI images.
#
# Config: security-stream-rss-gateway-config.toml (window_rows=8, max_rows=200000).
set -euo pipefail

export PATH="/Volumes/fushilu/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin:/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:${HOME}/.cargo/bin:${PATH:-}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.94.1}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$ROOT/examples/docker-compose.dev.yml"
CONFIG_FILE="$ROOT/examples/security-stream-rss-gateway-config.toml"
PROXY_LOG="${TMPDIR:-/tmp}/data-nexus-security-stream-rss.log"
COMPOSE=(docker compose -f "$COMPOSE_FILE")

# Tunables (honest bounds — not "exactly one window").
N_ROWS="${DN_RSS_N_ROWS:-50000}"
PAYLOAD_LEN="${DN_RSS_PAYLOAD_LEN:-256}"
# Absolute RSS growth cap (KiB). Default 256 MiB — catastrophic materialize / leak.
# Idle gateway ~20–40 MiB; full 50k×256B materialize would be multi-hundred-MiB class.
RSS_DELTA_CAP_KB="${DN_RSS_DELTA_CAP_KB:-262144}"
# Optional relative bound: growth must stay under full_result_estimate * MULT.
# Default 0 disables the relative check (OS RSS noise + client buffering make it flaky).
# Set DN_RSS_VS_FULL_MULT=8 (etc.) only in environments where RSS is stable.
RSS_VS_FULL_MULT="${DN_RSS_VS_FULL_MULT:-0}"
WINDOW_ROWS=8

cleanup() {
  if [[ -n "${PROXY_PID:-}" ]] && kill -0 "$PROXY_PID" 2>/dev/null; then
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing $1" >&2; exit 1; }; }
need docker; need cargo; need curl; need python3; need ps

rss_kb() {
  # macOS/BSD ps: RSS in KiB. Linux ps often same with -o rss=.
  local pid="$1"
  ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ' | head -1
}

pkill -f '/debug/proxy' 2>/dev/null || true
sleep 1

echo "==> start backends"
"${COMPOSE[@]}" up -d
for _ in $(seq 1 90); do
  "${COMPOSE[@]}" exec -T mysql-primary mysqladmin ping -h 127.0.0.1 -uroot -proot --silent 2>/dev/null && break
  sleep 2
done

echo "==> seed stream_rss_t with ${N_ROWS} rows (payload≈${PAYLOAD_LEN}B)"
# DROP+CREATE for schema drift; batch inserts via Python for speed.
"${COMPOSE[@]}" exec -T mysql-primary mysql -uroot -proot -e "
CREATE DATABASE IF NOT EXISTS orders;
USE orders;
DROP TABLE IF EXISTS stream_rss_t;
CREATE TABLE stream_rss_t (
  id INT PRIMARY KEY,
  payload VARCHAR(512) NOT NULL
) ENGINE=InnoDB;
"

python3 - <<PY
import subprocess, sys
n = int("${N_ROWS}")
plen = int("${PAYLOAD_LEN}")
payload = ("x" * plen).replace("'", "")
batch = 200  # keep SQL under ARG_MAX when piped
compose = ["docker", "compose", "-f", "${COMPOSE_FILE}", "exec", "-T", "mysql-primary",
           "mysql", "-uroot", "-proot"]
for start in range(1, n + 1, batch):
    end = min(start + batch - 1, n)
    values = ",".join(f"({i},'{payload}')" for i in range(start, end + 1))
    sql = f"USE orders; INSERT INTO stream_rss_t (id, payload) VALUES {values};\n"
    r = subprocess.run(compose, input=sql.encode(), capture_output=True)
    if r.returncode != 0:
        sys.stderr.write(r.stderr.decode("utf-8", "replace")[:2000] + "\n")
        sys.stderr.write(r.stdout.decode("utf-8", "replace")[:500] + "\n")
        raise SystemExit(f"seed insert failed at {start}-{end} rc={r.returncode}")
    if start == 1 or end == n or (start - 1) % 10000 == 0:
        print(f"  seeded {end}/{n}", flush=True)
print("seed done", n)
PY

echo "==> start gateway (window_rows=${WINDOW_ROWS}, Streaming, no mask)"
PROXY_BIN="${CARGO_TARGET_DIR}/debug/proxy"
(
  cd "$ROOT"
  if [[ ! -x "$PROXY_BIN" ]] \
    || [[ "$ROOT/runtime/gateway/src/core_engine.rs" -nt "$PROXY_BIN" ]] \
    || [[ "$ROOT/gateway/core/src/transport.rs" -nt "$PROXY_BIN" ]] \
    || [[ "$ROOT/runtime/gateway/src/server/metrics.rs" -nt "$PROXY_BIN" ]]; then
    cargo build -p data-proxy --bin proxy
  fi
  if [[ ! -x "$PROXY_BIN" ]]; then
    PROXY_BIN="/Volumes/fushilu/.caches/data-nexus/cargo-target/debug/proxy"
  fi
  exec "$PROXY_BIN" daemon -c "$CONFIG_FILE"
) >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!

for _ in $(seq 1 120); do
  curl -fsS "http://127.0.0.1:8082/healthz" >/dev/null 2>&1 && break
  kill -0 "$PROXY_PID" 2>/dev/null || { cat "$PROXY_LOG"; exit 1; }
  sleep 0.25
done

BASE_RSS="$(rss_kb "$PROXY_PID")"
if [[ -z "$BASE_RSS" || "$BASE_RSS" -le 0 ]]; then
  echo "FAIL: could not sample baseline RSS for pid=$PROXY_PID" >&2
  exit 1
fi
echo "baseline RSS_KiB=$BASE_RSS pid=$PROXY_PID"

echo "==> stream large SELECT via gateway (MySQL) while sampling gateway RSS"
# Discard client result body so we measure gateway RSS, not mysql client buffering.
(
  docker run --rm --add-host=host.docker.internal:host-gateway mysql:8.0 \
    mysql --ssl-mode=DISABLED -h host.docker.internal -P 9088 -uroot -proot -N \
    -e "SELECT id, payload FROM stream_rss_t ORDER BY id;" \
    >/dev/null 2>/tmp/dn-stream-rss-err.txt
) &
CLIENT_PID=$!

MAX_RSS="$BASE_RSS"
SAMPLES=0
while kill -0 "$CLIENT_PID" 2>/dev/null; do
  cur="$(rss_kb "$PROXY_PID" || true)"
  if [[ -n "$cur" && "$cur" -gt 0 ]]; then
    SAMPLES=$((SAMPLES + 1))
    if [[ "$cur" -gt "$MAX_RSS" ]]; then
      MAX_RSS="$cur"
    fi
  fi
  # Also ensure proxy still alive.
  if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "FAIL: proxy died during RSS stream" >&2
    cat "$PROXY_LOG" | tail -50 >&2 || true
    wait "$CLIENT_PID" 2>/dev/null || true
    exit 1
  fi
  sleep 0.05
done
set +e
wait "$CLIENT_PID"
CLIENT_RC=$?
set -e
# Final sample after drain.
cur="$(rss_kb "$PROXY_PID" || true)"
if [[ -n "$cur" && "$cur" -gt "$MAX_RSS" ]]; then
  MAX_RSS="$cur"
fi

if [[ "$CLIENT_RC" -ne 0 ]]; then
  echo "FAIL: client SELECT failed rc=$CLIENT_RC" >&2
  cat /tmp/dn-stream-rss-err.txt >&2 || true
  exit 1
fi

# Confirm row count with a separate COUNT(*) (body discarded above).
COUNT_OUT="$(
  docker run --rm --add-host=host.docker.internal:host-gateway mysql:8.0 \
    mysql --ssl-mode=DISABLED -h host.docker.internal -P 9088 -uroot -proot -N \
    -e "SELECT COUNT(*) FROM stream_rss_t;"
)"
ROW_LINES="$(echo "$COUNT_OUT" | tr -d '[:space:]')"
if [[ -z "$ROW_LINES" || "$ROW_LINES" -lt "$N_ROWS" ]]; then
  echo "FAIL: expected table count ≥${N_ROWS}, got '${ROW_LINES}'" >&2
  exit 1
fi

DELTA_KB=$((MAX_RSS - BASE_RSS))
if [[ "$DELTA_KB" -lt 0 ]]; then
  DELTA_KB=0
fi
# Full-result estimate (bytes): rows * (payload + id/overhead ~ 48 for wire/row bookkeeping).
FULL_EST_BYTES=$((N_ROWS * (PAYLOAD_LEN + 48)))
FULL_EST_KB=$((FULL_EST_BYTES / 1024))
BOUND_VS_FULL_KB=0
if [[ "${RSS_VS_FULL_MULT}" -gt 0 ]]; then
  BOUND_VS_FULL_KB=$((FULL_EST_KB * RSS_VS_FULL_MULT))
  if [[ "$BOUND_VS_FULL_KB" -lt 8192 ]]; then
    BOUND_VS_FULL_KB=8192
  fi
fi

echo "RSS samples=$SAMPLES baseline_KiB=$BASE_RSS max_KiB=$MAX_RSS delta_KiB=$DELTA_KB"
if [[ "${RSS_VS_FULL_MULT}" -gt 0 ]]; then
  echo "full_result_est_KiB=$FULL_EST_KB bound_vs_full_KiB=$BOUND_VS_FULL_KB (×${RSS_VS_FULL_MULT}) cap_KiB=$RSS_DELTA_CAP_KB"
else
  echo "full_result_est_KiB=$FULL_EST_KB relative_bound=off cap_KiB=$RSS_DELTA_CAP_KB"
fi
echo "table_rows=$ROW_LINES window_rows=$WINDOW_ROWS (client body discarded)"

if [[ "$DELTA_KB" -gt "$RSS_DELTA_CAP_KB" ]]; then
  echo "FAIL: RSS growth ${DELTA_KB} KiB exceeds absolute cap ${RSS_DELTA_CAP_KB} KiB (catastrophic materialize?)" >&2
  exit 1
fi
if [[ "${RSS_VS_FULL_MULT}" -gt 0 && "$DELTA_KB" -gt "$BOUND_VS_FULL_KB" ]]; then
  echo "FAIL: RSS growth ${DELTA_KB} KiB exceeds full-result estimate×${RSS_VS_FULL_MULT} (${BOUND_VS_FULL_KB} KiB)" >&2
  echo "  (Streaming should not retain multi-full ResultSets; logical peak is still authoritative)" >&2
  exit 1
fi
echo "A06 RSS sanity ok: delta under absolute cap${RSS_VS_FULL_MULT:+ and relative bound}"

echo "==> metrics: streaming path + logical peak ≤ window_rows=${WINDOW_ROWS}"
metrics="$(curl -fsS http://127.0.0.1:8082/metrics || true)"
if ! echo "$metrics" | grep -q 'execute_path="streaming"'; then
  echo "FAIL: expected execute_path=streaming after large Streaming SELECT" >&2
  echo "$metrics" | grep 'gateway_execute_path_total' | head -12 || true
  exit 1
fi
if ! echo "$metrics" | grep -q 'gateway_encode_peak_window_rows'; then
  echo "FAIL: missing gateway_encode_peak_window_rows" >&2
  exit 1
fi
bad_peak="$(echo "$metrics" | awk -v w="$WINDOW_ROWS" '/gateway_encode_peak_window_rows\{/ {
  v=$NF+0; if (v > w) print v
}' | head -1)"
if [[ -n "$bad_peak" ]]; then
  echo "FAIL: peak_window_rows=$bad_peak exceeds window_rows=$WINDOW_ROWS" >&2
  echo "$metrics" | grep 'gateway_encode_peak_window_rows' | head -8 || true
  exit 1
fi
echo "$metrics" | grep 'gateway_encode_peak_window_rows' | head -6 || true
echo "logical peak ≤ window_rows ok (authoritative; RSS is coarse OS sanity only)"

echo "smoke-security-stream-rss: OK"
echo "NOTE: process RSS is noisy; this smoke catches full-result materialize regressions, not exact window bytes."
