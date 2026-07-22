#!/usr/bin/env bash
# A06: coarse process memory sanity for true Streaming (logical peak still authoritative).
#
# Honesty:
# - Samples gateway memory during large multi-window SELECTs (MySQL + PostgreSQL).
# - Prefer Linux cgroup v2 memory.current when available; else /proc/<pid>/status
#   VmRSS; else `ps -o rss=` (macOS/BSD). Reported as source=cgroup|proc|ps.
# - Hard-fails if growth exceeds absolute cap (default 256 MiB) — catastrophic
#   full-result materialize / leak detector.
# - Optional relative bound DN_RSS_VS_FULL_MULT (default 0 / off; OS noise).
# - Still asserts gateway_encode_peak_window_rows ≤ window_rows (logical peak).
# - Asserts encode_windows > 1 so the scan actually multi-window streamed.
# - Does NOT prove peak ≈ 1–2 windows in bytes; not precise cgroup CI.
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
# Absolute growth cap (KiB). Default 256 MiB — catastrophic materialize / leak.
RSS_DELTA_CAP_KB="${DN_RSS_DELTA_CAP_KB:-262144}"
# Optional relative bound: growth must stay under full_result_estimate * MULT.
# Default 0 disables (OS RSS noise + client buffering make it flaky).
RSS_VS_FULL_MULT="${DN_RSS_VS_FULL_MULT:-0}"
WINDOW_ROWS=8
# Prefer a specific memory source: auto | cgroup | proc | ps
MEM_SOURCE_PREF="${DN_RSS_MEM_SOURCE:-auto}"

cleanup() {
  if [[ -n "${PROXY_PID:-}" ]] && kill -0 "$PROXY_PID" 2>/dev/null; then
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing $1" >&2; exit 1; }; }
need docker; need cargo; need curl; need python3; need ps

# Resolve best-effort memory sample in KiB + source name.
# cgroup: container/process group current usage (Linux CI best).
# proc:   VmRSS from /proc (Linux host).
# ps:     portable RSS (macOS default).
mem_sample_kb() {
  local pid="$1"
  local pref="${2:-auto}"
  local val="" src=""

  try_cgroup() {
    # cgroup v2: walk up from proc cgroup path looking for memory.current.
    local cg
    if [[ -r "/proc/${pid}/cgroup" ]]; then
      cg="$(awk -F: '/^0::/ {print $3; exit}' "/proc/${pid}/cgroup" 2>/dev/null || true)"
      if [[ -n "$cg" ]]; then
        local p="/sys/fs/cgroup${cg}"
        while [[ -n "$p" && "$p" != "/" ]]; do
          if [[ -r "${p}/memory.current" ]]; then
            # bytes → KiB
            local b
            b="$(cat "${p}/memory.current" 2>/dev/null || true)"
            if [[ -n "$b" && "$b" -gt 0 ]]; then
              echo "$((b / 1024)) cgroup"
              return 0
            fi
          fi
          p="$(dirname "$p")"
        done
      fi
    fi
    # Common single-cgroup mount for whole process tree.
    if [[ -r /sys/fs/cgroup/memory.current ]]; then
      local b
      b="$(cat /sys/fs/cgroup/memory.current 2>/dev/null || true)"
      if [[ -n "$b" && "$b" -gt 0 ]]; then
        echo "$((b / 1024)) cgroup"
        return 0
      fi
    fi
    return 1
  }

  try_proc() {
    if [[ -r "/proc/${pid}/status" ]]; then
      local kb
      kb="$(awk '/^VmRSS:/ {print $2; exit}' "/proc/${pid}/status" 2>/dev/null || true)"
      if [[ -n "$kb" && "$kb" -gt 0 ]]; then
        echo "${kb} proc"
        return 0
      fi
    fi
    return 1
  }

  try_ps() {
    local kb
    kb="$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ' | head -1)"
    if [[ -n "$kb" && "$kb" -gt 0 ]]; then
      echo "${kb} ps"
      return 0
    fi
    return 1
  }

  case "$pref" in
    cgroup)
      try_cgroup && return 0
      ;;
    proc)
      try_proc && return 0
      ;;
    ps)
      try_ps && return 0
      ;;
    auto|*)
      try_cgroup && return 0
      try_proc && return 0
      try_ps && return 0
      ;;
  esac
  return 1
}

pkill -f '/debug/proxy' 2>/dev/null || true
sleep 1

echo "==> start backends"
"${COMPOSE[@]}" up -d
for _ in $(seq 1 90); do
  "${COMPOSE[@]}" exec -T mysql-primary mysqladmin ping -h 127.0.0.1 -uroot -proot --silent 2>/dev/null && break
  sleep 2
done
for _ in $(seq 1 90); do
  "${COMPOSE[@]}" exec -T postgres-primary pg_isready -U postgres -d analytics >/dev/null 2>&1 && break
  sleep 2
done

echo "==> seed MySQL stream_rss_t with ${N_ROWS} rows (payload≈${PAYLOAD_LEN}B)"
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
batch = 200
compose = ["docker", "compose", "-f", "${COMPOSE_FILE}", "exec", "-T", "mysql-primary",
           "mysql", "-uroot", "-proot"]
for start in range(1, n + 1, batch):
    end = min(start + batch - 1, n)
    values = ",".join(f"({i},'{payload}')" for i in range(start, end + 1))
    sql = f"USE orders; INSERT INTO stream_rss_t (id, payload) VALUES {values};\n"
    r = subprocess.run(compose, input=sql.encode(), capture_output=True)
    if r.returncode != 0:
        sys.stderr.write(r.stderr.decode("utf-8", "replace")[:2000] + "\n")
        raise SystemExit(f"mysql seed failed at {start}-{end} rc={r.returncode}")
    if start == 1 or end == n or (start - 1) % 10000 == 0:
        print(f"  mysql seeded {end}/{n}", flush=True)
print("mysql seed done", n)
PY

echo "==> seed PostgreSQL stream_rss_t with ${N_ROWS} rows"
"${COMPOSE[@]}" exec -T postgres-primary \
  psql -U postgres -d analytics -v ON_ERROR_STOP=1 -c \
  "DROP TABLE IF EXISTS stream_rss_t;
   CREATE TABLE stream_rss_t (id INT PRIMARY KEY, payload TEXT NOT NULL);"

python3 - <<PY
import subprocess, sys
n = int("${N_ROWS}")
plen = int("${PAYLOAD_LEN}")
payload = ("x" * plen).replace("'", "")
batch = 200
compose = ["docker", "compose", "-f", "${COMPOSE_FILE}", "exec", "-T", "postgres-primary",
           "psql", "-U", "postgres", "-d", "analytics", "-v", "ON_ERROR_STOP=1"]
for start in range(1, n + 1, batch):
    end = min(start + batch - 1, n)
    values = ",".join(f"({i},'{payload}')" for i in range(start, end + 1))
    sql = f"INSERT INTO stream_rss_t (id, payload) VALUES {values};\n"
    r = subprocess.run(compose, input=sql.encode(), capture_output=True)
    if r.returncode != 0:
        sys.stderr.write(r.stderr.decode("utf-8", "replace")[:2000] + "\n")
        raise SystemExit(f"pg seed failed at {start}-{end} rc={r.returncode}")
    if start == 1 or end == n or (start - 1) % 10000 == 0:
        print(f"  pg seeded {end}/{n}", flush=True)
print("pg seed done", n)
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

sample="$(mem_sample_kb "$PROXY_PID" "$MEM_SOURCE_PREF" || true)"
if [[ -z "$sample" ]]; then
  echo "FAIL: could not sample baseline memory for pid=$PROXY_PID (pref=$MEM_SOURCE_PREF)" >&2
  exit 1
fi
BASE_RSS="${sample%% *}"
MEM_SOURCE="${sample#* }"
echo "baseline mem_KiB=$BASE_RSS source=$MEM_SOURCE pid=$PROXY_PID pref=$MEM_SOURCE_PREF"

run_stream_and_sample() {
  local label="$1"
  local client_cmd="$2"
  local err_file="$3"

  echo "==> stream large SELECT via gateway ($label) while sampling memory ($MEM_SOURCE)"
  (
    eval "$client_cmd" >/dev/null 2>"$err_file"
  ) &
  local CLIENT_PID=$!

  local MAX_RSS="$BASE_RSS"
  local SAMPLES=0
  while kill -0 "$CLIENT_PID" 2>/dev/null; do
    local cur_line cur
    cur_line="$(mem_sample_kb "$PROXY_PID" "$MEM_SOURCE_PREF" || true)"
    if [[ -n "$cur_line" ]]; then
      cur="${cur_line%% *}"
      if [[ -n "$cur" && "$cur" -gt 0 ]]; then
        SAMPLES=$((SAMPLES + 1))
        if [[ "$cur" -gt "$MAX_RSS" ]]; then
          MAX_RSS="$cur"
        fi
      fi
    fi
    if ! kill -0 "$PROXY_PID" 2>/dev/null; then
      echo "FAIL: proxy died during $label stream" >&2
      tail -50 "$PROXY_LOG" >&2 || true
      wait "$CLIENT_PID" 2>/dev/null || true
      exit 1
    fi
    sleep 0.05
  done
  set +e
  wait "$CLIENT_PID"
  local CLIENT_RC=$?
  set -e
  local cur_line cur
  cur_line="$(mem_sample_kb "$PROXY_PID" "$MEM_SOURCE_PREF" || true)"
  if [[ -n "$cur_line" ]]; then
    cur="${cur_line%% *}"
    if [[ -n "$cur" && "$cur" -gt "$MAX_RSS" ]]; then
      MAX_RSS="$cur"
    fi
  fi

  if [[ "$CLIENT_RC" -ne 0 ]]; then
    echo "FAIL: $label client SELECT failed rc=$CLIENT_RC" >&2
    cat "$err_file" >&2 || true
    exit 1
  fi

  # Export for caller via globals.
  LAST_MAX_RSS="$MAX_RSS"
  LAST_SAMPLES="$SAMPLES"
}

# Auth on this config is static root/root for both listeners (backend still postgres/root).
MYSQL_CLIENT='docker run --rm --add-host=host.docker.internal:host-gateway mysql:8.0 mysql --ssl-mode=DISABLED -h host.docker.internal -P 9088 -uroot -proot -N -e "SELECT id, payload FROM stream_rss_t ORDER BY id;"'
PG_CLIENT='docker run --rm --add-host=host.docker.internal:host-gateway postgres:16-alpine env PGPASSWORD=root psql -h host.docker.internal -p 9089 -U root -d analytics -tAc "SELECT id || chr(124) || payload FROM stream_rss_t ORDER BY id;"'

run_stream_and_sample "mysql" "$MYSQL_CLIENT" /tmp/dn-stream-rss-mysql-err.txt
MYSQL_MAX_RSS="$LAST_MAX_RSS"
MYSQL_SAMPLES="$LAST_SAMPLES"

# Same process; keep baseline for absolute delta across both streams.
run_stream_and_sample "postgresql" "$PG_CLIENT" /tmp/dn-stream-rss-pg-err.txt
PG_MAX_RSS="$LAST_MAX_RSS"
PG_SAMPLES="$LAST_SAMPLES"

# Peak across both streams.
MAX_RSS="$MYSQL_MAX_RSS"
if [[ "$PG_MAX_RSS" -gt "$MAX_RSS" ]]; then
  MAX_RSS="$PG_MAX_RSS"
fi
SAMPLES=$((MYSQL_SAMPLES + PG_SAMPLES))

DELTA_KB=$((MAX_RSS - BASE_RSS))
if [[ "$DELTA_KB" -lt 0 ]]; then
  DELTA_KB=0
fi
FULL_EST_BYTES=$((N_ROWS * (PAYLOAD_LEN + 48)))
FULL_EST_KB=$((FULL_EST_BYTES / 1024))
BOUND_VS_FULL_KB=0
if [[ "${RSS_VS_FULL_MULT}" -gt 0 ]]; then
  BOUND_VS_FULL_KB=$((FULL_EST_KB * RSS_VS_FULL_MULT))
  if [[ "$BOUND_VS_FULL_KB" -lt 8192 ]]; then
    BOUND_VS_FULL_KB=8192
  fi
fi

echo "mem samples=$SAMPLES source=$MEM_SOURCE baseline_KiB=$BASE_RSS max_KiB=$MAX_RSS delta_KiB=$DELTA_KB"
echo "  mysql_max_KiB=$MYSQL_MAX_RSS samples=$MYSQL_SAMPLES | pg_max_KiB=$PG_MAX_RSS samples=$PG_SAMPLES"
if [[ "${RSS_VS_FULL_MULT}" -gt 0 ]]; then
  echo "full_result_est_KiB=$FULL_EST_KB bound_vs_full_KiB=$BOUND_VS_FULL_KB (×${RSS_VS_FULL_MULT}) cap_KiB=$RSS_DELTA_CAP_KB"
else
  echo "full_result_est_KiB=$FULL_EST_KB relative_bound=off cap_KiB=$RSS_DELTA_CAP_KB"
fi
echo "rows_per_backend=$N_ROWS window_rows=$WINDOW_ROWS (client bodies discarded)"

if [[ "$DELTA_KB" -gt "$RSS_DELTA_CAP_KB" ]]; then
  echo "FAIL: memory growth ${DELTA_KB} KiB exceeds absolute cap ${RSS_DELTA_CAP_KB} KiB (catastrophic materialize?)" >&2
  exit 1
fi
if [[ "${RSS_VS_FULL_MULT}" -gt 0 && "$DELTA_KB" -gt "$BOUND_VS_FULL_KB" ]]; then
  echo "FAIL: memory growth ${DELTA_KB} KiB exceeds full-result estimate×${RSS_VS_FULL_MULT} (${BOUND_VS_FULL_KB} KiB)" >&2
  echo "  (Streaming should not retain multi-full ResultSets; logical peak is still authoritative)" >&2
  exit 1
fi
echo "A06 memory sanity ok: delta under absolute cap (source=$MEM_SOURCE; not precise window bytes)"

echo "==> metrics: streaming path + multi-window encode + logical peak ≤ window_rows=${WINDOW_ROWS}"
metrics="$(curl -fsS http://127.0.0.1:8082/metrics || true)"
if ! echo "$metrics" | grep -q 'execute_path="streaming"'; then
  echo "FAIL: expected execute_path=streaming after large Streaming SELECT" >&2
  echo "$metrics" | grep 'gateway_execute_path_total' | head -12 || true
  exit 1
fi
# Dual-protocol: both frontend protocols should have streaming samples.
mysql_stream="$(echo "$metrics" | awk '/gateway_execute_path_total\{/ && /mysql/ && /execute_path="streaming"/ {print}' | head -1)"
pg_stream="$(echo "$metrics" | awk '/gateway_execute_path_total\{/ && /postgresql/ && /execute_path="streaming"/ {print}' | head -1)"
if [[ -z "$mysql_stream" ]]; then
  echo "FAIL: expected MySQL execute_path=streaming" >&2
  exit 1
fi
if [[ -z "$pg_stream" ]]; then
  echo "FAIL: expected PostgreSQL execute_path=streaming" >&2
  exit 1
fi
echo "dual-protocol streaming path ok"

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
# Multi-window: 50k rows / window 8 ⇒ thousands of windows; hard-fail if ≤1 (materialize/single-shot).
windows_sum="$(echo "$metrics" | awk '/gateway_encode_windows_total\{/ && !/^#/ { s+=$NF } END { print s+0 }')"
if awk "BEGIN { exit !($windows_sum > 1) }"; then
  :
else
  echo "FAIL: expected gateway_encode_windows_total sum > 1 for multi-window stream, got ${windows_sum}" >&2
  echo "$metrics" | grep 'gateway_encode_windows_total' | head -8 || true
  exit 1
fi
# Stronger: at least more windows than a single page would need for N_ROWS.
min_windows_expected=$((N_ROWS / WINDOW_ROWS / 4)) # allow heavy skip; still multi-window
if [[ "$min_windows_expected" -lt 2 ]]; then
  min_windows_expected=2
fi
if awk -v s="$windows_sum" -v m="$min_windows_expected" 'BEGIN { exit !(s >= m) }'; then
  :
else
  echo "FAIL: encode_windows sum=${windows_sum} < expected multi-window floor ${min_windows_expected}" >&2
  exit 1
fi
echo "encode_windows sum=${windows_sum} ≥ ${min_windows_expected} (multi-window stream)"
echo "$metrics" | grep 'gateway_encode_peak_window_rows' | head -8 || true
echo "$metrics" | grep 'gateway_encode_windows_total' | head -8 || true
echo "logical peak ≤ window_rows ok (authoritative; process/cgroup memory is coarse OS sanity only)"

# A06: logical peak window *bytes* (encode payload high-water of one window).
if ! echo "$metrics" | grep -q 'gateway_encode_peak_window_bytes'; then
  echo "FAIL: missing gateway_encode_peak_window_bytes" >&2
  exit 1
fi
peak_b_max="$(echo "$metrics" | awk '/gateway_encode_peak_window_bytes\{/ { v=$NF+0; if (v>m) m=v } END { print m+0 }')"
total_b_sum="$(echo "$metrics" | awk '/gateway_encode_bytes_total\{/ && !/^#/ { s+=$NF } END { print s+0 }')"
echo "peak_window_bytes_max=${peak_b_max} encode_bytes_sum=${total_b_sum}"
if ! awk -v p="$peak_b_max" 'BEGIN { exit !(p > 0) }'; then
  echo "FAIL: expected peak_window_bytes > 0" >&2
  exit 1
fi
# 50k-row multi-window: peak window payload must be << total encoded bytes.
if ! awk -v p="$peak_b_max" -v t="$total_b_sum" -v w="$windows_sum" 'BEGIN {
  if (w < 2) exit 1
  if (t <= 0 || p <= 0) exit 1
  # peak of one window should be well under total (allow 2× noise margin vs full total)
  if (p * 4 >= t) exit 1
  exit 0
}'; then
  echo "FAIL: peak_window_bytes=${peak_b_max} not clearly below encode_bytes_sum=${total_b_sum} (windows=${windows_sum})" >&2
  echo "  (logical window-byte peak; not process RSS / cgroup)" >&2
  exit 1
fi
echo "$metrics" | grep 'gateway_encode_peak_window_bytes' | head -8 || true
echo "A06 logical peak_window_bytes << total encode_bytes ok (not process RSS)"

echo "smoke-security-stream-rss: OK"
echo "NOTE: memory sample source=$MEM_SOURCE; catches full-result materialize regressions, not exact window bytes."
echo "NOTE: set DN_RSS_MEM_SOURCE=cgroup|proc|ps to force a source; DN_RSS_VS_FULL_MULT>0 enables relative bound."
