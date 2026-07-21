#!/usr/bin/env bash
# Fail-closed config validate smoke (A08 TLS pin + B08 sample L2 gate).
# No DB required: daemon must refuse invalid configs before bind.
# Honesty: proves silent no-op configs are rejected at load, not at runtime.
set -euo pipefail

export PATH="/Volumes/fushilu/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin:/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:${HOME}/.cargo/bin:${PATH:-}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.94.1}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE_CFG="$ROOT/examples/security-deny-gateway-config.toml"
TMPDIR_SMOKE="${TMPDIR:-/tmp}/dn-config-validate-$$"
mkdir -p "$TMPDIR_SMOKE"
trap 'rm -rf "$TMPDIR_SMOKE"' EXIT

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing $1" >&2; exit 1; }; }
need cargo
need python3

PROXY_BIN="${CARGO_TARGET_DIR}/debug/proxy"
echo "==> ensure proxy binary"
(
  cd "$ROOT"
  if [[ ! -x "$PROXY_BIN" ]] \
    || [[ "$ROOT/gateway/core/src/security.rs" -nt "$PROXY_BIN" ]] \
    || [[ "$ROOT/gateway/core/src/config.rs" -nt "$PROXY_BIN" ]]; then
    cargo build -p data-proxy --bin proxy
  fi
  if [[ ! -x "$PROXY_BIN" ]]; then
    PROXY_BIN="/Volumes/fushilu/.caches/data-nexus/cargo-target/debug/proxy"
  fi
  [[ -x "$PROXY_BIN" ]]
)

run_expect_fail() {
  local label="$1"
  local cfg="$2"
  local needle="$3"
  local log="$TMPDIR_SMOKE/${label}.log"
  echo "==> expect fail: $label"
  set +e
  # Short timeout: validate fails before long-running listen; still cap hung starts.
  "$PROXY_BIN" daemon -c "$cfg" >"$log" 2>&1 &
  local pid=$!
  local i=0
  local rc=0
  while kill -0 "$pid" 2>/dev/null; do
    i=$((i + 1))
    if [[ $i -ge 40 ]]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      echo "FAIL: $label — process still alive after validate window" >&2
      cat "$log" >&2 || true
      exit 1
    fi
    sleep 0.1
  done
  wait "$pid"
  rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    echo "FAIL: $label — expected non-zero exit, got 0" >&2
    cat "$log" >&2 || true
    exit 1
  fi
  if ! grep -qiE "$needle" "$log"; then
    echo "FAIL: $label — log missing /$needle/" >&2
    cat "$log" >&2 || true
    exit 1
  fi
  echo "ok $label (rc=$rc)"
}

# --- B08: sample_enabled without L2 is a silent no-op if allowed; must reject ---
B08_CFG="$TMPDIR_SMOKE/b08-l0-sample.toml"
python3 - <<PY
from pathlib import Path
base = Path("$BASE_CFG").read_text()
# Force L0 + sample_enabled (invalid combination).
out = []
for line in base.splitlines():
    if line.strip().startswith("default_audit_level"):
        out.append('default_audit_level = "L0"')
    elif line.strip() == "[security.audit]":
        out.append(line)
        out.append("sample_enabled = true")
        out.append("sample_max_rows = 2")
        out.append("sample_max_bytes = 4096")
    else:
        out.append(line)
Path("$B08_CFG").write_text("\n".join(out) + "\n")
PY
run_expect_fail "b08-sample-requires-l2" "$B08_CFG" "sample_enabled|default_audit_level|L2"

# --- A08: require + verify without CA must reject (production pin) ---
A08_CFG="$TMPDIR_SMOKE/a08-require-no-ca.toml"
python3 - <<PY
from pathlib import Path
base = Path("$BASE_CFG").read_text()
lines = base.splitlines()
out = []
i = 0
while i < len(lines):
    line = lines[i]
    out.append(line)
    # After each [[endpoints]] block's protocol line, inject require TLS without CA.
    if line.strip().startswith("protocol ="):
        # insert ssl_mode require after address/database/user/password weight? better after protocol
        out.append('ssl_mode = "require"')
        out.append("ssl_accept_invalid_certs = false")
        # deliberately omit ssl_ca_file
    i += 1
Path("$A08_CFG").write_text("\n".join(out) + "\n")
PY
run_expect_fail "a08-require-verify-needs-ca" "$A08_CFG" "ssl_ca_file|ssl_mode=require|require"

# --- Sanity: valid base config starts (then we kill) ---
echo "==> sanity: valid config reaches admin (then stop)"
VALID_LOG="$TMPDIR_SMOKE/valid.log"
# Use unique ports so we don't collide with other smokes if any residual.
VALID_CFG="$TMPDIR_SMOKE/valid.toml"
python3 - <<PY
from pathlib import Path
t = Path("$BASE_CFG").read_text()
t = t.replace("port = 8082", "port = 18082")
t = t.replace("0.0.0.0:9088", "0.0.0.0:19088")
t = t.replace("0.0.0.0:9089", "0.0.0.0:19089")
t = t.replace("/tmp/data-nexus-audit-events.jsonl", "$TMPDIR_SMOKE/audit.jsonl")
t = t.replace("/tmp/data-nexus-audit-index.sqlite", "$TMPDIR_SMOKE/audit.sqlite")
t = t.replace("/tmp/data-nexus-audit-archive", "$TMPDIR_SMOKE/audit-archive")
Path("$VALID_CFG").write_text(t)
PY
"$PROXY_BIN" daemon -c "$VALID_CFG" >"$VALID_LOG" 2>&1 &
VALID_PID=$!
ok=0
for _ in $(seq 1 80); do
  if curl -fsS "http://127.0.0.1:18082/healthz" >/dev/null 2>&1; then
    ok=1
    break
  fi
  if ! kill -0 "$VALID_PID" 2>/dev/null; then
    echo "FAIL: valid config exited early" >&2
    cat "$VALID_LOG" >&2 || true
    exit 1
  fi
  sleep 0.15
done
if [[ $ok -ne 1 ]]; then
  echo "FAIL: valid config never became healthy" >&2
  cat "$VALID_LOG" >&2 || true
  kill "$VALID_PID" 2>/dev/null || true
  wait "$VALID_PID" 2>/dev/null || true
  exit 1
fi
kill "$VALID_PID" 2>/dev/null || true
wait "$VALID_PID" 2>/dev/null || true
echo "valid config started ok (stopped)"

echo "smoke-security-config-validate: OK"
