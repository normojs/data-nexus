#!/usr/bin/env bash
# H02: run grouped smoke tests for Data Nexus.
#
# Usage:
#   ./examples/run-smoke-matrix.sh              # default: l0 + security-core
#   ./examples/run-smoke-matrix.sh l0
#   ./examples/run-smoke-matrix.sh security-core
#   ./examples/run-smoke-matrix.sh security-extended
#   ./examples/run-smoke-matrix.sh cedar         # needs --features security-cedar binary build
#   ./examples/run-smoke-matrix.sh all
#   ./examples/run-smoke-matrix.sh list
#
# Env:
#   CARGO_TARGET_DIR   default from .cargo/config.toml or volume path
#   DN_SMOKE_KEEP_GOING=1  continue after a failure (still exit non-zero)
#   DN_SMOKE_TIMEOUT_SECS  per-script timeout (default 900; 0 = no timeout)
#
# Requirements: docker, cargo, curl, python3; rustc ≥1.88 recommended for cedar.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXAMPLES="$ROOT/examples"
# Prefer rustc 1.94.1 (MSRV for time/cedar); fall back to project toolchain.
export PATH="/Volumes/fushilu/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin:/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:${HOME}/.cargo/bin:/Volumes/fushilu/.rustup/toolchains/nightly-2025-01-07-aarch64-apple-darwin/bin:${PATH:-}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"
export RUSTUP_HOME="${RUSTUP_HOME:-${HOME}/.rustup}"
export CARGO_HOME="${CARGO_HOME:-${HOME}/.cargo}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.94.1}"

KEEP_GOING="${DN_SMOKE_KEEP_GOING:-0}"
TIMEOUT_SECS="${DN_SMOKE_TIMEOUT_SECS:-900}"

GROUP="${1:-default}"

list_groups() {
  cat <<'EOF'
Groups:
  l0                  L0 / security-off path (admin-auth, dual-listener, cross-protocol x2)
  security-core       deny, column, mask, audit, audit-sample, ticket, portal, vault, state-file
  security-extended   stream, passthrough, watermark, dual-control, time, xproto-stream, portal-xproto×2
  cedar               cedar + cedar-reload (build with --features security-cedar)
  default             l0 + security-core
  all                 default + security-extended (not cedar)
  list                show this help
EOF
}

if [[ "$GROUP" == "list" || "$GROUP" == "-h" || "$GROUP" == "--help" ]]; then
  list_groups
  exit 0
fi

l0_smokes=(
  smoke-admin-auth.sh
  smoke-dual-listener.sh
  smoke-cross-protocol.sh
  smoke-cross-protocol-pg-to-mysql.sh
)

security_core_smokes=(
  smoke-security-deny.sh
  smoke-security-column.sh
  smoke-security-mask.sh
  smoke-security-audit.sh
  smoke-security-audit-sample.sh
  smoke-security-ticket.sh
  smoke-security-portal.sh
  smoke-security-vault.sh
  smoke-security-state-file.sh
)

security_extended_smokes=(
  smoke-security-stream.sh
  smoke-security-passthrough.sh
  smoke-security-watermark.sh
  smoke-security-dual-control.sh
  smoke-security-time.sh
  smoke-cross-protocol-stream.sh
  smoke-security-portal-xproto.sh
  smoke-security-portal-xproto-pg-mysql.sh
)

cedar_smokes=(
  smoke-security-cedar.sh
  smoke-security-cedar-reload.sh
)

resolve_scripts() {
  case "$1" in
    l0) printf '%s\n' "${l0_smokes[@]}" ;;
    security-core) printf '%s\n' "${security_core_smokes[@]}" ;;
    security-extended) printf '%s\n' "${security_extended_smokes[@]}" ;;
    cedar) printf '%s\n' "${cedar_smokes[@]}" ;;
    default)
      printf '%s\n' "${l0_smokes[@]}"
      printf '%s\n' "${security_core_smokes[@]}"
      ;;
    all)
      printf '%s\n' "${l0_smokes[@]}"
      printf '%s\n' "${security_core_smokes[@]}"
      printf '%s\n' "${security_extended_smokes[@]}"
      ;;
    *)
      echo "unknown group: $1" >&2
      list_groups >&2
      exit 2
      ;;
  esac
}

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }; }
need bash
need docker
need cargo
need curl
need python3

run_one() {
  local script="$1"
  local path="$EXAMPLES/$script"
  if [[ ! -x "$path" && -f "$path" ]]; then
    chmod +x "$path" || true
  fi
  if [[ ! -f "$path" ]]; then
    echo "MISSING $script" >&2
    return 1
  fi
  echo ""
  echo "======== RUN $script ========"
  local start end rc
  start=$(date +%s)
  set +e
  if [[ "$TIMEOUT_SECS" != "0" ]] && command -v timeout >/dev/null 2>&1; then
    timeout "${TIMEOUT_SECS}s" bash "$path"
    rc=$?
  elif [[ "$TIMEOUT_SECS" != "0" ]] && command -v gtimeout >/dev/null 2>&1; then
    gtimeout "${TIMEOUT_SECS}s" bash "$path"
    rc=$?
  else
    bash "$path"
    rc=$?
  fi
  set -e
  end=$(date +%s)
  echo "======== END $script rc=$rc elapsed=$((end - start))s ========"
  return "$rc"
}

SCRIPTS=()
while IFS= read -r _line; do
  [[ -n "$_line" ]] && SCRIPTS+=("$_line")
done < <(resolve_scripts "$GROUP")
# bash 3 (macOS) lacks mapfile; also support plain pipelines without process substitution fallback:
if [[ ${#SCRIPTS[@]} -eq 0 ]]; then
  # fallback without process substitution
  _tmp="$(mktemp)"
  resolve_scripts "$GROUP" >"$_tmp"
  while IFS= read -r _line; do
    [[ -n "$_line" ]] && SCRIPTS+=("$_line")
  done <"$_tmp"
  rm -f "$_tmp"
fi

echo "smoke matrix group=$GROUP count=${#SCRIPTS[@]}"
echo "CARGO_TARGET_DIR=$CARGO_TARGET_DIR"
echo "rustc: $(rustc --version 2>/dev/null || echo unknown)"

failed=()
passed=()
for s in "${SCRIPTS[@]}"; do
  if run_one "$s"; then
    passed+=("$s")
  else
    failed+=("$s")
    if [[ "$KEEP_GOING" != "1" ]]; then
      echo "FAIL fast on $s (set DN_SMOKE_KEEP_GOING=1 to continue)" >&2
      break
    fi
  fi
done

echo ""
echo "======== SUMMARY ========"
echo "passed (${#passed[@]}): ${passed[*]:-}"
echo "failed (${#failed[@]}): ${failed[*]:-}"
if [[ "${#failed[@]}" -gt 0 ]]; then
  exit 1
fi
echo "smoke-matrix: OK ($GROUP)"

