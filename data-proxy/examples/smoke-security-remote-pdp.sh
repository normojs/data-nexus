#!/usr/bin/env bash
# F31: Remote PDP HTTP gate (table/action) + fail_closed honesty.
# Local mock answers allow/deny; PEP still owns mask/row obligations (not tested here).
# Not a full OPA/Cedar suite — only proves remote wiring is not a silent no-op.
set -euo pipefail

export PATH="/Volumes/fushilu/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin:/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:${HOME}/.cargo/bin:${PATH:-}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.94.1}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$ROOT/examples/docker-compose.dev.yml"
BASE_CFG="$ROOT/examples/security-deny-gateway-config.toml"
PROXY_LOG="${TMPDIR:-/tmp}/data-nexus-security-remote-pdp.log"
MOCK_LOG="${TMPDIR:-/tmp}/data-nexus-remote-pdp-mock.log"
MOCK_PORT=18181
TMPDIR_SMOKE="${TMPDIR:-/tmp}/dn-remote-pdp-$$"
mkdir -p "$TMPDIR_SMOKE"
COMPOSE=(docker compose -f "$COMPOSE_FILE")

cleanup() {
  if [[ -n "${PROXY_PID:-}" ]] && kill -0 "$PROXY_PID" 2>/dev/null; then
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
  if [[ -n "${MOCK_PID:-}" ]] && kill -0 "$MOCK_PID" 2>/dev/null; then
    kill "$MOCK_PID" 2>/dev/null || true
    wait "$MOCK_PID" 2>/dev/null || true
  fi
  rm -rf "$TMPDIR_SMOKE"
}
trap cleanup EXIT

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing $1" >&2; exit 1; }; }
need docker; need cargo; need curl; need python3

pkill -f '/debug/proxy' 2>/dev/null || true
# free mock port if leftover
pkill -f "18181" 2>/dev/null || true
sleep 1

echo "==> start backends"
"${COMPOSE[@]}" up -d
for _ in $(seq 1 90); do
  "${COMPOSE[@]}" exec -T mysql-primary mysqladmin ping -h 127.0.0.1 -uroot -proot --silent 2>/dev/null && break
  sleep 2
done

echo "==> start Remote PDP mock on :${MOCK_PORT}"
python3 - <<'PY' >"$MOCK_LOG" 2>&1 &
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class H(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("[mock]", fmt % args, flush=True)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            body = {}
        tables = body.get("tables") or []
        joined = " ".join(str(t) for t in tables).lower()
        # Deny any secret_* table; allow everything else (including empty tables / SELECT 1).
        if "secret" in joined:
            resp = {
                "allow": False,
                "rule": "remote-deny-secret",
                "message": "F31 mock denies secret tables",
            }
        else:
            resp = {"allow": True, "rule": "remote-allow"}
        data = json.dumps(resp).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

HTTPServer(("127.0.0.1", 18181), H).serve_forever()
PY
MOCK_PID=$!
for _ in $(seq 1 50); do
  if curl -fsS -X POST "http://127.0.0.1:${MOCK_PORT}/v1/data_nexus" \
    -H 'content-type: application/json' \
    -d '{"subject_id":"t","service":"orders","action":"select","tables":[]}' >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

write_remote_cfg() {
  local out_path="$1"
  local remote_url="$2"
  local fail_closed="$3"
  python3 - "$BASE_CFG" "$out_path" "$remote_url" "$fail_closed" "$TMPDIR_SMOKE" <<'PY'
import re, sys
from pathlib import Path
base_path, out_path, remote_url, fail_closed, tmp = sys.argv[1:6]
base = Path(base_path).read_text()
lines = []
skip_rules = False
for line in base.splitlines():
    s = line.strip()
    if s.startswith("[[security.rules]]"):
        skip_rules = True
        continue
    if skip_rules:
        if s.startswith("[["):
            skip_rules = False
            lines.append(line)
        continue
    lines.append(line)
text = "\n".join(lines) + "\n"
block = f'''[security.pdp]
backend = "remote"
remote_url = "{remote_url}"
remote_timeout_ms = 500
remote_fail_closed = {fail_closed}

'''
text2, n = re.subn(r"\[security\.pdp\]\n(?:.*\n)*?(?=\[|\Z)", block, text, count=1)
if n != 1:
    raise SystemExit(f"failed to rewrite pdp block n={n}")
text2 = text2.replace("/tmp/data-nexus-audit-events.jsonl", f"{tmp}/audit.jsonl")
text2 = text2.replace("/tmp/data-nexus-audit-index.sqlite", f"{tmp}/audit.sqlite")
text2 = text2.replace("/tmp/data-nexus-audit-archive", f"{tmp}/audit-archive")
Path(out_path).write_text(text2)
print("wrote", out_path)
PY
}

CFG_OK="$TMPDIR_SMOKE/remote-ok.toml"
write_remote_cfg "$CFG_OK" "http://127.0.0.1:${MOCK_PORT}/v1/data_nexus" "true"

echo "==> start gateway (backend=remote → mock)"
PROXY_BIN="${CARGO_TARGET_DIR}/debug/proxy"
(
  cd "$ROOT"
  if [[ ! -x "$PROXY_BIN" ]] \
    || [[ "$ROOT/gateway/core/src/remote_pdp.rs" -nt "$PROXY_BIN" ]] \
    || [[ "$ROOT/gateway/core/src/pdp.rs" -nt "$PROXY_BIN" ]] \
    || [[ "$ROOT/http/src/http/mod.rs" -nt "$PROXY_BIN" ]]; then
    cargo build -p data-proxy --bin proxy
  fi
  if [[ ! -x "$PROXY_BIN" ]]; then
    PROXY_BIN="/Volumes/fushilu/.caches/data-nexus/cargo-target/debug/proxy"
  fi
  # exec so PROXY_PID is the proxy process (kill/wait work across restarts).
  exec "$PROXY_BIN" daemon -c "$CFG_OK"
) >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!

for _ in $(seq 1 120); do
  curl -fsS "http://127.0.0.1:8082/admin/security-policies" >/dev/null 2>&1 && break
  kill -0 "$PROXY_PID" 2>/dev/null || { cat "$PROXY_LOG"; exit 1; }
  sleep 0.25
done

mysql_via_gateway() {
  docker run --rm --add-host=host.docker.internal:host-gateway mysql:8.0 \
    mysql --ssl-mode=DISABLED -h host.docker.internal -P 9088 -uroot -proot -N -e "$1"
}

echo "==> security-policies exposes F31 remote knobs (no token/url values)"
curl -fsS "http://127.0.0.1:8082/admin/security-policies" | tee /tmp/dn-remote-policies.json >/dev/null
python3 - <<'PY'
import json
data=json.load(open("/tmp/dn-remote-policies.json"))
assert data.get("pdp_backend") == "remote" or (data.get("pdp") or {}).get("backend") == "remote", data
pdp=data.get("pdp") or {}
assert pdp.get("remote_configured") is True, pdp
assert pdp.get("remote_fail_closed") is True, pdp
assert "remote_url" not in pdp and "remote_token" not in pdp, pdp
print("policies remote ok", pdp)
PY

echo "==> allow: SELECT 1 via remote allow"
out="$(mysql_via_gateway 'SELECT 1 AS ok;')"
echo "$out" | tr -d '[:space:]' | grep -qx '1'

echo "==> deny: secret table via remote mock (not local rules)"
set +e
mysql_via_gateway 'SELECT id FROM secret_tokens;' >/tmp/dn-remote-secret-err.txt 2>&1
rc=$?
set -e
[[ $rc -ne 0 ]]
grep -qiE 'security|denied|remote|secret|ERROR' /tmp/dn-remote-secret-err.txt
echo "remote deny secret ok"
head -3 /tmp/dn-remote-secret-err.txt || true

echo "==> restart with dead remote_url (fail_closed=true → deny)"
kill "$PROXY_PID" 2>/dev/null || true
wait "$PROXY_PID" 2>/dev/null || true
PROXY_PID=""
# Ensure nothing still holds 8082/9088 from a leaked child.
pkill -f '/debug/proxy' 2>/dev/null || true
sleep 1

CFG_DEAD="$TMPDIR_SMOKE/remote-dead.toml"
write_remote_cfg "$CFG_DEAD" "http://127.0.0.1:1/v1/data_nexus" "true"

(
  cd "$ROOT"
  PROXY_BIN="${CARGO_TARGET_DIR}/debug/proxy"
  [[ -x "$PROXY_BIN" ]] || PROXY_BIN="/Volumes/fushilu/.caches/data-nexus/cargo-target/debug/proxy"
  exec "$PROXY_BIN" daemon -c "$CFG_DEAD"
) >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!

for _ in $(seq 1 120); do
  curl -fsS "http://127.0.0.1:8082/admin/security-policies" >/dev/null 2>&1 && break
  kill -0 "$PROXY_PID" 2>/dev/null || { cat "$PROXY_LOG"; exit 1; }
  sleep 0.25
done

# Confirm still remote + fail_closed after restart.
curl -fsS "http://127.0.0.1:8082/admin/security-policies" | tee /tmp/dn-remote-dead-policies.json >/dev/null
python3 - <<'PY'
import json
data=json.load(open("/tmp/dn-remote-dead-policies.json"))
pdp=data.get("pdp") or {}
assert (data.get("pdp_backend") == "remote") or pdp.get("backend") == "remote", data
assert pdp.get("remote_fail_closed") is True, pdp
print("dead-url policies", pdp)
PY

set +e
mysql_via_gateway 'SELECT 1 AS ok;' >/tmp/dn-remote-failclosed.txt 2>&1
rc_fc=$?
set -e
if [[ $rc_fc -eq 0 ]]; then
  echo "FAIL: expected deny when remote_url is dead and remote_fail_closed=true" >&2
  cat /tmp/dn-remote-failclosed.txt >&2 || true
  exit 1
fi
grep -qiE 'security|denied|remote|ERROR|timeout|transport|pdp' /tmp/dn-remote-failclosed.txt \
  || {
    echo "FAIL: deny output should mention remote/security; got:" >&2
    cat /tmp/dn-remote-failclosed.txt >&2 || true
    exit 1
  }
echo "fail_closed deny on dead remote ok (rc=$rc_fc)"
head -5 /tmp/dn-remote-failclosed.txt || true

echo "smoke-security-remote-pdp: OK"
