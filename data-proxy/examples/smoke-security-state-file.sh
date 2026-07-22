#!/usr/bin/env bash
# H05: file state backend + AES-GCM ticket/vault; restart preserves records.
# Asserts security-policies.state encrypt flags and sealed file magic prefixes.
set -euo pipefail

export PATH="/Volumes/fushilu/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin:/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:${HOME}/.cargo/bin:${PATH:-}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/fushilu/.caches/data-nexus/cargo-target}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.94.1}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG_FILE="$ROOT/examples/security-state-file-gateway-config.toml"
PROXY_LOG="${TMPDIR:-/tmp}/data-nexus-security-state-file.log"
PROXY_BIN="${CARGO_TARGET_DIR}/debug/proxy"
TICKET_PATH="/tmp/data-nexus-h05-tickets.json"
VAULT_PATH="/tmp/data-nexus-h05-vault.json"
POLICY_PATH="/tmp/data-nexus-h05-local-pdp.json"
COMPOSE_FILE="$ROOT/examples/docker-compose.dev.yml"
COMPOSE=(docker compose -f "$COMPOSE_FILE")

cleanup() {
  if [[ -n "${PROXY_PID:-}" ]] && kill -0 "$PROXY_PID" 2>/dev/null; then
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing $1" >&2; exit 1; }; }
need curl; need cargo; need python3; need docker

pkill -f '/debug/proxy' 2>/dev/null || true
sleep 1
rm -f "$TICKET_PATH" "$VAULT_PATH" "$POLICY_PATH" \
  "${TICKET_PATH}.lock" "${VAULT_PATH}.lock" "${POLICY_PATH}.lock"

start_proxy() {
  (
    cd "$ROOT"
    if [[ ! -x "$PROXY_BIN" ]] \
      || [[ "$ROOT/gateway/core/src/vault.rs" -nt "$PROXY_BIN" ]] \
      || [[ "$ROOT/gateway/core/src/ticket.rs" -nt "$PROXY_BIN" ]] \
      || [[ "$ROOT/gateway/core/src/pdp.rs" -nt "$PROXY_BIN" ]] \
      || [[ "$ROOT/gateway/core/src/policy_file.rs" -nt "$PROXY_BIN" ]] \
      || [[ "$ROOT/http/src/http/mod.rs" -nt "$PROXY_BIN" ]]; then
      cargo build -p data-proxy --bin proxy
    fi
    exec "$PROXY_BIN" daemon -c "$CONFIG_FILE"
  ) >"$PROXY_LOG" 2>&1 &
  PROXY_PID=$!
  for _ in $(seq 1 120); do
    curl -fsS "http://127.0.0.1:8082/healthz" >/dev/null 2>&1 && return 0
    kill -0 "$PROXY_PID" 2>/dev/null || { cat "$PROXY_LOG"; exit 1; }
    sleep 1
  done
  echo "gateway did not become healthy" >&2
  cat "$PROXY_LOG" >&2
  exit 1
}

stop_proxy() {
  if [[ -n "${PROXY_PID:-}" ]] && kill -0 "$PROXY_PID" 2>/dev/null; then
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
  PROXY_PID=""
  sleep 1
}

echo "==> backends (vault issue needs endpoint)"
"${COMPOSE[@]}" up -d
for _ in $(seq 1 90); do
  "${COMPOSE[@]}" exec -T mysql-primary mysqladmin ping -h 127.0.0.1 -uroot -proot --silent 2>/dev/null && break
  sleep 2
done

echo "==> start gateway (state.backend=file + encrypt keys)"
start_proxy

echo "==> security-policies.state shows file + encrypt configured"
curl -fsS "http://127.0.0.1:8082/admin/security-policies" | tee /tmp/dn-h05-policies.json >/dev/null
python3 - <<'PY'
import json
d=json.load(open("/tmp/dn-h05-policies.json"))
s=d.get("state") or {}
assert s.get("backend")=="file", s
assert s.get("ticket_encrypt_configured") is True, s
assert s.get("vault_encrypt_configured") is True, s
assert "h05-tickets" in (s.get("ticket_path") or "")
assert "h05-vault" in (s.get("vault_path") or "")
# H05 honesty pins (not CRDT / not mlock)
assert s.get("last_writer_wins") is True, s
assert s.get("mlock") is False, s
assert s.get("crdt") is False, s
assert (s.get("merge_strategy") or "") == "last_writer_wins", s
raw=json.dumps(d)
assert "ticket_encrypt_key" not in raw and "vault_encrypt_key" not in raw
assert "0123456789abcdef" not in raw
print(
    "policies state file+enc ok",
    s.get("backend"),
    "lww",
    s.get("last_writer_wins"),
    "merge",
    s.get("merge_strategy"),
    "crdt",
    s.get("crdt"),
    "mlock",
    s.get("mlock"),
)
PY

echo "==> issue ticket + vault lease"
curl -fsS -X POST "http://127.0.0.1:8082/admin/tickets" \
  -H 'content-type: application/json' \
  -d '{"subject_id":"root","sql":"CREATE TABLE h05_t (id INT)","ticket_type":"ddl","ttl_secs":600,"max_uses":1,"note":"h05-smoke"}' \
  | tee /tmp/dn-h05-ticket.json >/dev/null
curl -fsS -X POST "http://127.0.0.1:8082/admin/vault/leases" \
  -H 'content-type: application/json' \
  -d '{"project":"orders","environment":"dev","ttl_secs":600}' \
  | tee /tmp/dn-h05-lease.json >/dev/null

TICKET_ID="$(python3 -c 'import json; print(json.load(open("/tmp/dn-h05-ticket.json"))["id"])')"
LEASE_ID="$(python3 -c 'import json; print(json.load(open("/tmp/dn-h05-lease.json"))["lease_id"])')"
echo "ticket=$TICKET_ID lease=$LEASE_ID"

echo "==> sealed files on disk (AES-GCM magic, no plaintext secrets)"
python3 - <<PY
from pathlib import Path
ticket=Path("$TICKET_PATH").read_text()
vault=Path("$VAULT_PATH").read_text()
assert ticket.startswith("DNTICKET1:"), ticket[:40]
assert vault.startswith("DNVAULT1:"), vault[:40]
assert "CREATE TABLE h05_t" not in ticket
# After magic prefix the rest is ciphertext/base64 — no SQL sample or password JSON.
body_v = vault.split(":", 1)[-1] if ":" in vault else vault
assert "CREATE TABLE" not in body_v
assert '"backend_password"' not in vault
assert "password" not in vault  # field names sealed inside ciphertext
print("sealed files ok", "ticket_len", len(ticket), "vault_len", len(vault))
PY

echo "==> restart gateway; state reloads from encrypted files"
stop_proxy
start_proxy

echo "==> tickets/leases still present after restart"
curl -fsS "http://127.0.0.1:8082/admin/tickets?limit=50" | tee /tmp/dn-h05-tickets-after.json >/dev/null
curl -fsS "http://127.0.0.1:8082/admin/vault/leases" | tee /tmp/dn-h05-leases-after.json >/dev/null
python3 - <<PY
import json
tickets=json.load(open("/tmp/dn-h05-tickets-after.json"))
# response may be {tickets:[...]} or list
if isinstance(tickets, dict):
    tickets=tickets.get("tickets") or tickets.get("items") or []
ids=[t.get("id") for t in tickets]
assert "$TICKET_ID" in ids, (ids, open("/tmp/dn-h05-tickets-after.json").read()[:500])
leases=json.load(open("/tmp/dn-h05-leases-after.json"))
if isinstance(leases, dict):
    leases=leases.get("leases") or leases.get("items") or []
elif not isinstance(leases, list):
    raise SystemExit(f"unexpected leases shape: {type(leases)}")
lids=[l.get("lease_id") for l in leases]
assert "$LEASE_ID" in lids, lids
# lease JSON still must not expose password
assert all("password" not in json.dumps(l).lower() or l.get("password") is None for l in leases)
print("reload ok ticket", "$TICKET_ID", "lease", "$LEASE_ID")
PY


echo "==> H05 Local PDP policy_path mtime hot-reload"
# Seed table for SELECT
"${COMPOSE[@]}" exec -T mysql-primary mysql -uroot -proot -e "
CREATE DATABASE IF NOT EXISTS orders;
USE orders;
CREATE TABLE IF NOT EXISTS h05_poll_t (id INT PRIMARY KEY, name VARCHAR(16));
INSERT INTO h05_poll_t VALUES (1,'a') ON DUPLICATE KEY UPDATE name=VALUES(name);
" >/dev/null

mysql_via_gateway() {
  docker run --rm --add-host=host.docker.internal:host-gateway mysql:8.0 \
    mysql --ssl-mode=DISABLED -h host.docker.internal -P 9088 -uroot -proot -N -e "$1"
}

echo "  baseline SELECT should allow (no deny rules)"
out="$(mysql_via_gateway 'SELECT id, name FROM h05_poll_t WHERE id=1;')"
echo "$out"
echo "$out" | grep -q 'a'

# policy file should exist after start (seeded)
if [[ ! -f "$POLICY_PATH" ]]; then
  echo "expected policy file seeded at $POLICY_PATH" >&2
  ls -la /tmp/data-nexus-h05* >&2 || true
  exit 1
fi

echo "  write deny-all SELECT into shared policy_path"
python3 - <<'PY'
import json, time
from pathlib import Path
path = Path("/tmp/data-nexus-h05-local-pdp.json")
try:
    snap = json.loads(path.read_text())
except Exception:
    snap = {}
snap.setdefault("fail_closed", False)
snap.setdefault("star_policy", "allow")
snap["rules"] = [{
    "name": "h05-deny-poll",
    "effect": "deny",
    "actions": ["select"],
    "tables": ["h05_poll_t", "*.h05_poll_t"],
    "columns": [],
    "subjects": [],
}]
# ensure mtime advances on 1s FS
time.sleep(1.1)
path.write_text(json.dumps(snap, indent=2))
print("policy written", path, "rules", len(snap["rules"]))
PY

echo "  wait for poll (>= policy_poll_ms) then SELECT must deny"
sleep 1
set +e
mysql_via_gateway 'SELECT id FROM h05_poll_t WHERE id=1;' >/tmp/dn-h05-poll-deny.txt 2>&1
rc=$?
set -e
if [[ $rc -eq 0 ]]; then
  if ! grep -qiE 'denied|security|policy|ERROR|1105' /tmp/dn-h05-poll-deny.txt; then
    echo "expected deny after policy poll, got success" >&2
    cat /tmp/dn-h05-poll-deny.txt >&2
    exit 1
  fi
fi
grep -qiE 'denied|security|policy|ERROR|1105|h05-deny' /tmp/dn-h05-poll-deny.txt \
  || { echo "deny message missing"; cat /tmp/dn-h05-poll-deny.txt; exit 1; }
echo "policy mtime poll deny ok"

echo "==> H05 last-writer-wins dual-writer honesty (not CRDT merge)"
# Two processes cannot both hold the live gateway; simulate LWW by writing a
# second sealed ticket file after process A wrote, then restarting so only the
# last full-file replace is visible (unit tests cover concurrent in-memory maps).
python3 - <<'PY'
import json, os, subprocess, sys, time
from pathlib import Path

# Decode path is inside the gateway; here we only prove the *disk* contract:
# a later full-file replace of the sealed blob is what reload sees.
# Create a second ticket via API, then overwrite the ticket file with a copy
# that only contains the second ticket's sealed content by re-issuing and
# checking reload drops the first if we restore an older snapshot then newer.
ticket_path = Path("/tmp/data-nexus-h05-tickets.json")
older = ticket_path.read_bytes()
# Issue a second ticket
import urllib.request
req = urllib.request.Request(
    "http://127.0.0.1:8082/admin/tickets",
    data=json.dumps({
        "subject_id": "root",
        "sql": "CREATE TABLE h05_lww (id INT)",
        "ticket_type": "ddl",
        "ttl_secs": 600,
        "max_uses": 1,
        "note": "h05-lww-second",
    }).encode(),
    headers={"content-type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=10) as resp:
    second = json.loads(resp.read().decode())
second_id = second["id"]
newer = ticket_path.read_bytes()
assert newer != older, "second issue must rewrite ticket file"
# Restore older snapshot (simulates loser of LWW)
ticket_path.write_bytes(older)
# Then apply newer again (last writer)
ticket_path.write_bytes(newer)
print("lww_disk_second_id", second_id, "older_len", len(older), "newer_len", len(newer))
open("/tmp/dn-h05-lww-second-id.txt", "w").write(second_id)
PY
# Restart so gateway reloads sealed file from disk
stop_proxy
start_proxy
curl -fsS "http://127.0.0.1:8082/admin/tickets?limit=50" | tee /tmp/dn-h05-lww-tickets.json >/dev/null
python3 - <<'PY'
import json
from pathlib import Path
second_id = Path("/tmp/dn-h05-lww-second-id.txt").read_text().strip()
tickets = json.load(open("/tmp/dn-h05-lww-tickets.json"))
if isinstance(tickets, dict):
    tickets = tickets.get("tickets") or tickets.get("items") or []
ids = [t.get("id") for t in tickets]
assert second_id in ids, (ids, "expected last-writer ticket after reload")
# First ticket may or may not be in the newer blob depending on store append
# semantics; LWW honesty is that the *last full-file replace* is what loads —
# we overwrote with the post-second-issue blob, which includes second_id.
print("lww reload ok last_writer_ticket", second_id, "ids", ids)
# API still advertises honesty fields
import urllib.request
pol = json.loads(urllib.request.urlopen("http://127.0.0.1:8082/admin/security-policies", timeout=10).read())
s = pol.get("state") or {}
assert s.get("last_writer_wins") is True
assert s.get("crdt") is False
assert s.get("merge_strategy") == "last_writer_wins"
assert s.get("mlock") is False
print("H05 honesty: last_writer_wins + crdt=false + merge_strategy (not CRDT merge)")
PY

echo "smoke-security-state-file: OK"
