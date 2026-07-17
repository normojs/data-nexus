#!/usr/bin/env bash
# Render examples/prod/gateway.example.toml using env vars (no secrets in git).
# Requires: bash. Prefers envsubst; falls back to python3.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TEMPLATE="${DN_PROD_TEMPLATE:-$ROOT/examples/prod/gateway.example.toml}"

if [[ ! -f "$TEMPLATE" ]]; then
  echo "missing template: $TEMPLATE" >&2
  exit 1
fi

required=(
  DN_JWT_SECRET
  DN_BREAK_GLASS_PASSWORD
  DN_MYSQL_HOST
  DN_MYSQL_PORT
  DN_MYSQL_DATABASE
  DN_MYSQL_USER
  DN_MYSQL_PASSWORD
  DN_PG_HOST
  DN_PG_PORT
  DN_PG_DATABASE
  DN_PG_USER
  DN_PG_PASSWORD
)

missing=0
for v in "${required[@]}"; do
  if [[ -z "${!v:-}" ]]; then
    echo "missing env: $v" >&2
    missing=1
  fi
done
if [[ "$missing" -ne 0 ]]; then
  echo "source examples/prod/env.example (after filling secrets) first" >&2
  exit 1
fi

# Reject unreplaced placeholders if someone used empty env by mistake
if [[ "$DN_JWT_SECRET" == replace* ]] || [[ "$DN_MYSQL_PASSWORD" == replace* ]]; then
  echo "warning: placeholder-looking secrets detected; ensure this is not production" >&2
fi

python3 - "$TEMPLATE" <<'PY'
import os, sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
keys = [
  "DN_JWT_SECRET", "DN_BREAK_GLASS_PASSWORD",
  "DN_MYSQL_HOST", "DN_MYSQL_PORT", "DN_MYSQL_DATABASE", "DN_MYSQL_USER", "DN_MYSQL_PASSWORD",
  "DN_PG_HOST", "DN_PG_PORT", "DN_PG_DATABASE", "DN_PG_USER", "DN_PG_PASSWORD",
]
for k in keys:
    text = text.replace("__" + k + "__", os.environ[k])
if "__DN_" in text:
    sys.stderr.write("unreplaced placeholders remain in template\n")
    sys.exit(1)
sys.stdout.write(text)
PY
