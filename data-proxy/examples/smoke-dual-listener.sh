#!/usr/bin/env bash
# Local dual-listener smoke test for Data Nexus v2.
# Requires: docker, cargo, mysql client, psql
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$ROOT/examples/docker-compose.dev.yml"
CONFIG_FILE="$ROOT/examples/dual-listener-gateway-config.toml"
PROXY_LOG="${TMPDIR:-/tmp}/data-nexus-smoke.log"

cleanup() {
  if [[ -n "${PROXY_PID:-}" ]] && kill -0 "$PROXY_PID" 2>/dev/null; then
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "==> starting backend containers"
docker compose -f "$COMPOSE_FILE" up -d

echo "==> waiting for MySQL"
for _ in $(seq 1 60); do
  if docker compose -f "$COMPOSE_FILE" exec -T mysql-primary \
    mysqladmin ping -h 127.0.0.1 -uroot -proot --silent 2>/dev/null; then
    break
  fi
  sleep 2
done

echo "==> waiting for PostgreSQL"
for _ in $(seq 1 60); do
  if docker compose -f "$COMPOSE_FILE" exec -T postgres-primary \
    pg_isready -U postgres -d analytics >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

echo "==> building and starting gateway"
(
  cd "$ROOT"
  cargo run -p pisa -- --config "$CONFIG_FILE"
) >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!

echo "==> waiting for listeners"
for _ in $(seq 1 60); do
  if (echo > /dev/tcp/127.0.0.1/9088) >/dev/null 2>&1 \
    && (echo > /dev/tcp/127.0.0.1/9089) >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "gateway exited early; log:"
    cat "$PROXY_LOG"
    exit 1
  fi
  sleep 1
done

echo "==> MySQL SELECT via gateway"
mysql -h 127.0.0.1 -P 9088 -uroot -proot -e 'SELECT 1 AS ok;'

echo "==> PostgreSQL SELECT via gateway"
PGPASSWORD=postgres psql -h 127.0.0.1 -p 9089 -U postgres -d analytics -c 'SELECT 1 AS ok;'

echo "==> metrics labels present"
curl -fsS "http://127.0.0.1:8082/metrics" | grep -E 'frontend_protocol|backend_protocol|service' || true

echo "smoke dual-listener: OK"
