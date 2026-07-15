# Data UI

Nuxt 3 admin console for **Data Nexus** gateway.

Consumes the gateway Admin HTTP API (default `http://127.0.0.1:8082`).

## Prerequisites

- Node 18+
- pnpm (or npm)
- Running Data Nexus proxy with Admin port open

## Configure

| Variable | Default | Purpose |
|----------|---------|---------|
| `NUXT_PUBLIC_ADMIN_API_BASE` | `http://127.0.0.1:8082` | Gateway Admin API base URL |

Gateway CORS is enabled by default for browser UIs. Restrict with:

```bash
export DATA_NEXUS_ADMIN_CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
```

## Develop

```bash
# terminal 1 – gateway
cd ../data-proxy
cargo run -p data-proxy --bin proxy -- daemon -c examples/dual-listener-gateway-config.toml

# terminal 2 – UI
cd ../data-ui
pnpm install
pnpm dev
```

Open `http://localhost:3000`.

## Features

- Live listeners / services / endpoints / pools / sessions
- Configurable API base URL
- `POST /admin/reload`
- Links to `/metrics` and embedded `/admin` HTML

## Embedded alternative

Gateway also serves a zero-dependency page at:

```text
GET http://127.0.0.1:8082/admin
```
