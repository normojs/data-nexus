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
| `NUXT_PUBLIC_ADMIN_PASSWORD` | _(empty)_ | Optional UI password; empty disables login |

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
# with password gate:
# NUXT_PUBLIC_ADMIN_PASSWORD=secret pnpm dev
```

Open `http://localhost:3000`.

## Routes

| Path | Page |
|------|------|
| `/` | Overview (counts + quick links) |
| `/topology` | Listeners / services / endpoints / pools |
| `/sessions` | Active sessions |
| `/settings` | API base + config reload |
| `/login` | Password gate (only when password set) |

Auth session is stored in `localStorage` for 12 hours.

## Features

- Multi-page layout with nav
- Optional password gate
- Configurable API base URL (localStorage)
- `POST /admin/reload`
- Links to `/metrics` and embedded `/admin`

## Embedded alternative

Gateway also serves a zero-dependency page at:

```text
GET http://127.0.0.1:8082/admin
```
