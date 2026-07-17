# Data UI

Nuxt 3 admin console for **Data Nexus** gateway (static SPA).

Consumes the gateway Admin HTTP API (default `http://127.0.0.1:8082`).

## Prerequisites

- Node 18+
- pnpm (or npm)
- Running Data Nexus proxy with Admin port open

## Configure

| Variable | Default | Purpose |
|----------|---------|---------|
| `NUXT_PUBLIC_ADMIN_API_BASE` | `http://127.0.0.1:8082` | Gateway Admin API base URL |
| `NUXT_PUBLIC_ADMIN_PASSWORD` | _(empty)_ | Legacy UI-only gate; prefer gateway `break_glass_password` (see `docs/admin-auth-password.md`) |
| `NUXT_PUBLIC_OIDC_ISSUER` | _(empty)_ | OIDC issuer URL (enables SSO) |
| `NUXT_PUBLIC_OIDC_CLIENT_ID` | _(empty)_ | Public OIDC client id |
| `NUXT_PUBLIC_OIDC_REDIRECT_URI` | `{origin}/auth/callback` | Redirect URI registered with IdP |
| `NUXT_PUBLIC_OIDC_SCOPES` | `openid profile email` | OIDC scopes |

Gateway CORS is enabled by default. Restrict with:

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
# password:
# NUXT_PUBLIC_ADMIN_PASSWORD=secret pnpm dev
# SSO (OIDC PKCE public client):
# NUXT_PUBLIC_OIDC_ISSUER=https://idp.example.com \
# NUXT_PUBLIC_OIDC_CLIENT_ID=data-nexus-admin \
# NUXT_PUBLIC_OIDC_REDIRECT_URI=http://localhost:3000/auth/callback \
# pnpm dev
```

Open `http://localhost:3000`.

## Routes

| Path | Page |
|------|------|
| `/` | Overview |
| `/topology` | Listeners / services / endpoints / pools |
| `/sessions` | Active sessions |
| `/settings` | API base + config reload |
| `/login` | Password / SSO |
| `/auth/callback` | OIDC PKCE callback |

Auth session is stored in `localStorage` (password: 12h; OIDC: token `expires_in` capped at 12h).

## Production packaging

### Static generate

```bash
NUXT_PUBLIC_ADMIN_API_BASE=https://gateway.example.com:8082 \
pnpm generate
# output: .output/public
```

### Docker (nginx)

```bash
docker build -t data-nexus-ui \
  --build-arg NUXT_PUBLIC_ADMIN_API_BASE=http://host.docker.internal:8082 \
  -f Dockerfile .

docker run --rm -p 8080:80 data-nexus-ui
# or
docker compose -f deploy/docker-compose.ui.yml up --build
```

SPA routes are handled by `deploy/nginx.conf` (`try_files` → `index.html`).

## Auth models

1. **Open** — no password, no OIDC env → no login gate  
2. **Password** — `NUXT_PUBLIC_ADMIN_PASSWORD` or gateway break-glass via `/admin/auth/login`  
3. **SSO** — OIDC authorization code + PKCE (`NUXT_PUBLIC_OIDC_ISSUER` + `CLIENT_ID`)  
4. **Both** — login page offers password and SSO  

IdP must allow the SPA redirect URI and public client (no client secret).

### Production OIDC (H04)

Full runbook: [`docs/oidc-production.md`](docs/oidc-production.md)

- Gateway: `admin_auth.mode = jwt_jwks` + `jwks_url` / `issuer` / `audience` / `role_bindings`  
  Template: [`../data-proxy/examples/prod/gateway-jwks.example.toml`](../data-proxy/examples/prod/gateway-jwks.example.toml)  
- UI env template: [`deploy/oidc.env.example`](deploy/oidc.env.example)  
- UI sends IdP **access_token** as `Authorization: Bearer` to Admin API  

## Embedded alternative

Gateway also serves a zero-dependency page at:

```text
GET http://127.0.0.1:8082/admin
```
