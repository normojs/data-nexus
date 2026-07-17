# Production OIDC runbook (H04)

End-to-end SSO for **data-ui** + gateway Admin API using **OIDC Authorization Code + PKCE** (public client) and gateway **`jwt_jwks`** verification.

Code paths already exist:

| Layer | Mechanism |
|-------|-----------|
| data-ui | `useOidc` → discovery → code+PKCE → stores **access_token** in `localStorage` |
| Gateway | `admin_auth.mode = jwt_jwks` + `jwks_url` validates Bearer on `/admin/*` |
| Break-glass | Optional HS256 mint via `jwt_secret` + `break_glass_password` |

This package is the **production wiring checklist** (no live IdP secrets in git).

## Architecture

```text
Browser (data-ui SPA)
   │  1) /authorize (PKCE)
   ▼
IdP (Keycloak / Auth0 / Azure AD / …)
   │  2) code → /token  (access_token + optional id_token)
   ▼
Browser stores access_token
   │  3) Authorization: Bearer <access_token>
   ▼
Data Nexus Admin API (jwt_jwks + role_bindings)
```

**Important:** the UI must send the IdP **access_token** (not only id_token). Gateway JWKS validates that access token’s signature, `iss`, and `aud`.

## 1. IdP client

Create a **public SPA** client (no client secret):

| Setting | Value |
|---------|--------|
| Client type | Public / SPA |
| Auth | Authorization Code + PKCE (S256) |
| Redirect URIs | `https://ui.example.com/auth/callback` (+ local `http://localhost:3000/auth/callback` for dev) |
| Web origins / CORS | UI origin |
| Logout | optional front-channel / end_session |
| Scopes | at least `openid`; add groups/roles claim for RBAC |
| Audience | Must include gateway `admin_auth.audience` (e.g. `data-nexus-admin`) |

Role claim examples (map in IdP or use `role_claim_paths`):

- Keycloak realm roles → often `realm_access.roles`
- Groups → `groups`
- Custom → `roles`

Gateway bindings (`role_bindings`) map claim strings → `viewer` | `operator` | `admin`.

## 2. Gateway config (JWKS)

Use placeholders; render offline (same style as `examples/prod/`).

See [`gateway-jwks.example.toml`](gateway-jwks.example.toml).

```toml
[admin_auth]
enabled = true
mode = "jwt_jwks"
jwks_url = "https://idp.example.com/realms/ops/protocol/openid-connect/certs"
issuer = "https://idp.example.com/realms/ops"
audience = "data-nexus-admin"
jwks_cache_secs = 300
public_metrics = true
# optional break-glass (requires jwt_secret)
jwt_secret = "…"
break_glass_password = "…"
break_glass_role = "admin"
role_claim_paths = ["roles", "groups", "realm_access.roles"]

[admin_auth.role_bindings]
"data-nexus-viewers" = "viewer"
"data-nexus-operators" = "operator"
"data-nexus-admins" = "admin"
```

Validate config loads:

```bash
# after filling secrets into a private file
proxy daemon -c /secure/gateway-jwks.toml
curl -s http://127.0.0.1:8082/admin/auth/config
# expect: enabled=true, mode=jwt_jwks, break_glass_login=true|false
```

## 3. data-ui env (production build)

```bash
export NUXT_PUBLIC_ADMIN_API_BASE=https://gateway.example.com:8082
export NUXT_PUBLIC_OIDC_ISSUER=https://idp.example.com/realms/ops
export NUXT_PUBLIC_OIDC_CLIENT_ID=data-nexus-admin
export NUXT_PUBLIC_OIDC_REDIRECT_URI=https://ui.example.com/auth/callback
export NUXT_PUBLIC_OIDC_SCOPES="openid profile email"
# Leave NUXT_PUBLIC_ADMIN_PASSWORD empty when SSO is primary

pnpm generate   # or docker build with the same build-args
```

CORS on gateway (restrict to UI origin):

```bash
export DATA_NEXUS_ADMIN_CORS_ORIGINS=https://ui.example.com
```

## 4. Integration checklist

1. **Discovery** — browser can `GET {issuer}/.well-known/openid-configuration`  
2. **Login** — UI “Sign in with SSO” redirects to IdP; callback hits `/auth/callback`  
3. **Token** — DevTools: session has `access_token`; call  
   `curl -H "Authorization: Bearer $AT" $API/admin/me` → 200 + roles  
4. **RBAC** — viewer cannot `POST /admin/reload` (403); admin can  
5. **Expiry** — wait/force short TTL; UI should re-login (401 → login / forbidden)  
6. **Logout** — if IdP exposes `end_session_endpoint`, UI clears local session and redirects  
7. **Break-glass** — with gateway down IdP path, password login still works when configured  
8. **No secret in SPA** — client is public; never embed client_secret in Nuxt `public` config  

## 5. Common failures

| Symptom | Check |
|---------|--------|
| 401 after SSO | access_token vs id_token; `aud` / `iss` vs gateway config |
| 403 on APIs | `role_bindings` vs claim values; claim path |
| CORS errors | `DATA_NEXUS_ADMIN_CORS_ORIGINS` includes UI origin |
| state mismatch | multiple tabs / clock; restart login |
| JWKS fetch fail | gateway can reach `jwks_url` (egress / TLS) |

## 6. Local simulation without real IdP

Use **HMAC break-glass** (`examples/admin-auth-gateway-config.toml` + `smoke-admin-auth.sh`) for CI.  
Full OIDC requires a real or containerized IdP (e.g. Keycloak realm export — out of scope for unit smoke).

Optional future: Keycloak docker-compose profile + automated browser smoke (Playwright) — track as UI follow-up.

## Related

- [`docs/admin-auth-password.md`](../../../docs/admin-auth-password.md)
- [`examples/admin-auth.snippet.toml`](../../data-proxy/examples/admin-auth.snippet.toml)
- [`examples/prod/`](../../data-proxy/examples/prod/) — HMAC production template
- data-ui [`README.md`](../README.md)
