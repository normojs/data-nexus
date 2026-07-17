# Production config package (H01)

Templates for a **production-shaped** dual-listener gateway. Real secrets never live in git.

| File | Role |
|------|------|
| [`gateway.example.toml`](gateway.example.toml) | Full config with `__DN_*__` placeholders |
| [`env.example`](env.example) | Env var names to fill privately |
| [`render-config.sh`](render-config.sh) | Substitute placeholders → stdout |

## Quick start

```bash
cd data-proxy

# 1) private env (outside repo)
cp examples/prod/env.example /secure/path/data-nexus.env
# edit secrets in /secure/path/data-nexus.env

# 2) render
set -a && source /secure/path/data-nexus.env && set +a
./examples/prod/render-config.sh > /secure/path/gateway.toml
chmod 600 /secure/path/gateway.toml /secure/path/data-nexus.env

# 3) run (target-dir is external — see docs/build-cache.md)
cargo build -p data-proxy --bin proxy
# binary under /Volumes/fushilu/.caches/data-nexus/cargo-target/debug/proxy when using project config
./…/proxy daemon -c /secure/path/gateway.toml
```

## Production defaults baked into the template

| Area | Setting |
|------|---------|
| Admin API | `admin_auth.enabled=true`, JWT HMAC + break-glass (swap to `jwt_jwks` for OIDC) |
| Data plane | `security.enabled=true`, `fail_closed=true`, `star_policy=deny` |
| Audit | file sink + rotation (`max_file_bytes`, `retain_days`, `rotate_keep`) |
| OpenDAL archive | optional `audit-opendal` feature: `fs` / `s3` / `oss` after rotate; credentials via `DN_OPENDAL_*` |
| High risk | DDL + write-without-WHERE require tickets |
| Streaming | `window_rows=256`, `passthrough=true` |

## Related docs

- [`docs/admin-auth-password.md`](../../../docs/admin-auth-password.md) — break-glass vs OIDC  
- [`data-ui/docs/oidc-production.md`](../../../data-ui/docs/oidc-production.md) — production SSO runbook (H04)  
- [`gateway-jwks.example.toml`](gateway-jwks.example.toml) — JWKS admin_auth fragment  
- [`docs/build-cache.md`](../build-cache.md) — Cargo target on external volume  
- [`examples/admin-auth.snippet.toml`](../admin-auth.snippet.toml) — JWKS snippet  
- Smoke matrix: [`../run-smoke-matrix.sh`](../run-smoke-matrix.sh)

## Checklist before go-live

1. Replace all `replace-*` secrets; prefer OIDC `jwt_jwks` over long-lived HMAC break-glass  
2. Backend accounts are least-privilege (not root)  
3. Audit directory exists and is writable by the proxy user  
4. TLS: terminate at LB or enable protocol TLS when available  
5. Run `./examples/run-smoke-matrix.sh l0` against a staging stack  
