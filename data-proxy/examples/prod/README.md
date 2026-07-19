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
| Audit index | SQLite side-index (`index_path`) for Admin search; same `retain_days` prune |
| OpenDAL archive | optional `audit-opendal` feature: `fs` / `s3` / `oss` after rotate; credentials via `DN_OPENDAL_*` |
| High risk | DDL + write-without-WHERE require tickets |
| Streaming | `window_rows=256`, `passthrough=true` |
| Multi-instance (H05) | `security.state.backend=file` + ticket/vault/policy paths; optional AES-GCM keys |

### H05 multi-instance notes

- **Not CRDT**: concurrent writers use advisory locks + full-file replace (last writer wins for overlapping updates).
- **Vault passwords**: only persisted when `vault_encrypt_key` is set (64 hex). Without key, lease file is metadata-only.
- **Local PDP**: `policy_path` + `policy_poll_ms` (default 1000; `0` disables mtime poll).
- **Audit SQLite**: put `index_path` on shared durable storage; WAL multi-writer OK with busy timeout.
- Redis/remote state backends are **rejected** at config validate until implemented.

## Related docs

- [`docs/admin-auth-password.md`](../../../docs/admin-auth-password.md) — break-glass vs OIDC  
- [`data-ui/docs/oidc-production.md`](../../../data-ui/docs/oidc-production.md) — production SSO runbook (H04)  
- [`docs/ticket-vault-runbook.md`](../../../docs/ticket-vault-runbook.md) — Ticket / Vault ops (T02): comment injection, dual-control, revoke, portal  
- [`gateway-jwks.example.toml`](gateway-jwks.example.toml) — JWKS admin_auth fragment  
- [`docs/build-cache.md`](../build-cache.md) — Cargo target on external volume  
- [`examples/admin-auth.snippet.toml`](../admin-auth.snippet.toml) — JWKS snippet  
- Smoke matrix: [`../run-smoke-matrix.sh`](../run-smoke-matrix.sh)

## Checklist before go-live

1. Replace all `replace-*` secrets; prefer OIDC `jwt_jwks` over long-lived HMAC break-glass  
2. Backend accounts are least-privilege (not root)  
3. Audit directory exists and is writable by the proxy user  
4. **Backend TLS pin (A08)**: template defaults to `ssl_mode=require` + `ssl_ca_file=__DN_*_SSL_CA_FILE__` + `ssl_accept_invalid_certs=false`. Set `DN_MYSQL_SSL_CA_FILE` / `DN_PG_SSL_CA_FILE` to PEM paths. Config validate rejects require+verify without CA. Client TLS still terminates at LB.  
5. Run `./examples/run-smoke-matrix.sh l0` against a staging stack  
6. Multi-instance: shared `security.state.*` paths + encrypt keys; shared audit `index_path`  
