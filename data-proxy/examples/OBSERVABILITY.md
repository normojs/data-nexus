# Data Nexus Observability

## Logs and spans

Gateway process logging is configured at startup (`proxy` binary):

| Variable | Purpose |
|----------|---------|
| `RUST_LOG` | Standard tracing filter (preferred) |
| `DATA_NEXUS_LOG` | Alternate filter if `RUST_LOG` unset |
| `DATA_NEXUS_LOG_FORMAT=json` | Emit JSON logs with span lists |
| `admin.log_level` in config | Default level when no env filter |

Example:

```bash
RUST_LOG=info,data_nexus=debug,runtime_gateway=debug \
DATA_NEXUS_LOG_FORMAT=json \
./target/debug/proxy daemon -c examples/dual-listener-gateway-config.toml
```

### Span names (structured fields)

| Span | Fields |
|------|--------|
| `gateway.handle_frame` | `listener`, `service`, `frontend_protocol`, `backend_protocol` |
| `gateway.command` | `command_type`, `endpoint`, `outcome`, `security_decision`, `security_rule_class`, `execute_path` |

`security_*` / `execute_path` are **low-cardinality** (B03). Rule names are mapped to classes (`table` / `column` / `cedar` / `time` / `ticket` / …), not raw policy ids.

Audit events also go to target `data_nexus::audit` with decision/latency fields.

## Metrics

Prometheus text format on admin port (default `8082`):

```text
GET /metrics
```

Command metrics labels include listener, service, frontend protocol, backend protocol, command type, endpoint.

## OpenTelemetry / OTLP (optional feature)

Default builds stay free of the OTel SDK. Enable export with:

```bash
cargo build -p data-proxy --bin proxy --features otel

OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4317 \
./target/debug/proxy daemon -c examples/dual-listener-gateway-config.toml
```

| Item | Detail |
|------|--------|
| Feature flag | `otel` on crate `data-proxy` (enables `runtime_gateway/otel`) |
| Runtime gate | `OTEL_EXPORTER_OTLP_ENDPOINT` must be set (non-empty) |
| Protocol | OTLP gRPC (tonic), default collector port `4317` |
| Service name | `data-nexus` |
| Traces | spans `gateway.handle_frame`, `gateway.command` |
| Metrics | default on; disable with `DATA_NEXUS_OTEL_METRICS=0` |
| Logs | default on (tracing → OTLP logs); disable with `DATA_NEXUS_OTEL_LOGS=0` |
| Security attrs | default on; disable with `DATA_NEXUS_OTEL_ATTR_SECURITY=0` |

### Trace sampling

| Variable | Values | Default |
|----------|--------|---------|
| `OTEL_TRACES_SAMPLER` or `DATA_NEXUS_OTEL_TRACES_SAMPLER` | `always_on`, `always_off`, `traceidratio`, `parentbased_always_on`, `parentbased_always_off`, `parentbased_traceidratio` | `parentbased_traceidratio` |
| `OTEL_TRACES_SAMPLER_ARG` or `DATA_NEXUS_OTEL_TRACES_SAMPLER_ARG` | ratio `0.0`–`1.0` for `*traceidratio` | `1.0` |

Example (sample 10% of root traces, respect parent decision):

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4317 \
OTEL_TRACES_SAMPLER=parentbased_traceidratio \
OTEL_TRACES_SAMPLER_ARG=0.1 \
./target/debug/proxy daemon -c examples/dual-listener-gateway-config.toml
```

### Business metrics (command path)

When `otel` is built and metrics are enabled:

| Metric | Type | Labels |
|--------|------|--------|
| `data_nexus.otel.up` | counter | (startup) |
| `data_nexus.gateway.commands` | counter | base labels + `security_decision`, `security_rule_class`, `execute_path` |
| `data_nexus.gateway.command_duration_ms` | histogram | same |
| `data_nexus.gateway.errors` | counter | same (`error:*`, `translation_reject`, `plugin_reject`) |
| `data_nexus.gateway.security_denies` | counter | same (only `security_deny` / `security_require_ticket`) |

Base labels: `listener`, `service`, `frontend_protocol`, `backend_protocol`, `command_type`, `endpoint`, `outcome`.

| Attribute | Values (controlled) |
|-----------|---------------------|
| `security_decision` | `none` / `allow` / `allow_obligations` / `deny` / `require_ticket` |
| `security_rule_class` | `none` / `table` / `column` / `row` / `cedar` / `time` / `ticket` / `fail_closed` / `other` |
| `execute_path` | `n/a` / `passthrough` / `streaming` / `materialized` / `xproto_stream` |

Prometheus text metrics on `/metrics` remain available regardless of OTel.

If the exporter fails to initialize, the process logs an error and continues with fmt-only logging.

## Admin API auth (management plane)

Optional. Default `admin_auth.enabled = false` keeps open Admin API (local dev).

When enabled:

| Mode | Use |
|------|-----|
| `jwt_hmac` | HS256 shared secret (+ optional break-glass login) |
| `jwt_jwks` | RS256 via IdP JWKS URL (enterprise OIDC access_token) |

| Endpoint | Auth |
|----------|------|
| `GET /admin/auth/config` | public |
| `POST /admin/auth/login` | public (break-glass password → JWT) |
| `GET /healthz`, `GET /version` | public |
| `GET /metrics` | public if `public_metrics = true` (default) |
| other `/admin/*` | `Authorization: Bearer <JWT>` |

Roles: `viewer` / `operator` / `admin` (permission union).  
Claims: `roles` / `groups` / paths → `role_bindings`.

Docs: `examples/admin-auth.snippet.toml`, `docs/admin-auth-password.md`, `docs/admin-rbac-design.md`.

```bash
# enabled: no token → 401 on reload
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:8082/admin/reload

# break-glass mint
curl -s -X POST http://127.0.0.1:8082/admin/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"password":"change-me-break-glass"}'
```

### Embedded (zero dependency)

```text
GET http://127.0.0.1:8082/admin
```

Loads live JSON from `/admin/listeners|services|endpoints|pools|sessions` and can trigger `POST /admin/reload`.

### Nuxt console (`data-ui`)

```bash
cd data-ui
pnpm install
NUXT_PUBLIC_ADMIN_API_BASE=http://127.0.0.1:8082 \
NUXT_PUBLIC_ADMIN_PASSWORD=secret \
pnpm dev
```

Open `http://localhost:3000`. Routes: `/`, `/topology`, `/sessions`, `/settings`, `/login`, `/auth/callback`.

Auth options:

- Password: `NUXT_PUBLIC_ADMIN_PASSWORD`
- SSO (OIDC PKCE): `NUXT_PUBLIC_OIDC_ISSUER` + `NUXT_PUBLIC_OIDC_CLIENT_ID`
- Production: `pnpm generate` or `docker build -f data-ui/Dockerfile`

### CORS

Admin routes allow browser origins by default (`Access-Control-Allow-Origin: *`).

Restrict:

```bash
export DATA_NEXUS_ADMIN_CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
```
