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
| `gateway.command` | `command_type`, `endpoint`, `outcome` |

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
| Feature flag | `otel` on crate `data-proxy` |
| Runtime gate | `OTEL_EXPORTER_OTLP_ENDPOINT` must be set (non-empty) |
| Protocol | OTLP gRPC (tonic), default collector port `4317` |
| Service name | `data-nexus` |
| Span names | `gateway.handle_frame`, `gateway.command` |

If the exporter fails to initialize, the process logs an error and continues with fmt-only logging.

## Admin UI

### Embedded (zero dependency)

```text
GET http://127.0.0.1:8082/admin
```

Loads live JSON from `/admin/listeners|services|endpoints|pools|sessions` and can trigger `POST /admin/reload`.

### Nuxt console (`data-ui`)

```bash
cd data-ui
pnpm install
NUXT_PUBLIC_ADMIN_API_BASE=http://127.0.0.1:8082 pnpm dev
```

Open `http://localhost:3000`. The UI calls the Admin API over HTTP.

### CORS

Admin routes allow browser origins by default (`Access-Control-Allow-Origin: *`).

Restrict:

```bash
export DATA_NEXUS_ADMIN_CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
```
