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

## OpenTelemetry / OTLP (optional next step)

Runtime already emits `tracing` spans. To export to an OTel collector without code changes in gateway_core:

1. Add a process-level OTLP layer (e.g. `tracing-opentelemetry` + `opentelemetry-otlp`) in `cmd/pisa` only.
2. Keep span names above stable so dashboards can key on `gateway.command`.
3. Prefer env-based enablement (`OTEL_EXPORTER_OTLP_ENDPOINT`) so default deployments stay dependency-light.

This repository intentionally does **not** hard-require the OTel SDK in the default build.
