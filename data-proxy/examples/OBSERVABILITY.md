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

### Prometheus path metrics (A05, always on)

| Metric | Type | Labels | Notes |
|--------|------|--------|-------|
| `unisql_proxy_gateway_execute_path_total` | counter | base + `execute_path` | hit-rate: passthrough / sum(all paths) |
| `unisql_proxy_gateway_passthrough_bytes_total` | counter | base SQL labels | wire payload bytes on `GatewayResponse::Wire` |

`execute_path` values: `passthrough` / `passthrough_client` / `passthrough_extended` / `passthrough_rewrite`(=extended alias) / `streaming` / `streaming_demote` / `materialized` / `xproto_stream` / `n/a`.

### A-track honesty (A06 / A08 / A09 / A10)

Do **not** treat path counters as proof of end-to-end zero-copy or process RSS bounds.

| Claim you might want | What the product actually guarantees today |
|----------------------|--------------------------------------------|
| Peak memory ≈ window | **Logical** encode peak is authoritative: `gateway_encode_peak_window_rows` (smoke ≤ `window_rows`) and **`gateway_encode_peak_window_bytes`** (max encoded payload of one window; multi-window smokes assert peak_bytes ≪ total `encode_bytes`). **Coarse process memory** smoke (`smoke-security-stream-rss`) samples cgroup/proc/ps with absolute cap — catches catastrophic full-result materialize, **not** exact “1–2 window process bytes”. |
| Passthrough always wire | **Simple Query** with **no result obligations** → `passthrough`. **Result obligations (mask / row_filter / max_rows / watermark) force Streaming** even when `passthrough=true` (smoke-security-mask pins `execute_path=streaming`). **Extended** under `passthrough=true` with no obligations: prefer original client Parse/Bind/Execute frames on backend TCP (`passthrough_client`, multi-Execute continuous hold; Sync → `PG_BACKEND_SYNC` flushes Z); fallback re-encoded P/B/D/E/S (`passthrough_extended`); else **`streaming_demote`** (MySQL COM_STMT). |
| Portal export is streaming | Multi-row SELECT Streaming → HTTP `x-data-nexus-stream: backend_window` (NDJSON/CSV/JSON) plus `x-data-nexus-window-rows`. **Complete** (INSERT/DDL/no RowStream) → `chunked` (HTTP windows; backend ResultSet may already be materialized). CSV has no body meta — use the window-rows header. Portal Admin path records Prometheus under `type=PORTAL_STREAM` / `PORTAL_CHUNKED` (same `gateway_execute_path_total` / `gateway_encode_peak_window_rows` series as protocol CoreEngine). Peak is still **logical window**, not process RSS. |
| PG PortalSuspended / SQL cursor = true server cursor | Client Execute `max_rows` page → `s` footer. Multi-Execute resume **prefers a held backend `RowStream`** (`hold_remainder`). Prometheus **`gateway_portal_resume_total{mode=hold\|resume_hold\|logical_skip\|sql_cursor_*}`**. Simple-query **`DECLARE/FETCH/CLOSE`** is a **process-local** named cursor: without `WITH HOLD` drops on COMMIT/ROLLBACK; with `WITH HOLD` survives COMMIT until CLOSE; **session disconnect / Quit / `Drop` clears all** (`sql_cursor_session_end`); **forward FETCH only** — `MOVE` / `FETCH ABSOLUTE|RELATIVE|BACKWARD` return `0A000` and count `sql_cursor_unsupported` — **still not** backend SQL server-side `WITH HOLD`. Policy `max_rows` still ends with `C`. |
| All traffic is Streaming | Control / empty Complete paths may label `n/a` or `materialized` depending on response shape. Row-returning Query* under obligations/max_rows should hit `streaming`. Extended under passthrough: text-bind rewrite → `passthrough_rewrite`; else `streaming_demote`. |
| Sample / L2 = full result | B08 samples are bounded rows/bytes and require `default_audit_level=L2`. **Not** L3 full-result archive. |
| Column ACL / `SELECT *` | T01: `star_policy=deny` rejects `*` / `t.*` (no expansion). `star_policy=allow` also **never expands** wildcards to strip denied columns — only explicit projections are rewritten. |

Related smokes: `smoke-security-stream.sh` (streaming + peak≤window + PortalSuspended resume), `smoke-security-passthrough.sh` (simple passthrough + PG client-frame / MySQL demote), `smoke-security-mask.sh` / `smoke-security-watermark.sh` (mask|watermark + `passthrough=true` still `execute_path=streaming`), `smoke-security-portal*.sh` (backend_window vs chunked).

### Secure encode metrics (O01 / A06, always on)

| Metric | Type | Labels | Notes |
|--------|------|--------|-------|
| `unisql_proxy_gateway_mask_rows_total` | counter | SQL base | Rows that applied a non-empty mask obligation |
| `unisql_proxy_gateway_encode_windows_total` | counter | SQL base | Encode windows written (streaming / windowed ResultSet) |
| `unisql_proxy_gateway_encode_bytes_total` | counter | SQL base | Approx. encoded payload bytes (not TCP framing) |
| `unisql_proxy_gateway_encode_peak_window_rows` | gauge | SQL base | **Logical** high-water rows held in one encode window (A06). Smoke asserts ≤ `window_rows`. **Not** process RSS. |
| `unisql_proxy_gateway_encode_peak_window_bytes` | gauge | SQL base | **Logical** high-water encoded payload bytes of one encode window (A06). Multi-window smokes assert peak ≪ total `encode_bytes`. **Not** process RSS / cgroup. |

SQL base labels: `listener`, `service`, `frontend_protocol`, `backend_protocol`, `command_type`, `endpoint` (same as other gateway SQL series; metric names may be prefixed by the process exporter, e.g. `unisql_proxy_`).

Interpreting `execute_path` for dashboards:

- **`passthrough`**: wire/TCP relay path for simple Query — count as “fast path hits”, not as “no security”.
- **`passthrough_client`**: A08 original client Parse/Bind/Execute frames TCP-relayed (unit + multi-Execute continuous hold; client Sync flushes backend Z). Not free-form proxy.
- **`passthrough_extended`**: A08 PG text-bind re-encoded as backend Parse/Bind/Execute/Sync TCP when client frames unavailable. `passthrough_rewrite` normalizes here.
- **`streaming`**: windowed encode path (A06/A10 row streams with obligations).
- **`streaming_demote`**: A08 extended under `passthrough=true` that could **not** TCP-relay (e.g. MySQL COM_STMT).
- **`materialized` / `n/a`**: control packets, empty Complete, or responses without a row stream — **expected**, not a regression by itself.
- **`xproto_stream`**: cross-protocol translation Streaming.

Example PromQL:

```text
# passthrough hit rate (5m) — simple Query only in practice when obligations are empty
sum(rate(unisql_proxy_gateway_execute_path_total{execute_path="passthrough"}[5m]))
/
sum(rate(unisql_proxy_gateway_execute_path_total[5m]))

# logical peak should stay near configured window_rows (not RSS)
max_over_time(unisql_proxy_gateway_encode_peak_window_rows[5m])
```

### Audit pipeline metrics (always on)

| Metric | Type | Labels | Notes |
|--------|------|--------|-------|
| `unisql_proxy_gateway_audit_queue_len` | gauge | `queue=main` / `priority` | In-memory queue depth snapshot |
| `unisql_proxy_gateway_audit_process_duration_seconds` | histogram | `sink` | Worker per-event process latency |

Audit must not block queries (bounded queue + async worker).

**B07 priority queue**: decisions `deny` / `require_ticket` / `require_approval` enter a separate queue (`security.audit.priority_queue_capacity`) drained before the main allow/execute queue. Admin `/admin/audit/stats` exposes `priority_accepted` / `priority_dropped` / `priority_queue_len`. Smoke: `smoke-security-audit.sh` asserts `priority_accepted>=1` after a deny.

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
| `data_nexus.gateway.execute_path` | counter | same (A05 path hit-rate) |
| `data_nexus.gateway.passthrough_bytes` | counter | base labels without outcome (A05 wire bytes) |

Base labels: `listener`, `service`, `frontend_protocol`, `backend_protocol`, `command_type`, `endpoint`, `outcome`.

| Attribute | Values (controlled) |
|-----------|---------------------|
| `security_decision` | `none` / `allow` / `allow_obligations` / `deny` / `require_ticket` |
| `security_rule_class` | `none` / `table` / `column` / `row` / `cedar` / `time` / `ticket` / `fail_closed` / `other` |
| `execute_path` | `n/a` / `passthrough` / `streaming` / `materialized` / `xproto_stream` |
| `wire_bytes` | recorded on passthrough only (OTel counter; Prometheus has dedicated series) |

Prometheus text metrics on `/metrics` remain available regardless of OTel.

If the exporter fails to initialize, the process logs an error and continues with fmt-only logging.

## Audit L2 samples (B08)

Result samples are **opt-in** and **bounded**. They are **not** full-result capture.

| Knob | Default | Meaning |
|------|---------|---------|
| `security.default_audit_level` | `L0` | Must be **`L2`** for samples to attach |
| `security.audit.sample_enabled` | `false` | Master switch; validate rejects `true` unless level is L2 |
| `security.audit.sample_max_rows` | `5` | Max rows in sample (hard cap 10000) |
| `security.audit.sample_max_bytes` | `4096` | Serialized JSON cap (hard cap 1 MiB) |
| `security.audit.sample_inline` | `true` | Keep truncated body on event JSONL if no OpenDAL |
| `security.audit.sample_prefix` | `samples` | OpenDAL key prefix under `opendal_prefix` |

### Behaviour (honest)

1. Hot path attaches sample only when **both** `sample_enabled` and effective level **L2**.
2. Sample is built **after** obligations (mask / watermark) on a **window-sized** set for Streaming (first window / capped rows), never a second full ResultSet.
3. Shape: `{"columns":[...],"rows":[[...],...],"truncated":bool}` on `sample_body`; Admin `GET /admin/audit/events` may include `sample_body` / `sample_ref` / `sample_row_count` / `sample_truncated`.
4. OpenDAL upload (feature `audit-opendal`) may set `sample_ref=opendal:…` and drop body when `sample_inline=false`.
5. **Not** L3 full-result audit. Do not enable on high-QPS paths expecting compliance archives of every row.

### Minimal config

```toml
[security]
enabled = true
default_audit_level = "L2"

[security.audit]
sample_enabled = true
sample_max_rows = 5
sample_max_bytes = 4096
sample_inline = true
sinks = ["tracing", "file"]
file_path = "/tmp/data-nexus-audit-events.jsonl"
```

Smoke: `./examples/smoke-security-audit-sample.sh`.

Read-only config snapshot: `GET /admin/security-policies` includes `audit_sample`
(`sample_enabled`, `sample_max_rows`, `sample_max_bytes`, `sample_inline`, `sample_prefix`).
Admin Policies page surfaces the same knobs (UI04).


## Audit levels (F32)

| Level | `sql_text` | Result sample (B08) | Notes |
|-------|------------|---------------------|-------|
| **L0** (default) | **stripped** | never | Fingerprint / decision / objects only |
| **L1** | truncated (`sql_text_max_chars`, default 2048) | never | No full SQL dump |
| **L2** | truncated | only if `sample_enabled=true` | Samples bounded by rows/bytes; not L3 full result |

Validate rejects `sample_enabled=true` unless `default_audit_level=L2` (silent no-op avoided).

Smoke:

- `smoke-security-audit.sh` — L0 deny events have fingerprint, **no** `sql_text`
- `smoke-security-audit-sample.sh` — L2 sample events keep truncated `sql_text` + bounded `sample_body`

Admin Audit UI: event detail shows `sql_text` when present; Sample column is B08-only.

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
