//! Optional OpenTelemetry business metrics for the gateway command path.
//!
//! Compiled only with `--features otel`. When the feature is off, callers use
//! no-op stubs so the default build stays free of the OTel SDK.

use std::sync::OnceLock;
use std::time::Duration;

use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram};
use opentelemetry::KeyValue;
use tracing::debug;

struct GatewayOtelInstruments {
    commands_total: Counter<u64>,
    command_duration_ms: Histogram<f64>,
    errors_total: Counter<u64>,
}

static INSTRUMENTS: OnceLock<Option<GatewayOtelInstruments>> = OnceLock::new();

fn instruments() -> Option<&'static GatewayOtelInstruments> {
    INSTRUMENTS
        .get_or_init(|| {
            // Only wire instruments when a global meter provider was installed
            // (cmd/pisa otel init). Building counters against a noop provider is
            // harmless but we still gate on env so operators can disable.
            if !env_metrics_enabled() {
                return None;
            }
            let meter = global::meter("data-nexus");
            Some(GatewayOtelInstruments {
                commands_total: meter
                    .u64_counter("data_nexus.gateway.commands")
                    .with_description("Gateway commands processed")
                    .build(),
                command_duration_ms: meter
                    .f64_histogram("data_nexus.gateway.command_duration_ms")
                    .with_description("Gateway command latency in milliseconds")
                    .build(),
                errors_total: meter
                    .u64_counter("data_nexus.gateway.errors")
                    .with_description("Gateway command errors")
                    .build(),
            })
        })
        .as_ref()
}

fn env_metrics_enabled() -> bool {
    match std::env::var("DATA_NEXUS_OTEL_METRICS") {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !(v == "0" || v == "false" || v == "off" || v == "no")
        }
        // Feature compiled in; default on (provider may still be noop if OTLP off).
        Err(_) => true,
    }
}

/// Record one finished gateway command for OTel metrics.
pub fn record_command(
    listener: &str,
    service: &str,
    frontend_protocol: &str,
    backend_protocol: &str,
    command_type: &str,
    endpoint: &str,
    outcome: &str,
    duration: Duration,
) {
    let Some(inst) = instruments() else {
        return;
    };
    let attrs = [
        KeyValue::new("listener", listener.to_owned()),
        KeyValue::new("service", service.to_owned()),
        KeyValue::new("frontend_protocol", frontend_protocol.to_owned()),
        KeyValue::new("backend_protocol", backend_protocol.to_owned()),
        KeyValue::new("command_type", command_type.to_owned()),
        KeyValue::new("endpoint", endpoint.to_owned()),
        KeyValue::new("outcome", outcome.to_owned()),
    ];
    inst.commands_total.add(1, &attrs);
    inst.command_duration_ms.record(duration.as_secs_f64() * 1000.0, &attrs);
    if outcome.starts_with("error") || outcome == "translation_reject" {
        inst.errors_total.add(1, &attrs);
    }
    debug!(
        target: "data_nexus::otel",
        command_type,
        outcome,
        "otel business metrics recorded"
    );
}
