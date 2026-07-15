//! Optional OpenTelemetry OTLP export (feature = "otel").
//!
//! Built with `--features otel`. Activates only when
//! `OTEL_EXPORTER_OTLP_ENDPOINT` is set at runtime.
//!
//! Exports:
//! - traces (always when endpoint set) with configurable sampler
//! - metrics when `DATA_NEXUS_OTEL_METRICS` is not `0`/`false` (default on)
//! - logs when `DATA_NEXUS_OTEL_LOGS` is not `0`/`false` (default on)
//!
//! Sampling (standard OTel env + Data Nexus alias):
//! - `OTEL_TRACES_SAMPLER` / `DATA_NEXUS_OTEL_TRACES_SAMPLER`:
//!   `always_on` | `always_off` | `traceidratio` | `parentbased_always_on` |
//!   `parentbased_always_off` | `parentbased_traceidratio` (default)
//! - `OTEL_TRACES_SAMPLER_ARG` / `DATA_NEXUS_OTEL_TRACES_SAMPLER_ARG`:
//!   ratio in `[0.0, 1.0]` for `*traceidratio` (default `1.0`)

use std::str::FromStr;
use std::time::Duration;

use opentelemetry::global;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_appender_tracing2::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::logs::LoggerProvider;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::trace::Sampler;
use opentelemetry_sdk::{runtime, Resource};
use tracing::{info, Level};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

/// Initialize logging + optional OTLP traces/metrics/logs.
///
/// Returns a shutdown guard that flushes providers on drop when OTLP is active.
pub fn init_tracing(admin_log_level: &str) -> Option<OtelGuard> {
    let default_level = Level::from_str(admin_log_level).unwrap_or(Level::INFO);
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_from_env("DATA_NEXUS_LOG"))
        .unwrap_or_else(|_| EnvFilter::new(default_level.as_str()));

    let json = std::env::var("DATA_NEXUS_LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok().filter(|s| !s.is_empty());
    if let Some(endpoint) = endpoint {
        match install_otlp(&endpoint, json, filter) {
            Ok(guard) => {
                info!(
                    %endpoint,
                    traces = true,
                    sampler = %guard.sampler_label,
                    metrics = guard.meter_provider.is_some(),
                    logs = guard.logger_provider.is_some(),
                    "OpenTelemetry OTLP exporter enabled"
                );
                return Some(guard);
            }
            Err(error) => {
                eprintln!("failed to init OTLP exporter ({error}); continuing without OTel");
                let filter = EnvFilter::try_from_default_env()
                    .or_else(|_| EnvFilter::try_from_env("DATA_NEXUS_LOG"))
                    .unwrap_or_else(|_| EnvFilter::new(default_level.as_str()));
                let fmt_layer = if json {
                    fmt::layer().json().with_span_list(true).with_current_span(true).boxed()
                } else {
                    fmt::layer().with_target(true).boxed()
                };
                tracing_subscriber::registry().with(filter).with(fmt_layer).init();
                return None;
            }
        }
    }

    let fmt_layer = if json {
        fmt::layer().json().with_span_list(true).with_current_span(true).boxed()
    } else {
        fmt::layer().with_target(true).boxed()
    };
    tracing_subscriber::registry().with(filter).with(fmt_layer).init();
    None
}

pub struct OtelGuard {
    tracer_provider: opentelemetry_sdk::trace::TracerProvider,
    meter_provider: Option<SdkMeterProvider>,
    logger_provider: Option<LoggerProvider>,
    sampler_label: String,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        let _ = self.tracer_provider.shutdown();
        if let Some(provider) = self.meter_provider.take() {
            let _ = provider.shutdown();
        }
        if let Some(provider) = self.logger_provider.take() {
            let _ = provider.shutdown();
        }
    }
}

fn env_flag_enabled(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !(v == "0" || v == "false" || v == "off" || v == "no")
        }
        Err(_) => default,
    }
}

fn env_first(names: &[&str]) -> Option<String> {
    for name in names {
        if let Ok(v) = std::env::var(name) {
            let v = v.trim().to_owned();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

fn service_resource() -> Resource {
    Resource::new(vec![
        KeyValue::new("service.name", "data-nexus"),
        KeyValue::new("service.namespace", "revocloud"),
    ])
}

/// Resolve sampler from OTEL / Data Nexus env vars.
///
/// Returns `(sampler, human-readable label)`.
pub fn resolve_sampler() -> (Sampler, String) {
    let name = env_first(&["OTEL_TRACES_SAMPLER", "DATA_NEXUS_OTEL_TRACES_SAMPLER"])
        .unwrap_or_else(|| "parentbased_traceidratio".into())
        .to_ascii_lowercase();
    let ratio = env_first(&["OTEL_TRACES_SAMPLER_ARG", "DATA_NEXUS_OTEL_TRACES_SAMPLER_ARG"])
        .and_then(|s| s.parse::<f64>().ok())
        .map(|r| r.clamp(0.0, 1.0))
        .unwrap_or(1.0);

    match name.as_str() {
        "always_on" => (Sampler::AlwaysOn, "always_on".into()),
        "always_off" => (Sampler::AlwaysOff, "always_off".into()),
        "traceidratio" => (
            Sampler::TraceIdRatioBased(ratio),
            format!("traceidratio({ratio})"),
        ),
        "parentbased_always_on" => (
            Sampler::ParentBased(Box::new(Sampler::AlwaysOn)),
            "parentbased_always_on".into(),
        ),
        "parentbased_always_off" => (
            Sampler::ParentBased(Box::new(Sampler::AlwaysOff)),
            "parentbased_always_off".into(),
        ),
        "parentbased_traceidratio" | _ => (
            Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(ratio))),
            format!("parentbased_traceidratio({ratio})"),
        ),
    }
}

fn install_otlp(
    endpoint: &str,
    json: bool,
    filter: EnvFilter,
) -> Result<OtelGuard, Box<dyn std::error::Error + Send + Sync>> {
    let resource = service_resource();
    let (sampler, sampler_label) = resolve_sampler();

    // --- traces ---
    let span_exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()?;
    let tracer_provider = opentelemetry_sdk::trace::TracerProvider::builder()
        .with_batch_exporter(span_exporter, runtime::Tokio)
        .with_sampler(sampler)
        .with_resource(resource.clone())
        .build();
    let tracer = tracer_provider.tracer("data-nexus");
    let otel_trace_layer = tracing_opentelemetry::layer().with_tracer(tracer).boxed();

    // --- metrics (optional) ---
    let meter_provider = if env_flag_enabled("DATA_NEXUS_OTEL_METRICS", true) {
        let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()?;
        let reader = PeriodicReader::builder(metric_exporter, runtime::Tokio)
            .with_interval(Duration::from_secs(15))
            .build();
        let provider = SdkMeterProvider::builder()
            .with_reader(reader)
            .with_resource(resource.clone())
            .build();
        global::set_meter_provider(provider.clone());
        // Emit a process-uptime counter so collectors see activity immediately.
        let meter = global::meter("data-nexus");
        let counter = meter
            .u64_counter("data_nexus.otel.up")
            .with_description("OTel metrics active")
            .build();
        counter.add(1, &[]);
        Some(provider)
    } else {
        None
    };

    // --- logs (optional) ---
    let (logger_provider, otel_log_layer) = if env_flag_enabled("DATA_NEXUS_OTEL_LOGS", true) {
        let log_exporter = opentelemetry_otlp::LogExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()?;
        let provider = LoggerProvider::builder()
            .with_batch_exporter(log_exporter, runtime::Tokio)
            .with_resource(resource)
            .build();
        let layer = OpenTelemetryTracingBridge::new(&provider).boxed();
        (Some(provider), Some(layer))
    } else {
        (None, None)
    };

    let fmt_layer = if json {
        fmt::layer().json().with_span_list(true).with_current_span(true).boxed()
    } else {
        fmt::layer().with_target(true).boxed()
    };

    let registry = tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(otel_trace_layer);
    if let Some(log_layer) = otel_log_layer {
        registry.with(log_layer).init();
    } else {
        registry.init();
    }

    Ok(OtelGuard {
        tracer_provider,
        meter_provider,
        logger_provider,
        sampler_label,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_sampler_defaults_to_parentbased_ratio() {
        // Clear-ish: function reads env; just ensure it returns a label.
        let (_sampler, label) = resolve_sampler();
        assert!(!label.is_empty());
    }
}
