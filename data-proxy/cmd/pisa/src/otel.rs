//! Optional OpenTelemetry OTLP export (feature = "otel").
//!
//! Built with `--features otel`. Activates only when
//! `OTEL_EXPORTER_OTLP_ENDPOINT` is set at runtime.

use std::str::FromStr;

use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{runtime, Resource};
use tracing::{info, Level};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

/// Initialize logging + optional OTLP tracing.
///
/// Returns a shutdown guard that flushes spans on drop when OTLP is active.
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
        match build_provider(&endpoint) {
            Ok(provider) => {
                let tracer = provider.tracer("data-nexus");
                // Type-erase layers so fmt format (json vs text) does not fight OTel generics.
                let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer).boxed();
                let fmt_layer = if json {
                    fmt::layer().json().with_span_list(true).with_current_span(true).boxed()
                } else {
                    fmt::layer().with_target(true).boxed()
                };
                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt_layer)
                    .with(otel_layer)
                    .init();
                info!(%endpoint, "OpenTelemetry OTLP exporter enabled");
                return Some(OtelGuard { provider });
            }
            Err(error) => {
                eprintln!("failed to init OTLP exporter ({error}); continuing without OTel");
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
    provider: opentelemetry_sdk::trace::TracerProvider,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        let _ = self.provider.shutdown();
    }
}

fn build_provider(
    endpoint: &str,
) -> Result<opentelemetry_sdk::trace::TracerProvider, Box<dyn std::error::Error + Send + Sync>> {
    let resource = Resource::new(vec![
        KeyValue::new("service.name", "data-nexus"),
        KeyValue::new("service.namespace", "revocloud"),
    ]);

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()?;

    Ok(opentelemetry_sdk::trace::TracerProvider::builder()
        .with_batch_exporter(exporter, runtime::Tokio)
        .with_resource(resource)
        .build())
}
