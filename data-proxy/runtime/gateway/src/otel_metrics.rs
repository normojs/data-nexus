//! Optional OpenTelemetry business metrics for the gateway command path.
//!
//! Compiled only with `--features otel`. When the feature is off, callers use
//! no-op stubs so the default build stays free of the OTel SDK.
//!
//! B03: optional low-cardinality security attributes (`security_decision`,
//! `security_rule_class`, `execute_path`) controlled by env.

use std::sync::OnceLock;
use std::time::Duration;

use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram};
use opentelemetry::KeyValue;
use tracing::debug;

/// Extra command attributes (B03). Keep values low-cardinality.
#[derive(Debug, Clone, Default)]
pub struct CommandOtelAttrs {
    /// allow | deny | require_ticket | none
    pub security_decision: &'static str,
    /// rule class: none | table | column | cedar | time | ticket | mask | other
    pub security_rule_class: &'static str,
    /// passthrough | streaming | materialized | n/a
    pub execute_path: &'static str,
}

impl CommandOtelAttrs {
    pub fn none() -> Self {
        Self {
            security_decision: "none",
            security_rule_class: "none",
            execute_path: "n/a",
        }
    }

    pub fn security(decision: &'static str, rule_class: &'static str) -> Self {
        Self {
            security_decision: decision,
            security_rule_class: rule_class,
            execute_path: "n/a",
        }
    }

    pub fn with_execute_path(mut self, path: &'static str) -> Self {
        self.execute_path = path;
        self
    }
}

/// Map a free-form security rule name to a low-cardinality class (B03).
pub fn classify_security_rule(rule: &str) -> &'static str {
    let r = rule.trim().to_ascii_lowercase();
    if r.is_empty() || r == "none" {
        return "none";
    }
    if r == "cedar" || r.starts_with("cedar") {
        return "cedar";
    }
    if r.contains("ticket") || r.contains("require") {
        return "ticket";
    }
    if r.contains("time") || r.contains("work-hours") || r.contains("business") {
        return "time";
    }
    if r.contains("column") || r.contains("mask") || r.contains("pii") {
        return "column";
    }
    if r.contains("secret") || r.contains("table") || r.contains("deny") {
        return "table";
    }
    if r.contains("row") || r.contains("filter") {
        return "row";
    }
    if r.contains("fail_closed") || r == "fail_closed" {
        return "fail_closed";
    }
    "other"
}

struct GatewayOtelInstruments {
    commands_total: Counter<u64>,
    command_duration_ms: Histogram<f64>,
    errors_total: Counter<u64>,
    security_denies_total: Counter<u64>,
}

static INSTRUMENTS: OnceLock<Option<GatewayOtelInstruments>> = OnceLock::new();

fn instruments() -> Option<&'static GatewayOtelInstruments> {
    INSTRUMENTS
        .get_or_init(|| {
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
                security_denies_total: meter
                    .u64_counter("data_nexus.gateway.security_denies")
                    .with_description(
                        "Security deny / require_ticket outcomes (low-cardinality rule class)",
                    )
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
        Err(_) => true,
    }
}

/// When false, security_* attributes collapse to "none" to control cardinality.
fn env_security_attrs_enabled() -> bool {
    match std::env::var("DATA_NEXUS_OTEL_ATTR_SECURITY") {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !(v == "0" || v == "false" || v == "off" || v == "no")
        }
        // Default on when metrics are compiled — values are already classified.
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
    attrs: &CommandOtelAttrs,
) {
    let Some(inst) = instruments() else {
        return;
    };
    let security_on = env_security_attrs_enabled();
    let sec_decision = if security_on {
        attrs.security_decision
    } else {
        "none"
    };
    let sec_rule = if security_on {
        attrs.security_rule_class
    } else {
        "none"
    };
    let exec_path = if security_on {
        attrs.execute_path
    } else {
        "n/a"
    };

    let kv = [
        KeyValue::new("listener", listener.to_owned()),
        KeyValue::new("service", service.to_owned()),
        KeyValue::new("frontend_protocol", frontend_protocol.to_owned()),
        KeyValue::new("backend_protocol", backend_protocol.to_owned()),
        KeyValue::new("command_type", command_type.to_owned()),
        KeyValue::new("endpoint", endpoint.to_owned()),
        KeyValue::new("outcome", outcome.to_owned()),
        KeyValue::new("security_decision", sec_decision.to_owned()),
        KeyValue::new("security_rule_class", sec_rule.to_owned()),
        KeyValue::new("execute_path", exec_path.to_owned()),
    ];
    inst.commands_total.add(1, &kv);
    inst.command_duration_ms
        .record(duration.as_secs_f64() * 1000.0, &kv);
    if outcome.starts_with("error")
        || outcome == "translation_reject"
        || outcome == "plugin_reject"
    {
        inst.errors_total.add(1, &kv);
    }
    if outcome == "security_deny" || outcome == "security_require_ticket" {
        inst.security_denies_total.add(1, &kv);
    }
    debug!(
        target: "data_nexus::otel",
        command_type,
        outcome,
        security_decision = sec_decision,
        security_rule_class = sec_rule,
        execute_path = exec_path,
        "otel business metrics recorded"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_rule_names() {
        assert_eq!(classify_security_rule(""), "none");
        assert_eq!(classify_security_rule("cedar"), "cedar");
        assert_eq!(classify_security_rule("require-ddl-ticket"), "ticket");
        assert_eq!(classify_security_rule("work-hours-writes"), "time");
        assert_eq!(classify_security_rule("deny-secret-tables"), "table");
        assert_eq!(classify_security_rule("deny-employee-pii"), "column");
        assert_eq!(classify_security_rule("row_filter"), "row");
        assert_eq!(classify_security_rule("custom-xyz"), "other");
    }
}
