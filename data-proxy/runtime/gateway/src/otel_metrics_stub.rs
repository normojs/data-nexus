// No-op OTel business metrics when feature `otel` is disabled.

use std::time::Duration;

/// Mirror of otel_metrics::CommandOtelAttrs for no-feature builds.
#[derive(Debug, Clone, Default)]
pub struct CommandOtelAttrs {
    pub security_decision: &'static str,
    pub security_rule_class: &'static str,
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

pub fn record_command(
    _listener: &str,
    _service: &str,
    _frontend_protocol: &str,
    _backend_protocol: &str,
    _command_type: &str,
    _endpoint: &str,
    _outcome: &str,
    _duration: Duration,
    _attrs: &CommandOtelAttrs,
) {
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
