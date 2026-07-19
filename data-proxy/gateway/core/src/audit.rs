//! Unified audit event schema for management and data planes (S0).
//!
//! Runtime still primarily emits structured `tracing` events with target
//! `data_nexus::audit`. Field names below are the stable contract for S4 sinks.

use serde::{Deserialize, Serialize};

/// Tracing / log target for all Data Nexus audit records.
pub const AUDIT_TARGET: &str = "data_nexus::audit";

/// Stable field names used in structured audit logs.
pub mod fields {
    pub const ACTION: &str = "action";
    pub const DECISION: &str = "decision";
    pub const SUBJECT_ID: &str = "subject_id";
    pub const DB_USER: &str = "db_user";
    pub const AUTH_METHOD: &str = "auth_method";
    pub const LISTENER: &str = "listener";
    pub const SERVICE: &str = "service";
    pub const FRONTEND_PROTOCOL: &str = "frontend_protocol";
    pub const BACKEND_PROTOCOL: &str = "backend_protocol";
    pub const COMMAND_TYPE: &str = "command_type";
    pub const ENDPOINT: &str = "endpoint";
    pub const DATABASE: &str = "database";
    pub const OUTCOME: &str = "outcome";
    pub const LATENCY_MS: &str = "latency_ms";
    pub const CODE: &str = "code";
    pub const MESSAGE: &str = "message";
    pub const METHOD: &str = "method";
    pub const PATH: &str = "path";
    pub const AUDIT_LEVEL: &str = "audit_level";
    pub const SQL_FINGERPRINT: &str = "sql_fingerprint";
}

/// High-level action category for an audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// Data-plane SQL / protocol command.
    Query,
    /// Management-plane mutating Admin API call.
    AdminWrite,
    /// Admin authentication (e.g. break-glass login).
    AdminLogin,
    /// Config reload / policy load.
    ConfigChange,
    /// Future: export / approval / etc.
    Other,
}

impl AuditAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::AdminWrite => "admin_write",
            Self::AdminLogin => "admin_login",
            Self::ConfigChange => "config_change",
            Self::Other => "other",
        }
    }
}

/// Decision / phase recorded on the audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    /// Command executed (or about to complete) without security deny.
    Execute,
    /// Plugin / circuit-break reject.
    Reject,
    /// Cross-protocol translation reject.
    TranslationReject,
    /// Explicit policy allow (S1+).
    Allow,
    /// Explicit policy deny (S1+).
    Deny,
    /// Requires approval ticket (S5+).
    RequireApproval,
}

impl AuditDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Execute => "execute",
            Self::Reject => "reject",
            Self::TranslationReject => "translation_reject",
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::RequireApproval => "require_approval",
        }
    }
}

/// Audit verbosity level (see tech architecture).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AuditLevel {
    /// Metadata only (default). No SQL text payload.
    L0,
    /// + truncated SQL text (`sql_text`).
    L1,
    /// + truncated SQL (like L1) and optional result sample (B08).
    L2,
}

impl AuditLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::L0 => "L0",
            Self::L1 => "L1",
            Self::L2 => "L2",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "L0" | "l0" => Some(Self::L0),
            "L1" | "l1" => Some(Self::L1),
            "L2" | "l2" => Some(Self::L2),
            _ => None,
        }
    }

    /// Default max SQL characters stored for L1/L2 (F32).
    pub const DEFAULT_SQL_TEXT_MAX_CHARS: usize = 2048;
}

/// Structured audit event (S0 schema; S4 persists this shape).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    /// Unix epoch milliseconds (filled by pipeline if absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listener: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontend_protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sql_fingerprint: Option<String>,
    /// Full or truncated SQL text (F32). Present only at L1+ after pipeline trim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sql_text: Option<String>,
    /// Policy rule name when decision is deny/allow-with-obligation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// Tables involved (best-effort, S4 L0).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tables: Vec<String>,
    /// B08: optional result sample (already-masked rows as JSON array-of-arrays).
    /// Hot path may attach this when `sample_enabled` and effective level is L2.
    /// Pipeline may strip it after OpenDAL upload (keeping only `sample_ref`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_body: Option<String>,
    /// B08: object key / local path reference after sample upload (or inline marker).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_ref: Option<String>,
    /// B08: number of rows included in the sample (not full result size).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_row_count: Option<u32>,
    /// B08: serialized sample bytes before truncation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_bytes: Option<u32>,
    /// B08: true when sample was truncated to `sample_max_bytes`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sample_truncated: bool,
}

/// B08 knobs used by [`apply_audit_level_payload`] and sample builders.
#[derive(Debug, Clone, Copy)]
pub struct AuditSamplePolicy {
    pub enabled: bool,
    pub max_rows: usize,
    pub max_bytes: usize,
    pub inline: bool,
}

impl Default for AuditSamplePolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            max_rows: 5,
            max_bytes: 4096,
            inline: true,
        }
    }
}

/// F32 + B08: apply audit level payload policy to an event **before** queue/index/disk.
///
/// | Level | SQL text | Sample body | Fingerprint / tables |
/// |-------|----------|-------------|----------------------|
/// | L0    | stripped | stripped    | kept                 |
/// | L1    | truncated| stripped    | kept                 |
/// | L2    | truncated| kept if `sample.enabled` and size-capped | kept |
///
/// Callers may set `sql_text` / `sample_body` freely; this function enforces the configured level.
pub fn apply_audit_level_payload(
    event: &mut AuditEvent,
    configured_level: AuditLevel,
    max_sql_chars: usize,
) {
    apply_audit_level_payload_with_sample(
        event,
        configured_level,
        max_sql_chars,
        AuditSamplePolicy::default(),
    );
}

/// Like [`apply_audit_level_payload`] but honours B08 sample policy.
pub fn apply_audit_level_payload_with_sample(
    event: &mut AuditEvent,
    configured_level: AuditLevel,
    max_sql_chars: usize,
    sample: AuditSamplePolicy,
) {
    let event_level = event
        .audit_level
        .as_deref()
        .and_then(AuditLevel::parse)
        .unwrap_or(configured_level);
    // Effective level is the *minimum* of event-requested and configured default
    // so a mis-tagged L2 event cannot store more than the deployment allows.
    let effective = min_audit_level(event_level, configured_level);
    event.audit_level = Some(effective.as_str().into());

    match effective {
        AuditLevel::L0 => {
            event.sql_text = None;
            strip_sample_fields(event);
        }
        AuditLevel::L1 => {
            if let Some(sql) = event.sql_text.take() {
                event.sql_text = Some(truncate_sql_text(&sql, max_sql_chars));
            }
            strip_sample_fields(event);
        }
        AuditLevel::L2 => {
            if let Some(sql) = event.sql_text.take() {
                event.sql_text = Some(truncate_sql_text(&sql, max_sql_chars));
            }
            if !sample.enabled {
                strip_sample_fields(event);
            } else if let Some(body) = event.sample_body.take() {
                let (kept, truncated) = truncate_sample_body(&body, sample.max_bytes);
                event.sample_truncated = event.sample_truncated || truncated;
                event.sample_bytes = Some(body.len().min(u32::MAX as usize) as u32);
                if sample.inline {
                    event.sample_body = Some(kept);
                } else {
                    // Keep body only until worker upload sets sample_ref.
                    event.sample_body = Some(kept);
                }
            }
        }
    }
}

fn strip_sample_fields(event: &mut AuditEvent) {
    event.sample_body = None;
    event.sample_ref = None;
    event.sample_row_count = None;
    event.sample_bytes = None;
    event.sample_truncated = false;
}

fn truncate_sample_body(body: &str, max_bytes: usize) -> (String, bool) {
    if max_bytes == 0 {
        return (String::new(), !body.is_empty());
    }
    if body.len() <= max_bytes {
        return (body.to_owned(), false);
    }
    // Truncate on UTF-8 char boundary.
    let mut end = max_bytes.min(body.len());
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = body[..end].to_owned();
    out.push('…');
    (out, true)
}

/// B08: build a JSON sample from column names + already-masked rows.
///
/// Shape: `{"columns":[...],"rows":[[...],...],"truncated":bool}`
/// Caps at `max_rows` and `max_bytes` (serialized). Never panics.
pub fn build_result_sample(
    columns: &[String],
    rows: &[Vec<crate::GatewayValue>],
    max_rows: usize,
    max_bytes: usize,
) -> Option<(String, u32, u32, bool)> {
    if max_rows == 0 || max_bytes == 0 {
        return None;
    }
    let take = rows.len().min(max_rows);
    let sample_rows: Vec<Vec<serde_json::Value>> = rows[..take]
        .iter()
        .map(|r| r.iter().map(gateway_value_to_json).collect())
        .collect();
    let mut payload = serde_json::json!({
        "columns": columns,
        "rows": sample_rows,
        "truncated": rows.len() > take,
    });
    let mut body = serde_json::to_string(&payload).ok()?;
    let mut truncated = rows.len() > take;
    if body.len() > max_bytes {
        // Drop rows until under cap (keep at least empty rows array).
        let mut n = take;
        while n > 0 && body.len() > max_bytes {
            n -= 1;
            let fewer: Vec<Vec<serde_json::Value>> = rows[..n]
                .iter()
                .map(|r| r.iter().map(gateway_value_to_json).collect())
                .collect();
            payload = serde_json::json!({
                "columns": columns,
                "rows": fewer,
                "truncated": true,
            });
            body = serde_json::to_string(&payload).ok()?;
            truncated = true;
        }
        if body.len() > max_bytes {
            let (kept, _) = truncate_sample_body(&body, max_bytes);
            body = kept;
            truncated = true;
        }
    }
    let bytes = body.len().min(u32::MAX as usize) as u32;
    let row_count = payload
        .get("rows")
        .and_then(|v| v.as_array())
        .map(|a| a.len().min(u32::MAX as usize) as u32)
        .unwrap_or(0);
    Some((body, row_count, bytes, truncated))
}

fn gateway_value_to_json(v: &crate::GatewayValue) -> serde_json::Value {
    use crate::GatewayValue::*;
    match v {
        Null => serde_json::Value::Null,
        Boolean(b) => serde_json::Value::Bool(*b),
        Integer(i) => serde_json::json!(*i),
        UnsignedInteger(u) => serde_json::json!(*u),
        Float(f) => {
            // JSON numbers must be finite; fall back to string for NaN/Inf.
            if f.is_finite() {
                serde_json::json!(*f)
            } else {
                serde_json::Value::String(f.to_string())
            }
        }
        Decimal(s) | String(s) => serde_json::Value::String(s.clone()),
        Bytes(b) => {
            // Hex-encode binary to keep samples text-safe and size-bounded.
            let max = 64.min(b.len());
            let mut hex = std::string::String::with_capacity(max * 2 + 3);
            for byte in &b[..max] {
                use std::fmt::Write as _;
                let _ = write!(hex, "{byte:02x}");
            }
            if b.len() > max {
                hex.push('…');
            }
            serde_json::Value::String(hex)
        }
    }
}

fn min_audit_level(a: AuditLevel, b: AuditLevel) -> AuditLevel {
    use AuditLevel::*;
    match (a, b) {
        (L0, _) | (_, L0) => L0,
        (L1, _) | (_, L1) => L1,
        (L2, L2) => L2,
    }
}

fn truncate_sql_text(sql: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let count = sql.chars().count();
    if count <= max_chars {
        return sql.to_owned();
    }
    let mut out: String = sql.chars().take(max_chars).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_decision_strings_are_stable() {
        assert_eq!(AuditAction::Query.as_str(), "query");
        assert_eq!(AuditAction::AdminWrite.as_str(), "admin_write");
        assert_eq!(AuditDecision::Execute.as_str(), "execute");
        assert_eq!(AuditDecision::TranslationReject.as_str(), "translation_reject");
    }

    #[test]
    fn audit_level_parse() {
        assert_eq!(AuditLevel::parse("L0"), Some(AuditLevel::L0));
        assert_eq!(AuditLevel::parse("l2"), Some(AuditLevel::L2));
        assert_eq!(AuditLevel::parse("full"), None);
    }

    #[test]
    fn audit_event_roundtrips_json() {
        let event = AuditEvent {
            action: Some(AuditAction::AdminWrite.as_str().into()),
            decision: Some(AuditDecision::Allow.as_str().into()),
            subject_id: Some("alice".into()),
            method: Some("POST".into()),
            path: Some("/admin/reload".into()),
            sql_text: Some("select 1".into()),
            ..AuditEvent::default()
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.subject_id.as_deref(), Some("alice"));
        assert_eq!(back.action.as_deref(), Some("admin_write"));
        assert_eq!(back.sql_text.as_deref(), Some("select 1"));
    }

    #[test]
    fn f32_l0_strips_sql_text() {
        let mut e = AuditEvent {
            audit_level: Some("L0".into()),
            sql_text: Some("SELECT secret FROM t".into()),
            sql_fingerprint: Some("fp".into()),
            tables: vec!["t".into()],
            ..AuditEvent::default()
        };
        apply_audit_level_payload(&mut e, AuditLevel::L0, 100);
        assert!(e.sql_text.is_none());
        assert_eq!(e.sql_fingerprint.as_deref(), Some("fp"));
        assert_eq!(e.tables, vec!["t".to_string()]);
        assert_eq!(e.audit_level.as_deref(), Some("L0"));
    }

    #[test]
    fn f32_l1_truncates_sql_text() {
        let mut e = AuditEvent {
            audit_level: Some("L1".into()),
            sql_text: Some("abcdefghijklmnopqrstuvwxyz".into()),
            ..AuditEvent::default()
        };
        apply_audit_level_payload(&mut e, AuditLevel::L1, 10);
        assert_eq!(e.sql_text.as_deref(), Some("abcdefghij…"));
    }

    #[test]
    fn f32_configured_l0_caps_event_l2() {
        let mut e = AuditEvent {
            audit_level: Some("L2".into()),
            sql_text: Some("SELECT 1".into()),
            ..AuditEvent::default()
        };
        apply_audit_level_payload(&mut e, AuditLevel::L0, 2048);
        assert!(e.sql_text.is_none());
        assert_eq!(e.audit_level.as_deref(), Some("L0"));
    }

    #[test]
    fn b08_l1_strips_sample_body() {
        let mut e = AuditEvent {
            audit_level: Some("L1".into()),
            sql_text: Some("SELECT 1".into()),
            sample_body: Some(r#"{"rows":[]}"#.into()),
            sample_row_count: Some(0),
            ..AuditEvent::default()
        };
        apply_audit_level_payload_with_sample(
            &mut e,
            AuditLevel::L1,
            100,
            AuditSamplePolicy {
                enabled: true,
                max_rows: 5,
                max_bytes: 4096,
                inline: true,
            },
        );
        assert!(e.sample_body.is_none());
        assert!(e.sql_text.is_some());
    }

    #[test]
    fn b08_l2_keeps_sample_when_enabled() {
        let mut e = AuditEvent {
            audit_level: Some("L2".into()),
            sql_text: Some("SELECT id FROM t".into()),
            sample_body: Some(r#"{"columns":["id"],"rows":[[1]],"truncated":false}"#.into()),
            sample_row_count: Some(1),
            ..AuditEvent::default()
        };
        apply_audit_level_payload_with_sample(
            &mut e,
            AuditLevel::L2,
            100,
            AuditSamplePolicy {
                enabled: true,
                max_rows: 5,
                max_bytes: 4096,
                inline: true,
            },
        );
        assert!(e.sample_body.as_deref().unwrap().contains("rows"));
        assert_eq!(e.audit_level.as_deref(), Some("L2"));
    }

    #[test]
    fn b08_l2_disabled_strips_sample() {
        let mut e = AuditEvent {
            audit_level: Some("L2".into()),
            sample_body: Some(r#"{"rows":[[1]]}"#.into()),
            ..AuditEvent::default()
        };
        apply_audit_level_payload_with_sample(
            &mut e,
            AuditLevel::L2,
            100,
            AuditSamplePolicy::default(), // enabled=false
        );
        assert!(e.sample_body.is_none());
    }

    #[test]
    fn b08_build_result_sample_caps_rows() {
        use crate::GatewayValue;
        let cols = vec!["id".into(), "name".into()];
        let rows: Vec<Vec<GatewayValue>> = (0..20)
            .map(|i| vec![GatewayValue::Integer(i), GatewayValue::String(format!("r{i}"))])
            .collect();
        let (body, n, _bytes, truncated) =
            build_result_sample(&cols, &rows, 3, 4096).expect("sample");
        assert_eq!(n, 3);
        assert!(truncated);
        assert!(body.contains("\"truncated\":true"));
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["rows"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn b08_build_result_sample_caps_bytes() {
        use crate::GatewayValue;
        let cols = vec!["blob".into()];
        let rows = vec![vec![GatewayValue::String("x".repeat(200))]];
        let (body, _n, bytes, truncated) =
            build_result_sample(&cols, &rows, 5, 80).expect("sample");
        assert!(truncated || body.len() <= 81);
        assert!(bytes as usize <= body.len().max(80) + 4);
        assert!(body.len() <= 81); // max_bytes + ellipsis
    }
}
