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
    /// + sample refs (B08); SQL text same as L1 until samples land.
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
}

/// F32: apply audit level payload policy to an event **before** queue/index/disk.
///
/// | Level | SQL text | Fingerprint | Tables / metadata |
/// |-------|----------|-------------|-------------------|
/// | L0    | stripped | kept        | kept              |
/// | L1/L2 | truncated (max_chars) | kept | kept |
///
/// Callers may set `sql_text` freely; this function enforces the configured level.
pub fn apply_audit_level_payload(
    event: &mut AuditEvent,
    configured_level: AuditLevel,
    max_sql_chars: usize,
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
        }
        AuditLevel::L1 | AuditLevel::L2 => {
            if let Some(sql) = event.sql_text.take() {
                event.sql_text = Some(truncate_sql_text(&sql, max_sql_chars));
            }
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
}
