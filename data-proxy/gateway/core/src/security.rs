//! Data-plane security configuration shell (S0).
//!
//! Default is **off**: existing gateway behaviour is unchanged until
//! `security.enabled = true` and later stages implement PDP/PEP.

use serde::{Deserialize, Serialize};

use crate::{GatewayError, GatewayResult};

/// Top-level data-plane security policy (management plane uses `admin_auth`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityPolicyConfig {
    /// Master switch. False keeps pure protocol-gateway behaviour.
    #[serde(default)]
    pub enabled: bool,
    /// When true, parse/policy failures deny access (safer). Default true.
    #[serde(default = "default_true")]
    pub fail_closed: bool,
    /// How `SELECT *` is treated when column ACL rules apply: `deny` | `allow`.
    #[serde(default = "default_star_policy")]
    pub star_policy: String,
    /// Default audit verbosity for data-plane commands: L0 | L1 | L2.
    #[serde(default = "default_audit_level")]
    pub default_audit_level: String,
    #[serde(default)]
    pub subject: SecuritySubjectConfig,
    #[serde(default)]
    pub pdp: SecurityPdpConfig,
    #[serde(default)]
    pub streaming: SecurityStreamingConfig,
    #[serde(default)]
    pub audit: SecurityAuditConfig,
    /// Rule list for Local PDP (ignored while `enabled` is false).
    #[serde(default)]
    pub rules: Vec<SecurityRuleConfig>,
    /// Named mask algorithms bound by column label or name (S3).
    #[serde(default)]
    pub mask_rules: Vec<SecurityMaskRuleConfig>,
    /// Column sensitivity labels → mask rule name (S3).
    #[serde(default)]
    pub column_tags: Vec<SecurityColumnTagConfig>,
    /// High-risk rules that require a ticket (S5).
    #[serde(default)]
    pub high_risk_rules: Vec<SecurityHighRiskRuleConfig>,
    /// Time-window rules (F27): e.g. writes only during business hours.
    #[serde(default)]
    pub time_rules: Vec<crate::time_rules::SecurityTimeRuleConfig>,
    /// Visible result watermark (F14).
    #[serde(default)]
    pub watermark: SecurityWatermarkConfig,
    /// H05: multi-instance state backend for ticket/vault (process-local by default).
    #[serde(default)]
    pub state: SecurityStateConfig,
}

/// H05: shared state for ticket / vault / Local PDP snapshot across gateway processes.
///
/// | backend | ticket | vault | Local PDP snapshot |
/// |---------|--------|-------|--------------------|
/// | `memory` (default) | process HashMap | process HashMap | process Arc only |
/// | `file` | JSON + lock | JSON + lock (no passwords) | optional `policy_path` JSON + lock |
///
/// `redis` / remote backends are **rejected** until implemented (no silent no-op).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityStateConfig {
    /// `memory` | `file`. Default `memory`.
    #[serde(default = "default_state_backend")]
    pub backend: String,
    /// Ticket JSON path when `backend=file` (required).
    #[serde(default)]
    pub ticket_path: String,
    /// Vault lease JSON path when `backend=file` (required).
    /// Stores public lease fields + projects; with `vault_encrypt_key` the file is
    /// AES-GCM sealed and may include backend secrets for multi-instance recovery
    /// (H05/H08). Without a key, passwords are never written (H03).
    #[serde(default)]
    pub vault_path: String,
    /// Optional 32-byte vault file encryption key as **64 hex chars** (H05/H08).
    /// Empty = plaintext JSON metadata only (no backend passwords on disk).
    /// Prefer injecting via env at deploy; do not commit real keys.
    #[serde(default)]
    pub vault_encrypt_key: String,
    /// Optional 32-byte ticket file encryption key as **64 hex chars** (H05).
    /// Empty = plaintext ticket JSON. Protects sql_sample / subject metadata at rest.
    #[serde(default)]
    pub ticket_encrypt_key: String,
    /// Optional Local PDP hot-reloadable snapshot path (H05).
    /// When set (typically with `backend=file`), rules/mask/time/watermark are
    /// shared across processes via JSON + advisory lock. Empty = process-local only.
    #[serde(default)]
    pub policy_path: String,
    /// H05: how often (ms) to `stat` `policy_path` for cross-process mtime reload.
    /// `0` disables polling (admin reload / install only). Default `1000`.
    #[serde(default = "default_policy_poll_ms")]
    pub policy_poll_ms: u64,
}

impl Default for SecurityStateConfig {
    fn default() -> Self {
        Self {
            backend: default_state_backend(),
            ticket_path: String::new(),
            vault_path: String::new(),
            vault_encrypt_key: String::new(),
            ticket_encrypt_key: String::new(),
            policy_path: String::new(),
            policy_poll_ms: default_policy_poll_ms(),
        }
    }
}

fn default_policy_poll_ms() -> u64 {
    1000
}

fn default_state_backend() -> String {
    "memory".into()
}

fn default_star_policy() -> String {
    "deny".into()
}

fn default_true() -> bool {
    true
}

fn default_audit_level() -> String {
    "L0".into()
}

impl Default for SecurityPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            fail_closed: true,
            star_policy: default_star_policy(),
            default_audit_level: default_audit_level(),
            subject: SecuritySubjectConfig::default(),
            pdp: SecurityPdpConfig::default(),
            streaming: SecurityStreamingConfig::default(),
            audit: SecurityAuditConfig::default(),
            rules: Vec::new(),
            mask_rules: Vec::new(),
            column_tags: Vec::new(),
            high_risk_rules: Vec::new(),
            time_rules: Vec::new(),
            watermark: SecurityWatermarkConfig::default(),
            state: SecurityStateConfig::default(),
        }
    }
}

impl SecurityPolicyConfig {
    pub fn validate(&self) -> GatewayResult<()> {
        match self.star_policy.to_ascii_lowercase().as_str() {
            "deny" | "allow" => {}
            other => {
                return Err(GatewayError::Configuration(format!(
                    "security.star_policy must be deny or allow, got '{other}'"
                )));
            }
        }

        match self.default_audit_level.as_str() {
            "L0" | "L1" | "L2" | "l0" | "l1" | "l2" => {}
            other => {
                return Err(GatewayError::Configuration(format!(
                    "security.default_audit_level must be L0, L1, or L2, got '{other}'"
                )));
            }
        }

        match self.pdp.backend.as_str() {
            "local" => {}
            "cedar" => {
                #[cfg(not(feature = "security-cedar"))]
                {
                    return Err(GatewayError::Configuration(
                        "security.pdp.backend=cedar requires building with --features security-cedar (and rustc ≥1.88)"
                            .into(),
                    ));
                }
                #[cfg(feature = "security-cedar")]
                {
                    if self.pdp.policy_dir.trim().is_empty() {
                        return Err(GatewayError::Configuration(
                            "security.pdp.backend=cedar requires non-empty security.pdp.policy_dir"
                                .into(),
                        ));
                    }
                }
            }
            // F31 not implemented: reject early so configs cannot "pass validate and no-op".
            "remote" => {
                return Err(GatewayError::Configuration(
                    "security.pdp.backend=remote is not implemented yet (F31 Remote PDP); use local or cedar"
                        .into(),
                ));
            }
            other => {
                return Err(GatewayError::Configuration(format!(
                    "security.pdp.backend must be local or cedar (remote reserved for F31), got '{other}'"
                )));
            }
        }

        match self.audit.overflow.as_str() {
            "drop_new" | "drop_old" | "sample" | "block" => {}
            other => {
                return Err(GatewayError::Configuration(format!(
                    "security.audit.overflow must be drop_new, drop_old, sample, or block, got '{other}'"
                )));
            }
        }

        if self.streaming.window_rows == 0 {
            return Err(GatewayError::Configuration(
                "security.streaming.window_rows must be >= 1".into(),
            ));
        }

        if self.audit.queue_capacity == 0 {
            return Err(GatewayError::Configuration(
                "security.audit.queue_capacity must be >= 1".into(),
            ));
        }

        for (idx, rule) in self.rules.iter().enumerate() {
            if rule.name.trim().is_empty() {
                return Err(GatewayError::Configuration(format!(
                    "security.rules[{idx}].name must not be empty"
                )));
            }
            match rule.effect.as_str() {
                "allow" | "deny" => {}
                other => {
                    return Err(GatewayError::Configuration(format!(
                        "security.rules[{idx}].effect must be allow or deny, got '{other}'"
                    )));
                }
            }
        }

        for (idx, mask) in self.mask_rules.iter().enumerate() {
            if mask.name.trim().is_empty() {
                return Err(GatewayError::Configuration(format!(
                    "security.mask_rules[{idx}].name must not be empty"
                )));
            }
            if crate::obligations::MaskAlgorithm::parse(&mask.algorithm).is_none() {
                return Err(GatewayError::Configuration(format!(
                    "security.mask_rules[{idx}].algorithm must be nullify|partial|hash|replace|keep_prefix, got '{}'",
                    mask.algorithm
                )));
            }
        }

        for (idx, tag) in self.column_tags.iter().enumerate() {
            if tag.column.trim().is_empty() {
                return Err(GatewayError::Configuration(format!(
                    "security.column_tags[{idx}].column must not be empty"
                )));
            }
            if tag.mask_rule.trim().is_empty() {
                return Err(GatewayError::Configuration(format!(
                    "security.column_tags[{idx}].mask_rule must not be empty"
                )));
            }
            if !self
                .mask_rules
                .iter()
                .any(|m| m.name.eq_ignore_ascii_case(&tag.mask_rule))
            {
                return Err(GatewayError::Configuration(format!(
                    "security.column_tags[{idx}].mask_rule '{}' not found in mask_rules",
                    tag.mask_rule
                )));
            }
        }

        for (idx, hr) in self.high_risk_rules.iter().enumerate() {
            if hr.name.trim().is_empty() {
                return Err(GatewayError::Configuration(format!(
                    "security.high_risk_rules[{idx}].name must not be empty"
                )));
            }
            if hr.ticket_type.trim().is_empty() {
                return Err(GatewayError::Configuration(format!(
                    "security.high_risk_rules[{idx}].ticket_type must not be empty"
                )));
            }
            match hr.kind.to_ascii_lowercase().as_str() {
                "ddl" | "write_no_where" | "action" | "table_write" | "export" => {}
                other => {
                    return Err(GatewayError::Configuration(format!(
                        "security.high_risk_rules[{idx}].kind must be ddl|write_no_where|action|table_write|export, got '{other}'"
                    )));
                }
            }
        }

        for (idx, tr) in self.time_rules.iter().enumerate() {
            tr.validate(idx)?;
        }

        match self.watermark.mode.to_ascii_lowercase().as_str() {
            "column" | "suffix" | "" => {}
            other => {
                return Err(GatewayError::Configuration(format!(
                    "security.watermark.mode must be column or suffix, got '{other}'"
                )));
            }
        }

        // H05 state backend
        match self.state.backend.trim().to_ascii_lowercase().as_str() {
            "memory" | "" => {
                // policy_path may still be set for optional shared Local PDP snapshot
                // even on memory ticket/vault (ops choice).
            }
            "file" => {
                if self.state.ticket_path.trim().is_empty() {
                    return Err(GatewayError::Configuration(
                        "security.state.backend=file requires non-empty security.state.ticket_path"
                            .into(),
                    ));
                }
                if self.state.vault_path.trim().is_empty() {
                    return Err(GatewayError::Configuration(
                        "security.state.backend=file requires non-empty security.state.vault_path"
                            .into(),
                    ));
                }
            }
            "redis" | "remote" => {
                return Err(GatewayError::Configuration(format!(
                    "security.state.backend='{}' is not implemented yet (H05); use memory or file",
                    self.state.backend
                )));
            }
            other => {
                return Err(GatewayError::Configuration(format!(
                    "security.state.backend must be memory or file, got '{other}'"
                )));
            }
        }

        // H05/H08: optional encrypt keys must be 64 hex chars (32 bytes).
        for (name, key) in [
            ("vault_encrypt_key", self.state.vault_encrypt_key.trim()),
            ("ticket_encrypt_key", self.state.ticket_encrypt_key.trim()),
        ] {
            if !key.is_empty()
                && (key.len() != 64 || !key.chars().all(|c| c.is_ascii_hexdigit()))
            {
                return Err(GatewayError::Configuration(format!(
                    "security.state.{name} must be empty or 64 hex characters (AES-256 key)"
                )));
            }
        }

        // enabled=true is a pre-staged shell; PDP stages validate at runtime.
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecuritySubjectConfig {
    /// How to bind data-plane identity (S1+). Defaults are documentation only in S0.
    #[serde(default = "default_subject_sources")]
    pub sources: Vec<String>,
}

fn default_subject_sources() -> Vec<String> {
    vec!["protocol_user".into()]
}

impl Default for SecuritySubjectConfig {
    fn default() -> Self {
        Self {
            sources: default_subject_sources(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityPdpConfig {
    #[serde(default = "default_pdp_backend")]
    pub backend: String,
    #[serde(default)]
    pub policy_dir: String,
    #[serde(default = "default_true")]
    pub cache_epoch_reload: bool,
}

fn default_pdp_backend() -> String {
    "local".into()
}

impl Default for SecurityPdpConfig {
    fn default() -> Self {
        Self {
            backend: default_pdp_backend(),
            policy_dir: String::new(),
            cache_epoch_reload: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityStreamingConfig {
    #[serde(default = "default_window_rows")]
    pub window_rows: u32,
    #[serde(default)]
    pub max_rows: Option<u64>,
    #[serde(default)]
    pub max_bytes: Option<u64>,
    #[serde(default = "default_true")]
    pub passthrough: bool,
}

fn default_window_rows() -> u32 {
    256
}

impl Default for SecurityStreamingConfig {
    fn default() -> Self {
        Self {
            window_rows: default_window_rows(),
            max_rows: None,
            max_bytes: None,
            passthrough: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityAuditConfig {
    #[serde(default = "default_queue_capacity")]
    pub queue_capacity: u32,
    /// Bounded queue for high-priority decisions (`deny` / `require_approval`). B07.
    /// Independent of `queue_capacity` so `drop_new` floods cannot discard critical events.
    /// `0` disables the separate queue (all events share the main queue).
    #[serde(default = "default_priority_queue_capacity")]
    pub priority_queue_capacity: u32,
    #[serde(default = "default_overflow")]
    pub overflow: String,
    #[serde(default = "default_audit_sinks")]
    pub sinks: Vec<String>,
    #[serde(default)]
    pub file_path: String,
    /// Rotate active JSONL when size ≥ this many bytes (0 = never by size). B04.
    #[serde(default)]
    pub max_file_bytes: u64,
    /// Delete rotated files older than this many days (0 = no age prune). B04.
    #[serde(default = "default_retain_days")]
    pub retain_days: u32,
    /// Keep at most this many rotated siblings (0 = unlimited count). B04.
    #[serde(default = "default_rotate_keep")]
    pub rotate_keep: u32,
    /// Directory to move/copy rotated files into (empty = same dir as file_path). B04.
    #[serde(default)]
    pub archive_dir: String,
    /// OpenDAL scheme when feature `audit-opendal` is enabled: `fs` | `memory` | `s3` | `oss` | empty=off.
    #[serde(default)]
    pub opendal_scheme: String,
    /// OpenDAL root. For `fs`: local path (empty → `archive_dir` or parent of `file_path`).
    /// For `s3`/`oss`/`memory`: object-key prefix root only (never inherits host paths).
    #[serde(default)]
    pub opendal_root: String,
    /// Object key prefix for archived files (e.g. `audit/`).
    #[serde(default)]
    pub opendal_prefix: String,
    /// S3/OSS bucket (required when scheme is s3 or oss).
    #[serde(default)]
    pub opendal_bucket: String,
    /// S3/OSS endpoint URL (optional for AWS default; required for OSS/minio).
    #[serde(default)]
    pub opendal_endpoint: String,
    /// S3 region (e.g. `us-east-1`).
    #[serde(default)]
    pub opendal_region: String,
    /// Access key id (or set env `DN_OPENDAL_ACCESS_KEY_ID` / `AWS_ACCESS_KEY_ID`).
    #[serde(default)]
    pub opendal_access_key_id: String,
    /// Secret key (or env `DN_OPENDAL_SECRET_ACCESS_KEY` / `AWS_SECRET_ACCESS_KEY`). Never log.
    #[serde(default)]
    pub opendal_secret_access_key: String,
    /// Optional session token (or env `DN_OPENDAL_SESSION_TOKEN` / `AWS_SESSION_TOKEN`).
    #[serde(default)]
    pub opendal_session_token: String,
    /// B06: SQLite side-index path for Admin audit search.
    /// Empty = disabled (query falls back to in-memory recent ring).
    /// Example: `/var/log/data-nexus/audit/index.sqlite`.
    #[serde(default)]
    pub index_path: String,
    /// F32: max characters of SQL stored at L1/L2 (`sql_text`). Default 2048.
    #[serde(default = "default_sql_text_max_chars")]
    pub sql_text_max_chars: u32,
}

fn default_queue_capacity() -> u32 {
    65_536
}

fn default_priority_queue_capacity() -> u32 {
    1_024
}

fn default_overflow() -> String {
    "drop_new".into()
}

fn default_audit_sinks() -> Vec<String> {
    vec!["tracing".into()]
}

fn default_retain_days() -> u32 {
    7
}

fn default_rotate_keep() -> u32 {
    32
}

fn default_sql_text_max_chars() -> u32 {
    2048
}

impl Default for SecurityAuditConfig {
    fn default() -> Self {
        Self {
            queue_capacity: default_queue_capacity(),
            priority_queue_capacity: default_priority_queue_capacity(),
            overflow: default_overflow(),
            sinks: default_audit_sinks(),
            file_path: String::new(),
            max_file_bytes: 0,
            retain_days: default_retain_days(),
            rotate_keep: default_rotate_keep(),
            archive_dir: String::new(),
            opendal_scheme: String::new(),
            opendal_root: String::new(),
            opendal_prefix: String::new(),
            opendal_bucket: String::new(),
            opendal_endpoint: String::new(),
            opendal_region: String::new(),
            opendal_access_key_id: String::new(),
            opendal_secret_access_key: String::new(),
            opendal_session_token: String::new(),
            index_path: String::new(),
            sql_text_max_chars: default_sql_text_max_chars(),
        }
    }
}

/// Rule entry consumed by Local PDP (S1 table/statement, S2 columns, S3 row filter).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityRuleConfig {
    pub name: String,
    #[serde(default = "default_rule_effect")]
    pub effect: String,
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default)]
    pub tables: Vec<String>,
    /// Column globs (bare or `table.col`). Empty = table-level only.
    #[serde(default)]
    pub columns: Vec<String>,
    #[serde(default)]
    pub subjects: Vec<String>,
    /// Optional static SQL predicate injected on Allow for matching SELECTs (S3).
    #[serde(default)]
    pub row_filter: Option<String>,
}

fn default_rule_effect() -> String {
    "deny".into()
}

/// Named mask algorithm definition (S3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityMaskRuleConfig {
    pub name: String,
    /// nullify | partial | hash | replace | keep_prefix
    pub algorithm: String,
    #[serde(default)]
    pub replace_with: String,
    #[serde(default = "default_mask_prefix")]
    pub prefix_len: usize,
    #[serde(default = "default_mask_suffix")]
    pub suffix_len: usize,
}

fn default_mask_prefix() -> usize {
    3
}

fn default_mask_suffix() -> usize {
    2
}

/// Bind a column name/glob to a mask rule (S3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityColumnTagConfig {
    /// Column name glob (bare or `table.col`).
    pub column: String,
    /// Optional table glob; empty = any table.
    #[serde(default)]
    pub tables: Vec<String>,
    /// Optional subject glob list; empty = all subjects.
    #[serde(default)]
    pub subjects: Vec<String>,
    /// Reference to [`SecurityMaskRuleConfig::name`].
    pub mask_rule: String,
    /// Optional label for audit (e.g. PII, phone).
    #[serde(default)]
    pub label: String,
}

/// Visible watermark applied on Allow result sets (F14).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityWatermarkConfig {
    #[serde(default)]
    pub enabled: bool,
    /// column | suffix
    #[serde(default = "default_wm_mode")]
    pub mode: String,
    /// Column name for mode=column (default `_dn_wm`).
    #[serde(default = "default_wm_column")]
    pub column: String,
    /// Optional static token; empty → per-query auto token from subject+time.
    #[serde(default)]
    pub token: String,
}

fn default_wm_mode() -> String {
    "column".into()
}

fn default_wm_column() -> String {
    "_dn_wm".into()
}

impl Default for SecurityWatermarkConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: default_wm_mode(),
            column: default_wm_column(),
            token: String::new(),
        }
    }
}

/// High-risk gate requiring a short-lived ticket (S5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityHighRiskRuleConfig {
    pub name: String,
    /// ddl | write_no_where | action | table_write | export
    pub kind: String,
    /// Ticket type required (e.g. ddl, high_risk).
    #[serde(default = "default_ticket_type")]
    pub ticket_type: String,
    /// For kind=action: statement actions (ddl, delete, update, …).
    #[serde(default)]
    pub actions: Vec<String>,
    /// For kind=table_write: table globs.
    #[serde(default)]
    pub tables: Vec<String>,
    /// Optional subject globs; empty = all.
    #[serde(default)]
    pub subjects: Vec<String>,
    /// Human message fragment.
    #[serde(default)]
    pub message: String,
}

fn default_ticket_type() -> String {
    "high_risk".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_disabled_and_valid() {
        let cfg = SecurityPolicyConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.fail_closed);
        assert_eq!(cfg.validate(), Ok(()));
    }

    #[test]
    fn rejects_bad_audit_level() {
        let mut cfg = SecurityPolicyConfig::default();
        cfg.default_audit_level = "full".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_bad_pdp_backend() {
        let mut cfg = SecurityPolicyConfig::default();
        cfg.pdp.backend = "opa".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_remote_pdp_until_f31() {
        let mut cfg = SecurityPolicyConfig::default();
        cfg.pdp.backend = "remote".into();
        let err = cfg.validate().expect_err("remote must fail closed until F31");
        let msg = err.to_string();
        assert!(
            msg.contains("remote") && msg.contains("F31"),
            "unexpected message: {msg}"
        );
    }

    #[test]
    fn rejects_empty_rule_name() {
        let mut cfg = SecurityPolicyConfig::default();
        cfg.rules.push(SecurityRuleConfig {
            name: "  ".into(),
            effect: "deny".into(),
            actions: vec![],
            tables: vec![],
            columns: vec![],
            subjects: vec![],
            row_filter: None,
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn accepts_pre_staged_enabled_shell() {
        let mut cfg = SecurityPolicyConfig::default();
        cfg.enabled = true;
        cfg.rules.push(SecurityRuleConfig {
            name: "deny-secret".into(),
            effect: "deny".into(),
            actions: vec!["select".into()],
            tables: vec!["*.*.secret_*".into()],
            columns: vec![],
            subjects: vec![],
            row_filter: None,
        });
        assert_eq!(cfg.validate(), Ok(()));
    }

    #[test]
    fn rejects_bad_star_policy() {
        let mut cfg = SecurityPolicyConfig::default();
        cfg.star_policy = "expand".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn cedar_backend_requires_feature_or_policy_dir() {
        let mut cfg = SecurityPolicyConfig::default();
        cfg.pdp.backend = "cedar".into();
        cfg.pdp.policy_dir = String::new();
        let err = cfg.validate().unwrap_err().to_string();
        #[cfg(feature = "security-cedar")]
        assert!(err.contains("policy_dir"), "{err}");
        #[cfg(not(feature = "security-cedar"))]
        assert!(err.contains("security-cedar") || err.contains("feature"), "{err}");
    }


    #[test]
    fn h05_state_file_requires_paths() {
        let mut cfg = SecurityPolicyConfig::default();
        cfg.state.backend = "file".into();
        assert!(cfg.validate().is_err());
        cfg.state.ticket_path = "/tmp/tickets.json".into();
        assert!(cfg.validate().is_err());
        cfg.state.vault_path = "/tmp/vault.json".into();
        assert_eq!(cfg.validate(), Ok(()));
    }

    #[test]
    fn h05_state_redis_rejected() {
        let mut cfg = SecurityPolicyConfig::default();
        cfg.state.backend = "redis".into();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("not implemented") || err.contains("H05"), "{err}");
    }

    #[test]
    fn h05_vault_encrypt_key_validation() {
        let mut cfg = SecurityPolicyConfig::default();
        cfg.state.backend = "file".into();
        cfg.state.ticket_path = "/tmp/t.json".into();
        cfg.state.vault_path = "/tmp/v.json".into();
        cfg.state.vault_encrypt_key = "short".into();
        assert!(cfg.validate().is_err());
        cfg.state.vault_encrypt_key =
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".into();
        assert_eq!(cfg.validate(), Ok(()));
        cfg.state.ticket_encrypt_key = "nope".into();
        assert!(cfg.validate().is_err());
        cfg.state.ticket_encrypt_key =
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".into();
        assert_eq!(cfg.validate(), Ok(()));
    }
}
