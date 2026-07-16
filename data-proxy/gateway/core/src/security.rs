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
            "local" | "cedar" | "remote" => {}
            other => {
                return Err(GatewayError::Configuration(format!(
                    "security.pdp.backend must be local, cedar, or remote, got '{other}'"
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
    #[serde(default = "default_overflow")]
    pub overflow: String,
    #[serde(default = "default_audit_sinks")]
    pub sinks: Vec<String>,
    #[serde(default)]
    pub file_path: String,
}

fn default_queue_capacity() -> u32 {
    65_536
}

fn default_overflow() -> String {
    "drop_new".into()
}

fn default_audit_sinks() -> Vec<String> {
    vec!["tracing".into()]
}

impl Default for SecurityAuditConfig {
    fn default() -> Self {
        Self {
            queue_capacity: default_queue_capacity(),
            overflow: default_overflow(),
            sinks: default_audit_sinks(),
            file_path: String::new(),
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
}
