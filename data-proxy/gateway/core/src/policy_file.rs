//! H05: file-backed Local PDP policy snapshot for multi-instance.
//!
//! When `security.state.backend=file` and `security.state.policy_path` is set, the
//! hot-reloadable Local PDP fields (rules / mask / tags / high-risk / time /
//! watermark / streaming.max_rows / fail_closed / star_policy) are shared via a
//! JSON file with advisory locks (same pattern as ticket/vault).
//!
//! **Not** shared: enabled/subject/pdp backend/streaming window/passthrough
//! (listener-rebuild fields stay in gateway config). Cedar policy_dir remains
//! process-local (F26b).

use crate::{
    SecurityColumnTagConfig, SecurityHighRiskRuleConfig, SecurityMaskRuleConfig,
    SecurityPolicyConfig, SecurityRuleConfig, SecurityTimeRuleConfig, SecurityWatermarkConfig,
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Subset of security config that Local PDP hot-reload may share across processes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct LocalPdpPolicyFile {
    #[serde(default)]
    pub fail_closed: bool,
    #[serde(default = "default_star")]
    pub star_policy: String,
    #[serde(default)]
    pub rules: Vec<SecurityRuleConfig>,
    #[serde(default)]
    pub mask_rules: Vec<SecurityMaskRuleConfig>,
    #[serde(default)]
    pub column_tags: Vec<SecurityColumnTagConfig>,
    #[serde(default)]
    pub high_risk_rules: Vec<SecurityHighRiskRuleConfig>,
    #[serde(default)]
    pub time_rules: Vec<SecurityTimeRuleConfig>,
    #[serde(default)]
    pub watermark: SecurityWatermarkConfig,
    /// Mirrors `security.streaming.max_rows` (hot-reloadable default max).
    #[serde(default)]
    pub default_max_rows: Option<u64>,
}

fn default_star() -> String {
    "deny".into()
}

impl LocalPdpPolicyFile {
    pub fn from_security(config: &SecurityPolicyConfig) -> Self {
        Self {
            fail_closed: config.fail_closed,
            star_policy: config.star_policy.clone(),
            rules: config.rules.clone(),
            mask_rules: config.mask_rules.clone(),
            column_tags: config.column_tags.clone(),
            high_risk_rules: config.high_risk_rules.clone(),
            time_rules: config.time_rules.clone(),
            watermark: config.watermark.clone(),
            default_max_rows: config.streaming.max_rows,
        }
    }

    /// Overlay hot-reloadable fields onto a full security config (clone base first).
    pub fn apply_to(&self, config: &mut SecurityPolicyConfig) {
        config.fail_closed = self.fail_closed;
        config.star_policy = self.star_policy.clone();
        config.rules = self.rules.clone();
        config.mask_rules = self.mask_rules.clone();
        config.column_tags = self.column_tags.clone();
        config.high_risk_rules = self.high_risk_rules.clone();
        config.time_rules = self.time_rules.clone();
        config.watermark = self.watermark.clone();
        config.streaming.max_rows = self.default_max_rows;
    }
}

/// Load policy snapshot from disk (shared lock). Missing file → `None`.
pub fn load_local_pdp_policy_file(path: &str) -> Result<Option<LocalPdpPolicyFile>, String> {
    let path = path.trim();
    if path.is_empty() {
        return Ok(None);
    }
    let path = PathBuf::from(path);
    if !path.exists() {
        return Ok(None);
    }
    let lock = open_state_lock(&path)?;
    lock.lock_shared().map_err(|e| e.to_string())?;
    let mut f = File::open(&path).map_err(|e| e.to_string())?;
    let mut raw = String::new();
    f.read_to_string(&mut raw).map_err(|e| e.to_string())?;
    let _ = lock.unlock();
    if raw.trim().is_empty() {
        return Ok(None);
    }
    let file: LocalPdpPolicyFile = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    Ok(Some(file))
}

/// Persist policy snapshot (exclusive lock, atomic rename).
pub fn save_local_pdp_policy_file(
    path: &str,
    snapshot: &LocalPdpPolicyFile,
) -> Result<(), String> {
    let path = path.trim();
    if path.is_empty() {
        return Ok(());
    }
    let path = PathBuf::from(path);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
    }
    let lock = open_state_lock(&path)?;
    lock.lock_exclusive().map_err(|e| e.to_string())?;
    let tmp = path.with_extension("json.tmp");
    let data = serde_json::to_vec_pretty(snapshot).map_err(|e| e.to_string())?;
    fs::write(&tmp, data).map_err(|e| e.to_string())?;
    fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    let _ = lock.unlock();
    Ok(())
}

/// If `policy_path` is set: load overlay when present, else seed file from `config`.
/// Returns config with shared fields applied (or original clone if path empty).
pub fn merge_local_pdp_from_file(config: &SecurityPolicyConfig) -> Result<SecurityPolicyConfig, String> {
    let path = config.state.policy_path.trim();
    if path.is_empty() {
        return Ok(config.clone());
    }
    match load_local_pdp_policy_file(path)? {
        Some(snap) => {
            let mut out = config.clone();
            snap.apply_to(&mut out);
            Ok(out)
        }
        None => {
            // Seed shared file so sibling processes can read the same rules.
            let snap = LocalPdpPolicyFile::from_security(config);
            save_local_pdp_policy_file(path, &snap)?;
            Ok(config.clone())
        }
    }
}

/// After admin hot-reload: write current hot-reloadable fields to shared file.
pub fn persist_local_pdp_to_file(config: &SecurityPolicyConfig) -> Result<(), String> {
    let path = config.state.policy_path.trim();
    if path.is_empty() {
        return Ok(());
    }
    save_local_pdp_policy_file(path, &LocalPdpPolicyFile::from_security(config))
}

fn open_state_lock(path: &Path) -> Result<File, String> {
    let lock_path = path.with_extension("json.lock");
    OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(lock_path)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecurityStreamingConfig;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp(tag: &str) -> PathBuf {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        std::env::temp_dir().join(format!("dn-h05-policy-{tag}-{ms}.json"))
    }

    #[test]
    fn h05_policy_file_roundtrip() {
        let path = tmp("rt");
        let mut cfg = SecurityPolicyConfig::default();
        cfg.enabled = true;
        cfg.fail_closed = false;
        cfg.star_policy = "allow".into();
        cfg.rules.push(SecurityRuleConfig {
            name: "r1".into(),
            effect: "allow".into(),
            actions: vec!["select".into()],
            tables: vec!["t".into()],
            columns: vec![],
            subjects: vec![],
            row_filter: None,
        });
        cfg.streaming = SecurityStreamingConfig {
            window_rows: 128,
            max_rows: Some(50),
            passthrough: true,
            max_bytes: None,
        };
        cfg.state.policy_path = path.to_string_lossy().into();

        save_local_pdp_policy_file(path.to_str().unwrap(), &LocalPdpPolicyFile::from_security(&cfg))
            .unwrap();
        let loaded = load_local_pdp_policy_file(path.to_str().unwrap())
            .unwrap()
            .expect("file");
        assert_eq!(loaded.star_policy, "allow");
        assert!(!loaded.fail_closed);
        assert_eq!(loaded.rules.len(), 1);
        assert_eq!(loaded.default_max_rows, Some(50));

        let mut other = SecurityPolicyConfig::default();
        other.enabled = true;
        other.star_policy = "deny".into();
        loaded.apply_to(&mut other);
        assert_eq!(other.star_policy, "allow");
        assert_eq!(other.rules[0].name, "r1");
        assert_eq!(other.streaming.max_rows, Some(50));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("json.lock"));
    }

    #[test]
    fn h05_merge_seeds_missing_file() {
        let path = tmp("seed");
        let mut cfg = SecurityPolicyConfig::default();
        cfg.enabled = true;
        cfg.rules.push(SecurityRuleConfig {
            name: "seed".into(),
            effect: "deny".into(),
            actions: vec!["*".into()],
            tables: vec!["*".into()],
            columns: vec![],
            subjects: vec![],
            row_filter: None,
        });
        cfg.state.policy_path = path.to_string_lossy().into();
        let merged = merge_local_pdp_from_file(&cfg).unwrap();
        assert_eq!(merged.rules[0].name, "seed");
        assert!(path.exists());
        // Second process: empty base rules, load from file.
        let mut empty = SecurityPolicyConfig::default();
        empty.enabled = true;
        empty.state.policy_path = path.to_string_lossy().into();
        let from_file = merge_local_pdp_from_file(&empty).unwrap();
        assert_eq!(from_file.rules[0].name, "seed");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("json.lock"));
    }
}
