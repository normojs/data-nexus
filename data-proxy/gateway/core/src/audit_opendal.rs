//! Optional OpenDAL cold archive for rotated audit JSONL (B04b / B04c).
//!
//! Compiled only with `--features audit-opendal`. After local rotation, the
//! rotated file is uploaded via OpenDAL. Hot path never blocks on network I/O —
//! upload runs on the audit worker thread with a short-lived current-thread
//! Tokio runtime.
//!
//! Schemes: `fs` | `memory` | `s3` | `oss` (Aliyun). Credentials prefer config
//! fields, then `DN_OPENDAL_*` / standard cloud env vars.

#![cfg(feature = "audit-opendal")]

use std::path::Path;
use std::sync::Mutex;

use opendal::services;
use opendal::Operator;
use tracing::{info, warn};

use crate::security::SecurityAuditConfig;
use crate::{GatewayError, GatewayResult};

/// Built OpenDAL operator + object key prefix.
#[derive(Clone)]
pub struct OpendalArchive {
    op: Operator,
    prefix: String,
    scheme: String,
}

impl std::fmt::Debug for OpendalArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpendalArchive")
            .field("scheme", &self.scheme)
            .field("prefix", &self.prefix)
            .finish()
    }
}

impl OpendalArchive {
    /// Build from audit config. Returns `None` when scheme is empty/off.
    pub fn from_config(config: &SecurityAuditConfig) -> GatewayResult<Option<Self>> {
        let scheme = config.opendal_scheme.trim().to_ascii_lowercase();
        if scheme.is_empty() || scheme == "off" || scheme == "none" {
            return Ok(None);
        }
        // Local schemes may fall back to archive_dir / file_path parent.
        // Object stores only use opendal_root (object-key prefix root), never a host path.
        let root = resolve_root(config, &scheme);
        let prefix = config.opendal_prefix.trim().trim_matches('/').to_owned();
        let op = match scheme.as_str() {
            "fs" => {
                let builder = services::Fs::default().root(&root);
                Operator::new(builder)
                    .map_err(|e| GatewayError::Configuration(format!("opendal fs operator: {e}")))?
                    .finish()
            }
            "memory" => {
                let builder = services::Memory::default();
                Operator::new(builder)
                    .map_err(|e| {
                        GatewayError::Configuration(format!("opendal memory operator: {e}"))
                    })?
                    .finish()
            }
            "s3" => build_s3(config, &root)?,
            "oss" => build_oss(config, &root)?,
            other => {
                return Err(GatewayError::Configuration(format!(
                    "security.audit.opendal_scheme must be fs|memory|s3|oss|empty (got '{other}')"
                )));
            }
        };
        info!(
            target: "data_nexus::audit",
            scheme = %scheme,
            root = %root,
            prefix = %prefix,
            bucket = %config.opendal_bucket,
            "audit OpenDAL archive ready"
        );
        Ok(Some(Self {
            op,
            prefix,
            scheme,
        }))
    }

    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// Upload a local rotated file; object key = prefix + file_name.
    pub fn archive_local_file(&self, local: &Path) -> Result<String, String> {
        let name = local
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| format!("bad path {}", local.display()))?;
        let key = if self.prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{}/{}", self.prefix, name)
        };
        let bytes =
            std::fs::read(local).map_err(|e| format!("read {}: {e}", local.display()))?;
        self.write_key(&key, &bytes)
    }

    /// B08: write raw sample bytes under `sample_prefix/name` (joined with archive prefix).
    pub fn write_bytes(
        &self,
        sample_prefix: &str,
        name: &str,
        bytes: &[u8],
    ) -> Result<String, String> {
        let sp = sample_prefix.trim().trim_matches('/');
        let name = name.trim().trim_start_matches('/');
        if name.is_empty() {
            return Err("sample object name empty".into());
        }
        let mut parts = Vec::new();
        if !self.prefix.is_empty() {
            parts.push(self.prefix.trim_matches('/').to_owned());
        }
        if !sp.is_empty() {
            parts.push(sp.to_owned());
        }
        parts.push(name.to_owned());
        let key = parts.join("/");
        self.write_key(&key, bytes)
    }

    fn write_key(&self, key: &str, bytes: &[u8]) -> Result<String, String> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("tokio runtime: {e}"))?;
        let op = self.op.clone();
        let key_cl = key.to_owned();
        let bytes = bytes.to_vec();
        // Simple retry for transient cloud errors (worker path only).
        let mut last_err = String::new();
        for attempt in 1..=3 {
            let op = op.clone();
            let key_cl = key_cl.clone();
            let bytes = bytes.clone();
            match rt.block_on(async move { op.write(&key_cl, bytes).await }) {
                Ok(_) => return Ok(key.to_owned()),
                Err(e) => {
                    last_err = format!("opendal write {key} attempt {attempt}: {e}");
                    std::thread::sleep(std::time::Duration::from_millis(50 * attempt as u64));
                }
            }
        }
        Err(last_err)
    }
}

fn resolve_root(config: &SecurityAuditConfig, scheme: &str) -> String {
    if !config.opendal_root.trim().is_empty() {
        return config.opendal_root.trim().to_owned();
    }
    // Cloud object-key roots must not inherit local archive paths.
    if matches!(scheme, "s3" | "oss" | "memory") {
        return String::new();
    }
    if !config.archive_dir.trim().is_empty() {
        return config.archive_dir.trim().to_owned();
    }
    if !config.file_path.trim().is_empty() {
        return Path::new(config.file_path.trim())
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".".into());
    }
    ".".into()
}

fn env_or(config_val: &str, keys: &[&str]) -> String {
    let c = config_val.trim();
    if !c.is_empty() {
        return c.to_owned();
    }
    for k in keys {
        if let Ok(v) = std::env::var(k) {
            if !v.trim().is_empty() {
                return v;
            }
        }
    }
    String::new()
}

fn build_s3(config: &SecurityAuditConfig, root: &str) -> GatewayResult<Operator> {
    let bucket = config.opendal_bucket.trim();
    if bucket.is_empty() {
        return Err(GatewayError::Configuration(
            "security.audit.opendal_bucket is required when opendal_scheme=s3".into(),
        ));
    }
    let access = env_or(
        &config.opendal_access_key_id,
        &["DN_OPENDAL_ACCESS_KEY_ID", "AWS_ACCESS_KEY_ID"],
    );
    let secret = env_or(
        &config.opendal_secret_access_key,
        &["DN_OPENDAL_SECRET_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY"],
    );
    let token = env_or(
        &config.opendal_session_token,
        &["DN_OPENDAL_SESSION_TOKEN", "AWS_SESSION_TOKEN"],
    );
    let region = env_or(&config.opendal_region, &["DN_OPENDAL_REGION", "AWS_REGION"]);
    let endpoint = config.opendal_endpoint.trim();

    let mut builder = services::S3::default().bucket(bucket);
    if !root.is_empty() {
        builder = builder.root(root);
    }
    if !region.is_empty() {
        builder = builder.region(&region);
    }
    if !endpoint.is_empty() {
        builder = builder.endpoint(endpoint);
    }
    if !access.is_empty() {
        builder = builder.access_key_id(&access);
    }
    if !secret.is_empty() {
        builder = builder.secret_access_key(&secret);
    }
    if !token.is_empty() {
        builder = builder.session_token(&token);
    }
    Operator::new(builder)
        .map_err(|e| GatewayError::Configuration(format!("opendal s3 operator: {e}")))
        .map(|b| b.finish())
}

fn build_oss(config: &SecurityAuditConfig, root: &str) -> GatewayResult<Operator> {
    let bucket = config.opendal_bucket.trim();
    if bucket.is_empty() {
        return Err(GatewayError::Configuration(
            "security.audit.opendal_bucket is required when opendal_scheme=oss".into(),
        ));
    }
    let endpoint = config.opendal_endpoint.trim();
    if endpoint.is_empty() {
        return Err(GatewayError::Configuration(
            "security.audit.opendal_endpoint is required when opendal_scheme=oss".into(),
        ));
    }
    let access = env_or(
        &config.opendal_access_key_id,
        &[
            "DN_OPENDAL_ACCESS_KEY_ID",
            "ALIBABA_CLOUD_ACCESS_KEY_ID",
            "OSS_ACCESS_KEY_ID",
        ],
    );
    let secret = env_or(
        &config.opendal_secret_access_key,
        &[
            "DN_OPENDAL_SECRET_ACCESS_KEY",
            "ALIBABA_CLOUD_ACCESS_KEY_SECRET",
            "OSS_ACCESS_KEY_SECRET",
        ],
    );
    let mut builder = services::Oss::default()
        .bucket(bucket)
        .endpoint(endpoint);
    if !root.is_empty() {
        builder = builder.root(root);
    }
    if !access.is_empty() {
        builder = builder.access_key_id(&access);
    }
    if !secret.is_empty() {
        builder = builder.access_key_secret(&secret);
    }
    Operator::new(builder)
        .map_err(|e| GatewayError::Configuration(format!("opendal oss operator: {e}")))
        .map(|b| b.finish())
}

/// Process-wide optional archive (set from install/reconfigure).
static GLOBAL_ARCHIVE: Mutex<Option<OpendalArchive>> = Mutex::new(None);

pub fn set_global_archive(archive: Option<OpendalArchive>) {
    if let Ok(mut g) = GLOBAL_ARCHIVE.lock() {
        *g = archive;
    }
}

pub fn global_archive() -> Option<OpendalArchive> {
    GLOBAL_ARCHIVE.lock().ok().and_then(|g| g.clone())
}

/// Best-effort archive; logs warnings, never panics.
pub fn try_archive_rotated_file(local: &Path) -> Option<String> {
    let Some(arch) = global_archive() else {
        return None;
    };
    match arch.archive_local_file(local) {
        Ok(key) => {
            info!(
                target: "data_nexus::audit",
                local = %local.display(),
                key = %key,
                scheme = %arch.scheme(),
                "archived rotated audit JSONL via OpenDAL"
            );
            Some(key)
        }
        Err(e) => {
            warn!(
                target: "data_nexus::audit",
                local = %local.display(),
                error = %e,
                "OpenDAL archive failed"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::SecurityAuditConfig;

    #[test]
    fn memory_scheme_archives_bytes() {
        let mut cfg = SecurityAuditConfig::default();
        cfg.opendal_scheme = "memory".into();
        cfg.opendal_prefix = "audit".into();
        let arch = OpendalArchive::from_config(&cfg).unwrap().expect("arch");
        let dir = std::env::temp_dir().join(format!("dn-od-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.jsonl.1");
        std::fs::write(&path, b"{\"decision\":\"deny\"}\n").unwrap();
        let key = arch.archive_local_file(&path).unwrap();
        assert_eq!(key, "audit/events.jsonl.1");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let data = rt.block_on(arch.op.read(&key)).unwrap();
        assert!(data.to_vec().starts_with(b"{\"decision\""));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn empty_scheme_is_off() {
        let cfg = SecurityAuditConfig::default();
        assert!(OpendalArchive::from_config(&cfg).unwrap().is_none());
    }

    #[test]
    fn s3_requires_bucket() {
        let mut cfg = SecurityAuditConfig::default();
        cfg.opendal_scheme = "s3".into();
        let err = OpendalArchive::from_config(&cfg).unwrap_err().to_string();
        assert!(err.contains("bucket"), "{err}");
    }

    #[test]
    fn oss_requires_bucket_and_endpoint() {
        let mut cfg = SecurityAuditConfig::default();
        cfg.opendal_scheme = "oss".into();
        cfg.opendal_bucket = "b".into();
        let err = OpendalArchive::from_config(&cfg).unwrap_err().to_string();
        assert!(err.contains("endpoint"), "{err}");
    }

    #[test]
    fn s3_builder_accepts_min_config() {
        // Does not perform network I/O; only constructs Operator.
        let mut cfg = SecurityAuditConfig::default();
        cfg.opendal_scheme = "s3".into();
        cfg.opendal_bucket = "test-bucket".into();
        cfg.opendal_region = "us-east-1".into();
        cfg.opendal_endpoint = "http://127.0.0.1:9000".into();
        cfg.opendal_access_key_id = "minio".into();
        cfg.opendal_secret_access_key = "minio123".into();
        cfg.opendal_root = "audit-root".into();
        let arch = OpendalArchive::from_config(&cfg).unwrap().expect("s3 op");
        assert_eq!(arch.scheme(), "s3");
    }

    #[test]
    fn s3_ignores_local_archive_dir_for_root() {
        let mut cfg = SecurityAuditConfig::default();
        cfg.opendal_scheme = "s3".into();
        cfg.opendal_bucket = "b".into();
        cfg.opendal_region = "us-east-1".into();
        cfg.opendal_endpoint = "http://127.0.0.1:9000".into();
        cfg.opendal_access_key_id = "k".into();
        cfg.opendal_secret_access_key = "s".into();
        cfg.archive_dir = "/var/log/data-nexus/audit/archive".into();
        // Should succeed without treating archive_dir as object root.
        let arch = OpendalArchive::from_config(&cfg).unwrap().expect("s3 op");
        assert_eq!(arch.scheme(), "s3");
        assert_eq!(resolve_root(&cfg, "s3"), "");
    }

    #[test]
    fn oss_builder_accepts_min_config() {
        let mut cfg = SecurityAuditConfig::default();
        cfg.opendal_scheme = "oss".into();
        cfg.opendal_bucket = "test-bucket".into();
        cfg.opendal_endpoint = "https://oss-cn-hangzhou.aliyuncs.com".into();
        cfg.opendal_access_key_id = "ak".into();
        cfg.opendal_secret_access_key = "sk".into();
        cfg.opendal_prefix = "audit".into();
        let arch = OpendalArchive::from_config(&cfg).unwrap().expect("oss op");
        assert_eq!(arch.scheme(), "oss");
    }
}
