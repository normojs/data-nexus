//! Optional OpenDAL cold archive for rotated audit JSONL (B04b).
//!
//! Compiled only with `--features audit-opendal`. After local rotation, the
//! rotated file is uploaded via OpenDAL (`fs` or `memory` in MVP). Hot path
//! never blocks on network I/O — upload runs on the audit worker thread with a
//! short-lived current-thread Tokio runtime.

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
        let root = if !config.opendal_root.trim().is_empty() {
            config.opendal_root.trim().to_owned()
        } else if !config.archive_dir.trim().is_empty() {
            config.archive_dir.trim().to_owned()
        } else if !config.file_path.trim().is_empty() {
            Path::new(config.file_path.trim())
                .parent()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| ".".into())
        } else {
            ".".into()
        };
        let prefix = config.opendal_prefix.trim().trim_matches('/').to_owned();
        let op = match scheme.as_str() {
            "fs" => {
                let builder = services::Fs::default().root(&root);
                Operator::new(builder)
                    .map_err(|e| {
                        GatewayError::Configuration(format!("opendal fs operator: {e}"))
                    })?
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
            other => {
                return Err(GatewayError::Configuration(format!(
                    "security.audit.opendal_scheme must be fs, memory, or empty (got '{other}')"
                )));
            }
        };
        info!(
            target: "data_nexus::audit",
            scheme = %scheme,
            root = %root,
            prefix = %prefix,
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
        let bytes = std::fs::read(local).map_err(|e| format!("read {}: {e}", local.display()))?;
        // Worker thread: current-thread runtime for a single write.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("tokio runtime: {e}"))?;
        let op = self.op.clone();
        let key_cl = key.clone();
        rt.block_on(async move {
            op.write(&key_cl, bytes)
                .await
                .map_err(|e| format!("opendal write {key_cl}: {e}"))
        })?;
        Ok(key)
    }
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
}
